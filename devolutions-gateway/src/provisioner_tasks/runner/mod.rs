//! Runs provisioner tasks: the one place that keeps a task's record and the job running it in step.
//!
//! Each kind of work is a [`ProvisionerTask`]: what one attempt does, what its payloads hold, and what to do once it has
//! ended.
//! [`ProvisionerTaskRunner`] does the rest for every task. It creates the record, queues the job, starts each attempt,
//! retries recoverable failures, moves the deadline ahead with each progress, cancels an attempt once the deadline passes,
//! and records how the task ended.
//!
//! The record is the source of truth and the job only wakes it up.
//! Each record names the one job allowed to run it, by its token, and each job names the attempt it starts, so a stale,
//! duplicate or rerun job stops without running anything.
//! At startup, before any job runs, [`ProvisionerTaskRunner::resume`] hands every unfinished record to a new job, which
//! also covers a record created just before a crash, before its job was queued.
//! A finished record keeps whether its end is done, so the same startup ends every record whose end was cut short,
//! whether or not a job for it survived.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use parking_lot::Mutex;
use provisioner_task::{
    AttemptStart, CreateOutcome, DynProvisionerTaskStore, NewProvisionerTaskRecord, ProvisionerTaskRecord,
    ProvisionerTaskState,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{AttemptError, Permanent};
use crate::job_queue::JobQueueHandle;

/// Time before a record whose end failed is ended again.
const END_RETRY_DELAY: time::Duration = time::Duration::minutes(5);

/// Attempts a record gets: a recoverable failure of the last one fails the record.
pub const MAX_ATTEMPTS: u32 = 5;

/// Time before the attempt that follows attempt number `attempts`: 30 seconds, doubled after each attempt.
fn retry_delay(attempts: u32) -> time::Duration {
    time::Duration::seconds(30) * 2i32.saturating_pow(attempts.saturating_sub(1))
}

/// Where the runner queues the jobs of its records.
#[async_trait]
pub trait ProvisionerTaskJobQueue: Send + Sync {
    /// Queues `job` to run at `schedule_for`, or at once without it, and returns once it is stored, so a record never
    /// waits for a job that was lost.
    async fn push(&self, job: ProvisionerTaskJob, schedule_for: Option<OffsetDateTime>) -> anyhow::Result<()>;
}

pub type DynProvisionerTaskJobQueue = Arc<dyn ProvisionerTaskJobQueue>;

/// Hands the job to the job queue task, which stores it later: for tests, which take the jobs from its channel.
#[async_trait]
impl ProvisionerTaskJobQueue for JobQueueHandle {
    async fn push(&self, job: ProvisionerTaskJob, schedule_for: Option<OffsetDateTime>) -> anyhow::Result<()> {
        match schedule_for {
            Some(schedule_for) => self.schedule(job, schedule_for).await,
            None => self.enqueue(job).await,
        }
    }
}

/// A provisioner task: the work Gateway does for one kind of request, such as `recording-ai-analysis`.
///
/// One value serves every record of its kind, so it keeps only what they share; what belongs to one record comes in
/// through [`Attempt`] and the parameters.
#[async_trait]
pub trait ProvisionerTask: Send + Sync + 'static {
    /// The kind written in the records of this task.
    const KIND: &'static str;

    /// What the record keeps as asked; never secrets, since records are kept and returned to callers.
    type Params: Serialize + DeserializeOwned + Send;

    /// The payload of a `succeeded` record.
    type Output: Serialize + Send;

    /// Why an attempt of this task fails for good, next to the failures any task may have.
    type Failure: Serialize + Send;

    /// Why an attempt of this task fails for now, so a later attempt may succeed.
    type Recoverable: Serialize + Send;

    /// Time from the creation of a record until its first attempt must start.
    fn start_window(&self) -> time::Duration;

    /// Time a running record may go without progress: each attempt start and each progress report moves its deadline
    /// this far ahead.
    fn progress_timeout(&self) -> time::Duration;

    /// The payload of the running record as an attempt starts, from `last`, its payload until then: `null` before its
    /// first attempt.
    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value;

    /// The payload of a record that failed with `error`, from `last`, its payload until then: `null` if it never ran.
    fn failed_payload(&self, error: &AnyPermanent, last: &serde_json::Value) -> serde_json::Value;

    /// Why an unfinished record fails when Gateway starts again, for a task that cannot outlive a restart, such as one
    /// whose secrets are kept in memory only; `None` for a task that goes on.
    ///
    /// A record that cannot be failed at startup is still handed to a new job, so [`ProvisionerTask::run`] must fail
    /// the same way after a restart.
    fn restart_failure(&self) -> Option<Self::Failure>;

    /// Runs one attempt.
    ///
    /// The attempt should stop soon after [`Attempt::cancel`] is cancelled, which happens once the record is past its
    /// deadline.
    async fn run(
        &self,
        attempt: &Attempt,
        params: Self::Params,
    ) -> Result<Self::Output, AttemptError<Self::Failure, Self::Recoverable>>;

    /// Finishes what the record leaves to do once it has ended, however it ended, such as dropping what was kept only
    /// while it ran.
    ///
    /// It may be called again for a record that already ended, so it must be idempotent; an error has it called again
    /// later, until it succeeds.
    async fn on_end(&self, _record: &ProvisionerTaskRecord) -> anyhow::Result<()> {
        Ok(())
    }
}

/// One attempt of a record, as its task sees it.
pub struct Attempt {
    pub task_id: Uuid,
    pub target: String,
    /// Attempts started so far, this one included.
    pub attempts: u32,
    /// Payload of the record as this attempt started, from [`ProvisionerTask::starting_payload`].
    pub payload: serde_json::Value,
    /// Cancelled once the record is past its deadline or no longer running.
    pub cancel: CancellationToken,
    progress_timeout: time::Duration,
    store: DynProvisionerTaskStore,
    latest: Arc<Mutex<Latest>>,
}

/// An attempt the prelude started: the task that runs it, and the record as the attempt started.
struct Started {
    task: Arc<dyn AnyProvisionerTask>,
    record: ProvisionerTaskRecord,
}

/// What the runner knows of the running record: the last payload of the attempt, and the deadline it stored.
struct Latest {
    payload: serde_json::Value,
    deadline_at: OffsetDateTime,
}

impl Attempt {
    /// Deadline of the record, after which the attempt is cancelled.
    pub fn deadline(&self) -> OffsetDateTime {
        self.latest.lock().deadline_at
    }

    /// State of another record of the same target, such as an earlier Task; `None` for an unknown one or one of another
    /// target. One past its deadline is failed first.
    pub async fn state_of(&self, task_id: Uuid) -> anyhow::Result<Option<ProvisionerTaskState>> {
        let record = self.store.get(task_id, OffsetDateTime::now_utc()).await?;
        Ok(record
            .filter(|record| record.target == self.target)
            .map(|record| record.state))
    }

    /// Replaces the payload of the running record and moves its deadline ahead, so whoever asks about it sees how the
    /// attempt goes.
    ///
    /// A record that is no longer running, such as one past its deadline, cancels the attempt.
    pub async fn report_progress(&self, payload: serde_json::Value) {
        let now = OffsetDateTime::now_utc();
        let deadline_at = deadline(now, self.progress_timeout);
        self.latest.lock().payload = payload.clone();

        match self.store.update_running(self.task_id, payload, deadline_at, now).await {
            Ok(true) => self.latest.lock().deadline_at = deadline_at,
            Ok(false) => {
                debug!(task.id = %self.task_id, "Task is no longer running, so its attempt stops");
                self.cancel.cancel();
            }
            Err(error) => {
                warn!(task.id = %self.task_id, error = format!("{error:#}"), "Failed to record the Task progress");
            }
        }
    }
}

/// [`Permanent`] with the failures of its kind of task as JSON, as the runner holds every kind together.
pub type AnyPermanent = Permanent<serde_json::Value, serde_json::Value>;

/// [`AttemptError`] with the failures of its kind of task as JSON.
type AnyAttemptError = AttemptError<serde_json::Value, serde_json::Value>;

/// `error` with the failures of its kind as JSON; one that cannot be written as JSON is an internal failure.
fn erase_permanent<F: Serialize, R: Serialize>(error: Permanent<F, R>) -> AnyPermanent {
    error
        .try_map(serde_json::to_value, serde_json::to_value)
        .unwrap_or_else(|error| {
            error!(%error, "Failed to write a Task failure as JSON");
            Permanent::Internal
        })
}

fn erase_attempt_error<F: Serialize, R: Serialize>(error: AttemptError<F, R>) -> AnyAttemptError {
    match error {
        AttemptError::Recoverable(error) => match serde_json::to_value(error) {
            Ok(error) => AttemptError::Recoverable(error),
            Err(error) => {
                error!(%error, "Failed to write a Task failure as JSON");
                AttemptError::Permanent(Permanent::Internal)
            }
        },
        AttemptError::Permanent(error) => AttemptError::Permanent(erase_permanent(error)),
    }
}

/// [`ProvisionerTask`] with its types erased, so the runner can hold every task together.
#[async_trait]
trait AnyProvisionerTask: Send + Sync {
    fn start_window(&self) -> time::Duration;

    fn progress_timeout(&self) -> time::Duration;

    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value;

    fn failed_payload(&self, error: &AnyPermanent, last: &serde_json::Value) -> serde_json::Value;

    fn restart_failure(&self) -> Option<AnyPermanent>;

    async fn run(&self, attempt: &Attempt, params: serde_json::Value) -> Result<serde_json::Value, AnyAttemptError>;

    async fn on_end(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()>;
}

#[async_trait]
impl<T: ProvisionerTask> AnyProvisionerTask for T {
    fn start_window(&self) -> time::Duration {
        ProvisionerTask::start_window(self)
    }

    fn progress_timeout(&self) -> time::Duration {
        ProvisionerTask::progress_timeout(self)
    }

    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value {
        ProvisionerTask::starting_payload(self, last)
    }

    fn failed_payload(&self, error: &AnyPermanent, last: &serde_json::Value) -> serde_json::Value {
        ProvisionerTask::failed_payload(self, error, last)
    }

    fn restart_failure(&self) -> Option<AnyPermanent> {
        ProvisionerTask::restart_failure(self)
            .map(|failure| erase_permanent(Permanent::<_, T::Recoverable>::Kind(failure)))
    }

    async fn run(&self, attempt: &Attempt, params: serde_json::Value) -> Result<serde_json::Value, AnyAttemptError> {
        let params = serde_json::from_value(params).map_err(|error| {
            warn!(task.id = %attempt.task_id, %error, "Invalid Task parameters");
            AnyAttemptError::Permanent(Permanent::InvalidTask)
        })?;

        let output = ProvisionerTask::run(self, attempt, params)
            .await
            .map_err(erase_attempt_error)?;

        serde_json::to_value(output).map_err(|error| {
            error!(task.id = %attempt.task_id, %error, "Failed to serialize the Task result");
            AnyAttemptError::Permanent(Permanent::Internal)
        })
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()> {
        ProvisionerTask::on_end(self, record).await
    }
}

/// Creates provisioner task records and runs them as jobs on the job queue.
#[derive(Clone)]
pub struct ProvisionerTaskRunner {
    inner: Arc<Inner>,
}

struct Inner {
    store: DynProvisionerTaskStore,
    job_queue: DynProvisionerTaskJobQueue,
    /// Kind → the task that runs records of this kind.
    tasks: HashMap<&'static str, Arc<dyn AnyProvisionerTask>>,
}

pub struct ProvisionerTaskRunnerBuilder {
    store: DynProvisionerTaskStore,
    job_queue: DynProvisionerTaskJobQueue,
    tasks: HashMap<&'static str, Arc<dyn AnyProvisionerTask>>,
}

impl ProvisionerTaskRunnerBuilder {
    /// Registers `task`, so records of its kind can be created and run.
    #[must_use]
    pub fn register<T: ProvisionerTask>(mut self, task: T) -> Self {
        self.tasks.insert(T::KIND, Arc::new(task));
        self
    }

    pub fn build(self) -> ProvisionerTaskRunner {
        ProvisionerTaskRunner {
            inner: Arc::new(Inner {
                store: self.store,
                job_queue: self.job_queue,
                tasks: self.tasks,
            }),
        }
    }
}

impl ProvisionerTaskRunner {
    pub fn builder(
        store: DynProvisionerTaskStore,
        job_queue: DynProvisionerTaskJobQueue,
    ) -> ProvisionerTaskRunnerBuilder {
        ProvisionerTaskRunnerBuilder {
            store,
            job_queue,
            tasks: HashMap::new(),
        }
    }

    /// Returns the record with this ID; one past its deadline is failed first.
    pub async fn get(&self, id: Uuid, now: OffsetDateTime) -> anyhow::Result<Option<ProvisionerTaskRecord>> {
        self.inner.store.get(id, now).await
    }

    /// Creates a record for the task `T` and queues the job that runs it.
    ///
    /// `on_created` runs only for a new record, before its job is queued, so what the job needs is in place before it
    /// can run; if it fails, the record fails and no job is queued. A known ID or a busy target creates nothing and
    /// queues nothing.
    pub async fn create<T: ProvisionerTask>(
        &self,
        id: Uuid,
        target: String,
        params: &T::Params,
        on_created: impl FnOnce(&ProvisionerTaskRecord) -> anyhow::Result<()> + Send,
    ) -> anyhow::Result<CreateOutcome> {
        let task = self.task(T::KIND).context("unregistered provisioner task")?;
        let params = serde_json::to_value(params).context("serialize the task parameters")?;
        let now = OffsetDateTime::now_utc();
        let job_token = Uuid::new_v4();

        let outcome = self
            .inner
            .store
            .create(
                NewProvisionerTaskRecord {
                    id,
                    kind: T::KIND.to_owned(),
                    target,
                    params,
                    deadline_at: deadline(now, task.start_window()),
                    job_token,
                },
                now,
            )
            .await?;

        let CreateOutcome::Created(record) = &outcome else {
            return Ok(outcome);
        };

        let queued = match on_created(record) {
            Ok(()) => self.enqueue(id, job_token, Step::Attempt(1), None).await,
            Err(error) => Err(error.context("prepare the Task")),
        };

        if let Err(error) = queued {
            error!(task.id = %id, task.kind = T::KIND, error = format!("{error:#}"), "Failed to queue the Task");
            self.fail_not_queued(task.as_ref(), id, job_token, &serde_json::Value::Null)
                .await;
            return Err(error);
        }

        info!(task.id = %id, task.kind = T::KIND, "Task queued");

        Ok(outcome)
    }

    /// Hands every unfinished record to a new job, since a record created just before Gateway stopped may have none,
    /// then queues the end of every finished record whose end is not done, since Gateway may have stopped before it.
    ///
    /// Each unfinished record gets a new `job_token`, so a job left from before finds itself superseded and stops, and
    /// the job queue is never read.
    /// A record whose task cannot outlive a restart fails instead, and is ended with the other finished records.
    /// A record that was waiting to retry runs at once, since retry timing is no promise to the caller.
    /// Call it at startup, before the job runner claims any job, so no job runs an attempt meanwhile.
    /// A record whose new job cannot be queued is failed, since no job is left to run it.
    pub async fn resume(&self) -> anyhow::Result<()> {
        let store = &self.inner.store;
        let now = OffsetDateTime::now_utc();

        for record in store.list_unfinished(now).await? {
            let job_token = Uuid::new_v4();

            match store.replace_job_token(record.id, job_token, now).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    error!(
                        task.id = %record.id,
                        task.kind = %record.kind,
                        error = format!("{error:#}"),
                        "Failed to hand the Task to a new job"
                    );
                    continue;
                }
            }

            let task = self.task(&record.kind);

            if let Some(task) = &task
                && let Some(failure) = task.restart_failure()
            {
                match store
                    .fail(record.id, task.failed_payload(&failure, &record.payload), now)
                    .await
                {
                    Ok(_) => {
                        info!(
                            task.id = %record.id,
                            task.kind = %record.kind,
                            ?failure,
                            "Task failed, since it cannot outlive a restart"
                        );
                        continue;
                    }
                    // Its new job runs the attempt then, which fails the same way.
                    Err(error) => error!(
                        task.id = %record.id,
                        task.kind = %record.kind,
                        error = format!("{error:#}"),
                        "Failed to fail the Task that cannot outlive a restart"
                    ),
                }
            }

            let next = Step::Attempt(record.attempts.saturating_add(1));

            match self.enqueue(record.id, job_token, next, None).await {
                Ok(()) => info!(task.id = %record.id, task.kind = %record.kind, "Task queued again"),
                Err(error) => {
                    error!(
                        task.id = %record.id,
                        task.kind = %record.kind,
                        error = format!("{error:#}"),
                        "Failed to queue the Task again"
                    );
                    if let Some(task) = &task {
                        self.fail_not_queued(task.as_ref(), record.id, job_token, &record.payload)
                            .await;
                    }
                }
            }
        }

        for record in store.list_unended().await? {
            match self.enqueue(record.id, record.job_token, Step::End, None).await {
                Ok(()) => info!(task.id = %record.id, task.kind = %record.kind, "Task end queued again"),
                Err(error) => error!(
                    task.id = %record.id,
                    task.kind = %record.kind,
                    error = format!("{error:#}"),
                    "Failed to queue the end of the Task again"
                ),
            }
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn store(&self) -> &DynProvisionerTaskStore {
        &self.inner.store
    }

    /// The task that runs records of `kind`.
    fn task(&self, kind: &str) -> Option<Arc<dyn AnyProvisionerTask>> {
        self.inner.tasks.get(kind).cloned()
    }

    async fn enqueue(
        &self,
        task_id: Uuid,
        job_token: Uuid,
        step: Step,
        schedule_for: Option<OffsetDateTime>,
    ) -> anyhow::Result<()> {
        self.inner
            .job_queue
            .push(
                ProvisionerTaskJob {
                    task_id,
                    job_token,
                    step,
                    runner: self.clone(),
                },
                schedule_for,
            )
            .await
    }

    /// Runs attempt number `attempt` for the job holding `job_token`, in three steps.
    ///
    /// The prelude marks the start of the attempt on the record, the body runs the work of the task, and the completion
    /// records how it ended, then ends the record or queues its next attempt.
    /// The record counts its attempts, and the job queues the next one itself, so the job queue runs a job again only
    /// when what it had to record or queue could not be stored; the prelude then finds its attempt already started.
    async fn run_attempt(&self, task_id: Uuid, job_token: Uuid, attempt: u32) -> anyhow::Result<()> {
        let Some(started) = self.begin_attempt(task_id, job_token, attempt).await? else {
            return Ok(());
        };

        let (outcome, latest) = self.execute(&started).await;

        self.complete(&started, job_token, outcome, latest).await
    }

    /// The prelude: marks the start of attempt number `attempt` on the record, unless another job holds it, it has
    /// ended, or the attempt already started.
    ///
    /// A record that has ended is ended instead, if its end is not done yet.
    /// An attempt that already started is never run again, since that could do paid work twice: its record is ended
    /// once its deadline passes, unless the attempt is still running and ends it first.
    async fn begin_attempt(&self, task_id: Uuid, job_token: Uuid, attempt: u32) -> anyhow::Result<Option<Started>> {
        let store = &self.inner.store;
        let now = OffsetDateTime::now_utc();

        // The starting payload carries over what earlier attempts reported, so the record is read first.
        let Some(record) = store.get(task_id, now).await? else {
            debug!(task.id = %task_id, "Task is unknown, so this attempt does not run");
            return Ok(None);
        };

        let Some(task) = self.task(&record.kind) else {
            if record.job_token == job_token && !record.state.is_finished() {
                error!(task.id = %task_id, task.kind = %record.kind, "Task of an unknown kind");
                // Without its kind, nothing else of the payload is known, so it holds the error alone.
                store
                    .fail(task_id, json!({ "error": AnyPermanent::InvalidTask }), now)
                    .await
                    .context("record the Task failure")?;
            }
            return Ok(None);
        };

        let starting_payload = task.starting_payload(&record.payload);
        let deadline_at = deadline(now, task.progress_timeout());

        match store
            .start_attempt(task_id, job_token, attempt, starting_payload, deadline_at, now)
            .await?
        {
            AttemptStart::Started(record) => Ok(Some(Started { task, record })),
            AttemptStart::Finished(record) => {
                debug!(task.id = %task_id, "Task is over, so this attempt does not run");
                self.end_record(&record, job_token).await?;
                Ok(None)
            }
            AttemptStart::AlreadyStarted(record) => {
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempt,
                    attempts = record.attempts,
                    "Task attempt already started, so it does not run again"
                );

                // The store fails the record once its deadline passes, so a job that runs after it only ends it.
                let after_deadline = record.deadline_at + time::Duration::SECOND;

                self.enqueue(task_id, job_token, Step::End, Some(after_deadline))
                    .await
                    .context("queue the end of the Task")?;
                Ok(None)
            }
            AttemptStart::Superseded => {
                debug!(task.id = %task_id, "Another job runs this Task, so this one stops");
                Ok(None)
            }
            AttemptStart::Unknown => {
                debug!(task.id = %task_id, "Task is unknown, so this attempt does not run");
                Ok(None)
            }
        }
    }

    /// The body: runs the attempt of the task, and cancels it once the record is past its deadline.
    ///
    /// Returns how the attempt ended, with the last payload it reported and the deadline it last set.
    async fn execute(&self, started: &Started) -> (Result<serde_json::Value, AnyAttemptError>, Latest) {
        let Started { task, record } = started;
        let cancel = CancellationToken::new();
        let latest = Arc::new(Mutex::new(Latest {
            payload: record.payload.clone(),
            deadline_at: record.deadline_at,
        }));
        let attempt = Attempt {
            task_id: record.id,
            target: record.target.clone(),
            attempts: record.attempts,
            payload: record.payload.clone(),
            cancel: cancel.clone(),
            progress_timeout: task.progress_timeout(),
            store: Arc::clone(&self.inner.store),
            latest: Arc::clone(&latest),
        };

        info!(task.id = %record.id, task.kind = %record.kind, attempts = record.attempts, "Task attempt started");

        // The attempt has its own Tokio task, so a panic fails the record instead of leaving it running.
        let mut handle = tokio::spawn({
            let task = Arc::clone(task);
            let params = record.params.clone();
            async move { task.run(&attempt, params).await }
        });

        let mut past_deadline = false;
        let joined = loop {
            let deadline_at = latest.lock().deadline_at;
            let wait = std::time::Duration::try_from(deadline_at - OffsetDateTime::now_utc()).unwrap_or_default();

            tokio::select! {
                joined = &mut handle => break joined,
                () = tokio::time::sleep(wait) => {
                    // Progress may have moved the deadline while the timer ran.
                    if OffsetDateTime::now_utc() < latest.lock().deadline_at {
                        continue;
                    }

                    warn!(
                        task.id = %record.id,
                        task.kind = %record.kind,
                        attempts = record.attempts,
                        "Task went past its deadline; its attempt is cancelled"
                    );
                    past_deadline = true;
                    // Aborting cannot stop blocking steps, so the attempt is cancelled and awaited instead: what runs
                    // once the Task ends never runs alongside it.
                    cancel.cancel();
                    break handle.await;
                }
            }
        };

        let outcome = match joined {
            // The attempt stopped because it was cancelled, whatever error it reports for it.
            Ok(Err(_)) if past_deadline => Err(AttemptError::Permanent(Permanent::DeadlinePassed)),
            Ok(outcome) => outcome,
            Err(_) => Err(AttemptError::Permanent(Permanent::Panicked)),
        };

        let latest = latest.lock();

        (
            outcome,
            Latest {
                payload: latest.payload.clone(),
                deadline_at: latest.deadline_at,
            },
        )
    }

    /// The completion: records how the attempt ended, then ends the record or queues its next attempt.
    ///
    /// If that cannot be stored, the error is returned so the job queue runs the job again, and the record fails at its
    /// deadline, see [`ProvisionerTaskRunner::begin_attempt`].
    /// Recording the end and dropping what the record kept are separate steps, so a failed drop never undoes the end.
    async fn complete(
        &self,
        started: &Started,
        job_token: Uuid,
        outcome: Result<serde_json::Value, AnyAttemptError>,
        latest: Latest,
    ) -> anyhow::Result<()> {
        let Started { task, record } = started;
        let (task_id, attempts) = (record.id, record.attempts);
        let last = &latest.payload;

        match outcome {
            Ok(output) => {
                let ended = self
                    .inner
                    .store
                    .succeed(task_id, output, OffsetDateTime::now_utc())
                    .await
                    .context("record the Task success")?;

                if ended {
                    info!(task.id = %task_id, task.kind = %record.kind, attempts, "Task succeeded");
                } else {
                    warn!(
                        task.id = %task_id,
                        task.kind = %record.kind,
                        "Task attempt succeeded after the Task had ended, such as past its deadline; the Task keeps its earlier end"
                    );
                }

                self.end(task_id, job_token).await?;
            }
            Err(AttemptError::Recoverable(error)) if attempts < MAX_ATTEMPTS => {
                let retry_at = OffsetDateTime::now_utc() + retry_delay(attempts);
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    %error,
                    %retry_at,
                    "Task attempt failed; it will be retried"
                );
                self.enqueue(task_id, job_token, Step::Attempt(attempts + 1), Some(retry_at))
                    .await
                    .context("queue the next attempt")?;
            }
            Err(AttemptError::Recoverable(error)) => {
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    %error,
                    "Task failed after its last attempt"
                );
                self.fail(
                    task.as_ref(),
                    task_id,
                    job_token,
                    &Permanent::AttemptsExhausted { last: error },
                    last,
                )
                .await?;
            }
            Err(AttemptError::Permanent(error)) => {
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    error = %serde_json::to_value(&error).unwrap_or_default(),
                    "Task failed"
                );
                self.fail(task.as_ref(), task_id, job_token, &error, last).await?;
            }
        }

        Ok(())
    }

    /// Records the failure, then ends the record.
    ///
    /// If the failure cannot be recorded, nothing is dropped, since the record may still run, and the error is returned.
    async fn fail(
        &self,
        task: &dyn AnyProvisionerTask,
        task_id: Uuid,
        job_token: Uuid,
        error: &AnyPermanent,
        last: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.inner
            .store
            .fail(task_id, task.failed_payload(error, last), OffsetDateTime::now_utc())
            .await
            .context("record the Task failure")?;

        self.end(task_id, job_token).await
    }

    /// Fails a record no job will run.
    async fn fail_not_queued(
        &self,
        task: &dyn AnyProvisionerTask,
        task_id: Uuid,
        job_token: Uuid,
        last: &serde_json::Value,
    ) {
        if let Err(error) = self.fail(task, task_id, job_token, &Permanent::NotQueued, last).await {
            error!(task.id = %task_id, error = format!("{error:#}"), "Failed to end the Task that has no job");
        }
    }

    /// Ends the record, read again so its task sees how it ended.
    async fn end(&self, task_id: Uuid, job_token: Uuid) -> anyhow::Result<()> {
        match self.inner.store.get(task_id, OffsetDateTime::now_utc()).await {
            Ok(Some(record)) => self.end_record(&record, job_token).await,
            Ok(None) => Ok(()),
            Err(error) => self.end_later(task_id, job_token, error).await,
        }
    }

    /// Does what the finished record leaves to do, then records that it is done.
    ///
    /// A record still unfinished is left to its attempt, and one of a kind this Gateway does not know is left for one
    /// that does.
    async fn end_record(&self, record: &ProvisionerTaskRecord, job_token: Uuid) -> anyhow::Result<()> {
        if !record.state.is_finished() || record.ended_at.is_some() {
            return Ok(());
        }

        let Some(task) = self.task(&record.kind) else {
            return Ok(());
        };

        if let Err(error) = task.on_end(record).await {
            return self.end_later(record.id, job_token, error).await;
        }

        match self.inner.store.mark_ended(record.id, OffsetDateTime::now_utc()).await {
            Ok(_) => Ok(()),
            Err(error) => self.end_later(record.id, job_token, error).await,
        }
    }

    /// Hands the record to a new job that ends it again later; an error means that job could not be queued.
    ///
    /// The end stays due on the record, so the next startup ends it if that job is lost too.
    async fn end_later(&self, task_id: Uuid, job_token: Uuid, error: anyhow::Error) -> anyhow::Result<()> {
        warn!(task.id = %task_id, error = format!("{error:#}"), "Failed to end the Task; it is ended again later");

        self.enqueue(
            task_id,
            job_token,
            Step::End,
            Some(OffsetDateTime::now_utc() + END_RETRY_DELAY),
        )
        .await
        .context("queue the end of the Task again")
    }
}

/// The deadline `timeout` after `now`, in whole seconds as the store keeps it, so the runner and the store agree on when
/// it passes.
fn deadline(now: OffsetDateTime, timeout: time::Duration) -> OffsetDateTime {
    (now + timeout).truncate_to_second()
}

/// What a job comes to do for its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum Step {
    /// Start the attempt with this number, counting from 1, unless it already started.
    Attempt(u32),
    /// End the finished record, unless that is already done.
    End,
}

#[derive(Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobDef {
    task_id: Uuid,
    job_token: Uuid,
    step: Step,
}

/// The job of a provisioner task record: it only wakes the record up, and the record decides what runs.
pub struct ProvisionerTaskJob {
    task_id: Uuid,
    job_token: Uuid,
    step: Step,
    runner: ProvisionerTaskRunner,
}

impl ProvisionerTaskJob {
    pub const NAME: &'static str = "provisioner-task";

    pub fn read_json(json: &str, runner: ProvisionerTaskRunner) -> anyhow::Result<Self> {
        let def: JobDef = serde_json::from_str(json).context("failed to deserialize ProvisionerTaskJob")?;

        Ok(Self {
            task_id: def.task_id,
            job_token: def.job_token,
            step: def.step,
            runner,
        })
    }
}

#[async_trait]
impl job_queue::Job for ProvisionerTaskJob {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn write_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(&JobDef {
            task_id: self.task_id,
            job_token: self.job_token,
            step: self.step,
        })
        .context("failed to serialize ProvisionerTaskJob")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        match self.step {
            Step::Attempt(attempt) => self.runner.run_attempt(self.task_id, self.job_token, attempt).await,
            Step::End => self.runner.end(self.task_id, self.job_token).await,
        }
    }
}
