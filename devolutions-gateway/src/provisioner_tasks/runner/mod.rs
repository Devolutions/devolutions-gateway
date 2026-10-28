//! Runs provisioner tasks: the one place that keeps a task's record and the job running it in step.
//!
//! Each kind of work is a [`ProvisionerTask`]: what one attempt does, what its payloads hold, and what to do once it has
//! ended.
//! [`ProvisionerTaskRunner`] does the rest for every task. It creates the record, queues the job, starts each attempt,
//! retries recoverable failures, moves the deadline ahead with each progress, cancels an attempt once the deadline passes,
//! and records how the task ended.
//!
//! The record is the source of truth and the job only wakes it up.
//! Each record names the one job allowed to run it, by its token, so a stale or duplicate job stops without running
//! anything.
//! At startup, before any job runs, [`ProvisionerTaskRunner::resume`] hands every unfinished record to a new job, which
//! also covers a record created just before a crash, before its job was queued.
//! A record whose end fails is handed to a new job that ends it again later, since the job queue gives up on a job
//! after a few failed runs; that job is stored, so a restart runs it too.

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
    time::Duration::seconds(30) * 2_i32.saturating_pow(attempts.saturating_sub(1))
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

    /// Time from the creation of a record until its first attempt must start.
    fn start_window(&self) -> time::Duration;

    /// Time a running record may go without progress: each attempt start and each progress report moves its deadline
    /// this far ahead.
    fn progress_timeout(&self) -> time::Duration;

    /// The payload of the running record as an attempt starts, from `last`, its payload until then: `null` before its
    /// first attempt.
    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value;

    /// The payload of a record that failed with `error`, from `last`, its payload until then: `null` if it never ran.
    fn failed_payload(&self, error: &Permanent, last: &serde_json::Value) -> serde_json::Value;

    /// Why an unfinished record fails when Gateway starts again, for a task that cannot outlive a restart, such as one
    /// whose secrets are kept in memory only; `None` for a task that goes on.
    ///
    /// A record that cannot be failed at startup is still handed to a new job, so [`ProvisionerTask::run`] must fail
    /// the same way after a restart.
    fn restart_failure(&self) -> Option<Permanent>;

    /// Runs one attempt.
    ///
    /// The attempt should stop soon after [`Attempt::cancel`] is cancelled, which happens once the record is past its
    /// deadline.
    async fn run(&self, attempt: &Attempt, params: Self::Params) -> Result<Self::Output, AttemptError>;

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

/// [`ProvisionerTask`] with its types erased, so the runner can hold every task together.
#[async_trait]
trait AnyProvisionerTask: Send + Sync {
    fn start_window(&self) -> time::Duration;

    fn progress_timeout(&self) -> time::Duration;

    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value;

    fn failed_payload(&self, error: &Permanent, last: &serde_json::Value) -> serde_json::Value;

    fn restart_failure(&self) -> Option<Permanent>;

    async fn run(&self, attempt: &Attempt, params: serde_json::Value) -> Result<serde_json::Value, AttemptError>;

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

    fn failed_payload(&self, error: &Permanent, last: &serde_json::Value) -> serde_json::Value {
        ProvisionerTask::failed_payload(self, error, last)
    }

    fn restart_failure(&self) -> Option<Permanent> {
        ProvisionerTask::restart_failure(self)
    }

    async fn run(&self, attempt: &Attempt, params: serde_json::Value) -> Result<serde_json::Value, AttemptError> {
        let params = serde_json::from_value(params).map_err(|error| {
            warn!(task.id = %attempt.task_id, %error, "Invalid Task parameters");
            AttemptError::Permanent(Permanent::InvalidTask)
        })?;

        let output = ProvisionerTask::run(self, attempt, params).await?;

        serde_json::to_value(output).map_err(|error| {
            error!(task.id = %attempt.task_id, %error, "Failed to serialize the Task result");
            AttemptError::Permanent(Permanent::Internal)
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
            Ok(()) => self.enqueue(id, job_token, None).await,
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

    /// Hands every unfinished record to a new job, since a record created just before Gateway stopped may have none.
    ///
    /// Each record gets a new `job_token`, so a job left from before finds itself superseded and stops, and the job
    /// queue is never read.
    /// A record whose task cannot outlive a restart fails first, and its new job only ends it.
    /// Call it at startup, before the job runner claims any job, so no job runs an attempt meanwhile.
    /// A record whose new job cannot be queued is failed, since no job is left to run it.
    pub async fn resume(&self) -> anyhow::Result<()> {
        let now = OffsetDateTime::now_utc();
        let records = self.inner.store.list_unfinished(now).await?;

        for record in records {
            let job_token = Uuid::new_v4();

            match self.inner.store.replace_job_token(record.id, job_token, now).await {
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
                match self
                    .inner
                    .store
                    .fail(record.id, task.failed_payload(&failure, &record.payload), now)
                    .await
                {
                    Ok(_) => info!(
                        task.id = %record.id,
                        task.kind = %record.kind,
                        ?failure,
                        "Task failed, since it cannot outlive a restart"
                    ),
                    // Its new job runs the attempt then, which fails the same way.
                    Err(error) => error!(
                        task.id = %record.id,
                        task.kind = %record.kind,
                        error = format!("{error:#}"),
                        "Failed to fail the Task that cannot outlive a restart"
                    ),
                }
            }

            match self.enqueue(record.id, job_token, None).await {
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
        schedule_for: Option<OffsetDateTime>,
    ) -> anyhow::Result<()> {
        self.inner
            .job_queue
            .push(
                ProvisionerTaskJob {
                    task_id,
                    job_token,
                    runner: self.clone(),
                },
                schedule_for,
            )
            .await
    }

    /// Runs one attempt for the job holding `job_token`.
    ///
    /// The record counts its attempts, and the job queues the next one itself, so the job queue retries a job only when
    /// what it had to record or queue could not be stored.
    async fn run_attempt(&self, task_id: Uuid, job_token: Uuid) -> anyhow::Result<()> {
        let store = &self.inner.store;
        let now = OffsetDateTime::now_utc();

        // The starting payload carries over what earlier attempts reported, so the record is read first.
        let Some(record) = store.get(task_id, now).await? else {
            debug!(task.id = %task_id, "Task is unknown, so this attempt does not run");
            return Ok(());
        };

        let Some(task) = self.task(&record.kind) else {
            if record.job_token == job_token && !record.state.is_finished() {
                error!(task.id = %task_id, task.kind = %record.kind, "Task of an unknown kind");
                // Without its kind, nothing else of the payload is known, so it holds the error alone.
                store
                    .fail(task_id, json!({ "error": Permanent::InvalidTask }), now)
                    .await
                    .context("record the Task failure")?;
            }
            return Ok(());
        };

        let starting_payload = task.starting_payload(&record.payload);
        let deadline_at = deadline(now, task.progress_timeout());

        let record = match store
            .start_attempt(task_id, job_token, starting_payload.clone(), deadline_at, now)
            .await?
        {
            AttemptStart::Started(record) => record,
            AttemptStart::Finished(record) => {
                debug!(task.id = %task_id, "Task is over, so this attempt does not run");
                return self.end_record(task.as_ref(), &record, job_token).await;
            }
            AttemptStart::Superseded => {
                debug!(task.id = %task_id, "Another job runs this Task, so this one stops");
                return Ok(());
            }
            AttemptStart::Unknown => {
                debug!(task.id = %task_id, "Task is unknown, so this attempt does not run");
                return Ok(());
            }
        };

        let attempts = record.attempts;
        let cancel = CancellationToken::new();
        let latest = Arc::new(Mutex::new(Latest {
            payload: starting_payload.clone(),
            deadline_at,
        }));
        let attempt = Attempt {
            task_id,
            target: record.target.clone(),
            attempts,
            payload: starting_payload,
            cancel: cancel.clone(),
            progress_timeout: task.progress_timeout(),
            store: Arc::clone(store),
            latest: Arc::clone(&latest),
        };

        info!(task.id = %task_id, task.kind = %record.kind, attempts, "Task attempt started");

        // The attempt has its own Tokio task, so a panic fails the record instead of leaving it running.
        let mut handle = tokio::spawn({
            let task = Arc::clone(&task);
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

                    warn!(task.id = %task_id, task.kind = %record.kind, attempts, "Task went past its deadline; its attempt is cancelled");
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

        let last = latest.lock().payload.clone();

        match outcome {
            Ok(output) => match store.succeed(task_id, output, OffsetDateTime::now_utc()).await {
                Ok(ended) => {
                    if ended {
                        info!(task.id = %task_id, task.kind = %record.kind, attempts, "Task succeeded");
                    } else {
                        warn!(
                            task.id = %task_id,
                            task.kind = %record.kind,
                            "Task attempt succeeded after the Task had ended, such as past its deadline; the Task keeps its earlier end"
                        );
                    }

                    self.end(task.as_ref(), task_id, job_token).await?;
                }
                // A success that cannot be recorded fails the Task instead of being retried, since a retry would do
                // the work again, such as paying for a second analysis.
                Err(error) => {
                    error!(
                        task.id = %task_id,
                        error = format!("{error:#}"),
                        "Failed to record the Task success; the Task fails instead"
                    );

                    let payload = task.failed_payload(&Permanent::Internal, &last);

                    match store.fail(task_id, payload, OffsetDateTime::now_utc()).await {
                        // The job retries only when the end could not be queued again, which then only ends the Task.
                        Ok(_) => self.end(task.as_ref(), task_id, job_token).await?,
                        Err(error) => {
                            error!(task.id = %task_id, error = format!("{error:#}"), "Failed to fail the Task; it fails at its deadline");

                            // The store fails the Task once its deadline passes, so a job that runs after it only ends it.
                            let after_deadline = latest.lock().deadline_at + time::Duration::SECOND;

                            if let Err(error) = self.enqueue(task_id, job_token, Some(after_deadline)).await {
                                error!(task.id = %task_id, error = format!("{error:#}"), "Failed to queue the end of the Task");
                            }
                        }
                    }
                }
            },
            Err(AttemptError::Recoverable(error)) if attempts < MAX_ATTEMPTS => {
                let retry_at = OffsetDateTime::now_utc() + retry_delay(attempts);
                warn!(task.id = %task_id, task.kind = %record.kind, attempts, ?error, %retry_at, "Task attempt failed; it will be retried");
                self.enqueue(task_id, job_token, Some(retry_at))
                    .await
                    .context("queue the next attempt")?;
            }
            Err(AttemptError::Recoverable(error)) => {
                warn!(task.id = %task_id, task.kind = %record.kind, attempts, ?error, "Task failed after its last attempt");
                self.fail(
                    task.as_ref(),
                    task_id,
                    job_token,
                    &Permanent::AttemptsExhausted { last: error },
                    &last,
                )
                .await?;
            }
            Err(AttemptError::Permanent(error)) => {
                warn!(task.id = %task_id, task.kind = %record.kind, attempts, ?error, "Task failed");
                self.fail(task.as_ref(), task_id, job_token, &error, &last).await?;
            }
        }

        Ok(())
    }

    /// Records the failure, then ends the record.
    ///
    /// If the failure cannot be recorded, nothing is dropped, since the record may still run, and the error is returned so
    /// the job queue tries again.
    async fn fail(
        &self,
        task: &dyn AnyProvisionerTask,
        task_id: Uuid,
        job_token: Uuid,
        error: &Permanent,
        last: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.inner
            .store
            .fail(task_id, task.failed_payload(error, last), OffsetDateTime::now_utc())
            .await
            .context("record the Task failure")?;

        self.end(task, task_id, job_token).await
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
    async fn end(&self, task: &dyn AnyProvisionerTask, task_id: Uuid, job_token: Uuid) -> anyhow::Result<()> {
        match self.inner.store.get(task_id, OffsetDateTime::now_utc()).await {
            Ok(Some(record)) => self.end_record(task, &record, job_token).await,
            Ok(None) => Ok(()),
            Err(error) => self.end_later(task_id, job_token, error).await,
        }
    }

    async fn end_record(
        &self,
        task: &dyn AnyProvisionerTask,
        record: &ProvisionerTaskRecord,
        job_token: Uuid,
    ) -> anyhow::Result<()> {
        match task.on_end(record).await {
            Ok(()) => Ok(()),
            Err(error) => self.end_later(record.id, job_token, error).await,
        }
    }

    /// Hands the record to a new job that ends it again later; an error means that job could not be queued.
    async fn end_later(&self, task_id: Uuid, job_token: Uuid, error: anyhow::Error) -> anyhow::Result<()> {
        warn!(task.id = %task_id, error = format!("{error:#}"), "Failed to end the Task; it is ended again later");

        self.enqueue(task_id, job_token, Some(OffsetDateTime::now_utc() + END_RETRY_DELAY))
            .await
            .context("queue the end of the Task again")
    }
}

/// The deadline `timeout` after `now`, in whole seconds as the store keeps it, so the runner and the store agree on when
/// it passes.
fn deadline(now: OffsetDateTime, timeout: time::Duration) -> OffsetDateTime {
    (now + timeout).truncate_to_second()
}

#[derive(Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobDef {
    task_id: Uuid,
    job_token: Uuid,
}

/// The job of a provisioner task record: it only wakes the record up, and the record decides what runs.
pub struct ProvisionerTaskJob {
    task_id: Uuid,
    job_token: Uuid,
    runner: ProvisionerTaskRunner,
}

impl ProvisionerTaskJob {
    pub const NAME: &'static str = "provisioner-task";

    pub fn read_json(json: &str, runner: ProvisionerTaskRunner) -> anyhow::Result<Self> {
        let def: JobDef = serde_json::from_str(json).context("failed to deserialize ProvisionerTaskJob")?;

        Ok(Self {
            task_id: def.task_id,
            job_token: def.job_token,
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
        })
        .context("failed to serialize ProvisionerTaskJob")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        self.runner.run_attempt(self.task_id, self.job_token).await
    }
}
