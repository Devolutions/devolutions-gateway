//! Runs provisioner tasks: the one place that keeps a task's record and the job running it in step.
//!
//! Each kind of work is a [`ProvisionerTask`]: what one attempt does, what its payloads hold, and what to do once it has
//! ended.
//! Its job is a [`TaskJob`], a job like any other on the job queue, which wraps each attempt in a prelude and a
//! completion: the prelude records the start of the attempt, and the completion records how it ended and ends the record.
//! After a recoverable failure, the job waits [`ProvisionerTask::retry_delay`] and runs the next attempt itself, up to
//! [`MAX_ATTEMPTS`].
//! [`create`] records a Task and stores its job.
//!
//! The record is the source of truth and the job only wakes it up.
//! The job queue delivers the job at least once, so after a restart the job picks the record up where it left off, and
//! [`requeue_lost_jobs`] stores the job of a record Gateway stopped before storing it.

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::marker::PhantomData;
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
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{AttemptError, Permanent};
use crate::job_queue::{DurableJobQueue, StorableJob};

/// Attempts a record gets: a recoverable failure of the last one fails the record.
pub const MAX_ATTEMPTS: u32 = 5;

/// A provisioner task: the work Gateway does for one kind of request, such as `recording-ai-analysis`.
///
/// One value serves every record of its kind, so it keeps only what they share; what belongs to one record comes in
/// through [`Attempt`] and the parameters.
#[async_trait]
pub trait ProvisionerTask: Send + Sync + 'static {
    /// The kind written in the records of this task, and the name of its jobs.
    const KIND: &'static str;

    /// Time from the creation of a record until its first attempt must start.
    const START_WINDOW: time::Duration;

    /// What the record keeps as asked; never secrets, since records are kept and returned to callers.
    type Params: Serialize + DeserializeOwned + Send + 'static;

    /// The payload of a `succeeded` record.
    type Output: Serialize + Send + 'static;

    /// Why an attempt of this task fails for good, next to the failures any task may have.
    type Failure: Serialize + Send + Sync + 'static;

    /// Why an attempt of this task fails for now, so a later attempt may succeed.
    type Recoverable: Serialize + Send + Sync + 'static;

    /// Time a running record may go without progress: each attempt start and each progress report moves its deadline
    /// this far ahead.
    fn progress_timeout(&self) -> time::Duration;

    /// Time to wait after attempt `attempts` failed with a recoverable failure, before the next attempt starts.
    fn retry_delay(&self, attempts: u32) -> time::Duration;

    /// The payload of the running record as an attempt starts, from `last`, its payload until then: `null` before its
    /// first attempt.
    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value;

    /// The payload of a record that failed with `error`, from `last`, its payload until then: `null` if it never ran.
    fn failed_payload(
        &self,
        error: &Permanent<Self::Failure, Self::Recoverable>,
        last: &serde_json::Value,
    ) -> serde_json::Value;

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
    /// It may be called again for a record that already ended, so it must be idempotent; an error returns from the job,
    /// and the job queue runs the job again, which calls it again.
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

/// What the job knows of the running record: the last payload of the attempt, and the deadline it stored.
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

/// `value` as JSON for the logs, empty if it cannot be written.
fn log_json(value: &impl Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_default()
}

/// Records a Task of `T` and stores the job that runs it.
///
/// `on_created` runs only for a new record, before its job is stored, so what the job needs is in place before it can
/// run; if it fails, no job is stored. A known ID or a busy target creates nothing and stores nothing.
pub async fn create<T: ProvisionerTask>(
    store: &DynProvisionerTaskStore,
    job_queue: &DurableJobQueue,
    id: Uuid,
    target: String,
    params: &T::Params,
    on_created: impl FnOnce(&ProvisionerTaskRecord) -> anyhow::Result<()> + Send,
) -> anyhow::Result<CreateOutcome> {
    let params = serde_json::to_value(params).context("serialize the task parameters")?;
    let now = OffsetDateTime::now_utc();
    let job = TaskJobUnhydrated::<T> {
        task_id: id,
        task: PhantomData,
    };

    let outcome = store
        .create(
            NewProvisionerTaskRecord {
                id,
                kind: T::KIND.to_owned(),
                target,
                params,
                deadline_at: deadline(now, T::START_WINDOW),
            },
            now,
        )
        .await?;

    let CreateOutcome::Created(record) = &outcome else {
        return Ok(outcome);
    };

    on_created(record).context("prepare the Task")?;

    job_queue.push(&job, None).await?;

    info!(task.id = %id, task.kind = T::KIND, "Task queued");

    Ok(outcome)
}

/// Stores again the job of every queued record of `T` that has none among `job_defs`, the JSON of the jobs stored under
/// [`TaskJob::NAME`], as when Gateway stopped between recording a Task and storing its job.
///
/// Call it at startup, before the job runner claims any job, so a job that runs meanwhile is never taken for lost.
pub async fn requeue_lost_jobs<T: ProvisionerTask>(
    store: &DynProvisionerTaskStore,
    job_queue: &DurableJobQueue,
    job_defs: &[String],
) -> anyhow::Result<()> {
    let stored = job_defs
        .iter()
        .map(|json| TaskJobUnhydrated::<T>::read_json(json).map(|job| job.task_id))
        .collect::<anyhow::Result<HashSet<Uuid>>>()?;

    for record in store.list_unfinished(OffsetDateTime::now_utc()).await? {
        if record.kind != T::KIND || record.state != ProvisionerTaskState::Queued || stored.contains(&record.id) {
            continue;
        }

        let job = TaskJobUnhydrated::<T> {
            task_id: record.id,
            task: PhantomData,
        };
        job_queue.push(&job, None).await?;

        info!(task.id = %record.id, task.kind = %record.kind, "Task job queued again");
    }

    Ok(())
}

/// The deadline `timeout` after `now`, in whole seconds as the store keeps it, so Gateway and the store agree on when
/// it passes.
fn deadline(now: OffsetDateTime, timeout: time::Duration) -> OffsetDateTime {
    (now + timeout).truncate_to_second()
}

/// The job of a record of the task `T`: it wakes the record up, and the record decides what runs.
///
/// It runs the attempts of `T` until the record ends, each in three steps: the prelude records its start, the body runs
/// [`ProvisionerTask::run`], and the completion records how the last one ended. A record that has ended is ended
/// instead.
pub struct TaskJob<T> {
    task_id: Uuid,
    task: Arc<T>,
    store: DynProvisionerTaskStore,
}

/// A [`TaskJob<T>`] as the job queue stores it, before it gets its task and the task store.
#[derive(Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", bound = "")]
pub struct TaskJobUnhydrated<T> {
    task_id: Uuid,
    #[serde(skip)]
    task: PhantomData<T>,
}

impl<T: ProvisionerTask> TaskJobUnhydrated<T> {
    pub fn read_json(json: &str) -> anyhow::Result<Self> {
        serde_json::from_str(json).context("failed to deserialize TaskJob")
    }

    pub fn into_job(self, task: Arc<T>, store: DynProvisionerTaskStore) -> TaskJob<T> {
        TaskJob {
            task_id: self.task_id,
            task,
            store,
        }
    }
}

impl<T: ProvisionerTask> StorableJob for TaskJobUnhydrated<T> {
    fn name(&self) -> &str {
        TaskJob::<T>::NAME
    }

    fn write_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(self).context("failed to serialize TaskJob")
    }
}

impl<T: ProvisionerTask> TaskJob<T> {
    /// The name its jobs are stored under.
    pub const NAME: &'static str = T::KIND;

    /// Records the failure, then ends the record.
    async fn fail(
        &self,
        error: &Permanent<T::Failure, T::Recoverable>,
        last: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.store
            .fail(
                self.task_id,
                self.task.failed_payload(error, last),
                OffsetDateTime::now_utc(),
            )
            .await
            .context("record the Task failure")?;

        self.end().await
    }

    /// Ends the record, read again so its task sees how it ended.
    async fn end(&self) -> anyhow::Result<()> {
        match self.store.get(self.task_id, OffsetDateTime::now_utc()).await? {
            Some(record) => self.end_record(&record).await,
            None => Ok(()),
        }
    }

    /// Does what the finished record leaves to do; a record still unfinished is left to its attempt.
    async fn end_record(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()> {
        if !record.state.is_finished() {
            return Ok(());
        }

        self.task.on_end(record).await.context("end the Task")
    }

    /// The prelude: marks the start of one more attempt on the record, unless it has ended.
    ///
    /// A record that has ended is ended instead.
    async fn prelude(&self) -> anyhow::Result<Option<ProvisionerTaskRecord>> {
        let Self { task, store, .. } = self;
        let now = OffsetDateTime::now_utc();

        // The starting payload carries over what earlier attempts reported, so the record is read first.
        let Some(record) = store.get(self.task_id, now).await? else {
            error!(task.id = %self.task_id, "Task is unknown, so this attempt does not run");
            return Ok(None);
        };

        if record.state.is_finished() {
            debug!(task.id = %self.task_id, "Task is over, so this attempt does not run");
            self.end_record(&record).await?;
            return Ok(None);
        }

        // A restart in the middle of the last attempt delivers the job again.
        if MAX_ATTEMPTS <= record.attempts {
            warn!(
                task.id = %self.task_id,
                task.kind = %record.kind,
                attempts = record.attempts,
                "Task has no attempt left, so it fails without running another"
            );
            self.fail(&Permanent::Internal, &record.payload).await?;
            return Ok(None);
        }

        let starting_payload = task.starting_payload(&record.payload);
        let deadline_at = deadline(now, task.progress_timeout());

        match store
            .start_attempt(self.task_id, starting_payload, deadline_at, now)
            .await?
        {
            AttemptStart::Started(record) => Ok(Some(record)),
            AttemptStart::Finished(record) => {
                debug!(task.id = %self.task_id, "Task is over, so this attempt does not run");
                self.end_record(&record).await?;
                Ok(None)
            }
            AttemptStart::Unknown => {
                error!(task.id = %self.task_id, "Task is unknown, so this attempt does not run");
                Ok(None)
            }
        }
    }

    /// The body: runs the attempt of `T`, and cancels it once the record is past its deadline.
    ///
    /// Returns how the attempt ended, with the last payload it reported and the deadline it last set.
    async fn body(
        &self,
        record: &ProvisionerTaskRecord,
    ) -> (Result<T::Output, AttemptError<T::Failure, T::Recoverable>>, Latest) {
        let latest = Arc::new(Mutex::new(Latest {
            payload: record.payload.clone(),
            deadline_at: record.deadline_at,
        }));
        let take_latest = |latest: &Mutex<Latest>| {
            let latest = latest.lock();
            Latest {
                payload: latest.payload.clone(),
                deadline_at: latest.deadline_at,
            }
        };

        let params = match serde_json::from_value::<T::Params>(record.params.clone()) {
            Ok(params) => params,
            Err(error) => {
                warn!(task.id = %record.id, %error, "Invalid Task parameters");
                return (
                    Err(AttemptError::Permanent(Permanent::InvalidTask)),
                    take_latest(&latest),
                );
            }
        };

        let cancel = CancellationToken::new();
        let attempt = Attempt {
            task_id: record.id,
            target: record.target.clone(),
            attempts: record.attempts,
            payload: record.payload.clone(),
            cancel: cancel.clone(),
            progress_timeout: self.task.progress_timeout(),
            store: Arc::clone(&self.store),
            latest: Arc::clone(&latest),
        };

        info!(task.id = %record.id, task.kind = %record.kind, attempts = record.attempts, "Task attempt started");

        // The attempt has its own Tokio task, so a panic fails the record instead of leaving it running.
        let mut handle = tokio::spawn({
            let task = Arc::clone(&self.task);
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

        (outcome, take_latest(&latest))
    }

    /// The completion: records how the last attempt ended, then ends the record.
    ///
    /// Recording the end and dropping what the record kept are separate steps, so a failed drop never undoes the end.
    async fn completion(
        &self,
        record: &ProvisionerTaskRecord,
        outcome: Result<T::Output, AttemptError<T::Failure, T::Recoverable>>,
        latest: Latest,
    ) -> anyhow::Result<()> {
        let store = &self.store;
        let (task_id, attempts) = (record.id, record.attempts);
        let last = &latest.payload;

        match outcome {
            Ok(output) => {
                let output = match serde_json::to_value(output) {
                    Ok(output) => output,
                    Err(error) => {
                        error!(task.id = %task_id, %error, "Failed to serialize the Task result");
                        return self.fail(&Permanent::Internal, last).await;
                    }
                };

                let succeeded = store
                    .succeed(task_id, output, OffsetDateTime::now_utc())
                    .await
                    .context("record the Task success")?;

                if succeeded {
                    info!(task.id = %task_id, task.kind = %record.kind, attempts, "Task succeeded");
                } else {
                    warn!(
                        task.id = %task_id,
                        task.kind = %record.kind,
                        "Task attempt succeeded after the Task had ended, such as past its deadline; the Task keeps its earlier end"
                    );
                }

                self.end().await
            }
            Err(AttemptError::Recoverable(error)) => {
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    error = %log_json(&error),
                    "Task failed after its last attempt"
                );
                self.fail(&Permanent::AttemptsExhausted { last: error }, last).await
            }
            Err(AttemptError::Permanent(error)) => {
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    error = %log_json(&error),
                    "Task failed"
                );
                self.fail(&error, last).await
            }
        }
    }
}

#[async_trait]
impl<T: ProvisionerTask> job_queue::Job for TaskJob<T> {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn write_json(&self) -> anyhow::Result<String> {
        TaskJobUnhydrated::<T> {
            task_id: self.task_id,
            task: PhantomData,
        }
        .write_json()
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let Some(record) = self.prelude().await? else {
                return Ok(());
            };

            let (outcome, latest) = self.body(&record).await;

            match outcome {
                Err(AttemptError::Recoverable(error)) if record.attempts < MAX_ATTEMPTS => {
                    let delay = self.task.retry_delay(record.attempts);
                    warn!(
                        task.id = %record.id,
                        task.kind = %record.kind,
                        attempts = record.attempts,
                        error = %log_json(&error),
                        %delay,
                        "Task attempt failed; the next one runs after a delay"
                    );
                    tokio::time::sleep(std::time::Duration::try_from(delay).unwrap_or_default()).await;
                }
                outcome => return self.completion(&record, outcome, latest).await,
            }
        }
    }
}
