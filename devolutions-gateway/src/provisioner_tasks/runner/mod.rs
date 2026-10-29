//! Runs provisioner tasks: the one place that keeps a task's record and the job running it in step.
//!
//! Each kind of work is a [`ProvisionerTask`]: what one attempt does, what its payloads hold, and what to do once it has
//! ended.
//! Its job is a [`TaskJob`], a job like any other on the job queue, which wraps each attempt in a prelude and a
//! completion: the prelude records the start of the attempt, and the completion records how it ended and ends the record.
//! A recoverable failure goes back to the job queue, which runs the same job again later for the next attempt.
//! [`ProvisionerTaskManager`] creates the records, reads them, and recovers them at startup.
//!
//! The record is the source of truth and the job only wakes it up.
//! Each record names the one job allowed to run it, by its token, so a stale job stops without running anything.
//! At startup, before any job runs, [`ProvisionerTaskManager::resume`] hands every unfinished record to a new job,
//! which also covers a record created just before a crash, before its job was queued.

#[cfg(test)]
mod tests;

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
use crate::job_queue::DurableJobQueue;

/// Time before a record whose end failed is ended again.
const END_RETRY_DELAY: time::Duration = time::Duration::minutes(5);

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

    /// What the record keeps as asked; never secrets, since records are kept and returned to callers.
    type Params: Serialize + DeserializeOwned + Send + 'static;

    /// The payload of a `succeeded` record.
    type Output: Serialize + Send + 'static;

    /// Why an attempt of this task fails for good, next to the failures any task may have.
    type Failure: Serialize + Send + Sync + 'static;

    /// Why an attempt of this task fails for now, so a later attempt may succeed.
    type Recoverable: Serialize + Send + Sync + 'static;

    /// Time from the creation of a record until its first attempt must start.
    fn start_window(&self) -> time::Duration;

    /// Time a running record may go without progress: each attempt start and each progress report moves its deadline
    /// this far ahead.
    fn progress_timeout(&self) -> time::Duration;

    /// The payload of the running record as an attempt starts, from `last`, its payload until then: `null` before its
    /// first attempt.
    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value;

    /// The payload of a record that failed with `error`, from `last`, its payload until then: `null` if it never ran.
    fn failed_payload(
        &self,
        error: &Permanent<Self::Failure, Self::Recoverable>,
        last: &serde_json::Value,
    ) -> serde_json::Value;

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

/// Creates, reads and recovers the records of the task `T`, whose jobs are [`TaskJob<T>`].
pub struct ProvisionerTaskManager<T> {
    inner: Arc<Inner<T>>,
}

impl<T> Clone for ProvisionerTaskManager<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct Inner<T> {
    task: T,
    store: DynProvisionerTaskStore,
    job_queue: DurableJobQueue,
}

impl<T: ProvisionerTask> ProvisionerTaskManager<T> {
    pub fn new(task: T, store: DynProvisionerTaskStore, job_queue: DurableJobQueue) -> Self {
        Self {
            inner: Arc::new(Inner { task, store, job_queue }),
        }
    }

    pub(crate) fn task(&self) -> &T {
        &self.inner.task
    }

    /// Returns the record with this ID; one past its deadline is failed first.
    pub async fn get(&self, id: Uuid, now: OffsetDateTime) -> anyhow::Result<Option<ProvisionerTaskRecord>> {
        self.inner.store.get(id, now).await
    }

    /// Creates a record and queues the job that runs it.
    ///
    /// `on_created` runs only for a new record, before its job is queued, so what the job needs is in place before it
    /// can run; if it fails, the record fails and no job is queued. A known ID or a busy target creates nothing and
    /// queues nothing.
    pub async fn create(
        &self,
        id: Uuid,
        target: String,
        params: &T::Params,
        on_created: impl FnOnce(&ProvisionerTaskRecord) -> anyhow::Result<()> + Send,
    ) -> anyhow::Result<CreateOutcome> {
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
                    deadline_at: deadline(now, self.inner.task.start_window()),
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
            self.fail_not_queued(id, job_token, &serde_json::Value::Null).await;
            return Err(error);
        }

        info!(task.id = %id, task.kind = T::KIND, "Task queued");

        Ok(outcome)
    }

    /// Hands every unfinished record of `T` to a new job, since a record created just before Gateway stopped may have
    /// none.
    ///
    /// Each record gets a new `job_token`, so a job left from before finds itself superseded and stops, and the job
    /// queue is never read.
    /// The new job is stored before a record whose task cannot outlive a restart is failed, so a crash in between never
    /// leaves a finished record without a job to end it.
    /// A record that was waiting to retry runs at once, since retry timing is no promise to the caller.
    /// A record whose new job cannot be stored is failed, since no job is left to run it.
    /// Call it at startup, before the job runner claims any job, so no job runs an attempt meanwhile.
    pub async fn resume(&self) -> anyhow::Result<()> {
        let Inner { task, store, .. } = self.inner.as_ref();
        let now = OffsetDateTime::now_utc();

        for record in store.list_unfinished(now).await? {
            if record.kind != T::KIND {
                continue;
            }

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

            if let Err(error) = self.enqueue(record.id, job_token, None).await {
                error!(
                    task.id = %record.id,
                    task.kind = %record.kind,
                    error = format!("{error:#}"),
                    "Failed to queue the Task again"
                );
                self.fail_not_queued(record.id, job_token, &record.payload).await;
                continue;
            }

            info!(task.id = %record.id, task.kind = %record.kind, "Task queued again");

            let Some(failure) = task.restart_failure() else {
                continue;
            };
            let failure = Permanent::Kind(failure);

            match store
                .fail(record.id, task.failed_payload(&failure, &record.payload), now)
                .await
            {
                Ok(_) => info!(
                    task.id = %record.id,
                    task.kind = %record.kind,
                    failure = %log_json(&failure),
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

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn store(&self) -> &DynProvisionerTaskStore {
        &self.inner.store
    }

    /// Stores the job holding `job_token`, which wakes the record up at `schedule_for`, or at once without it.
    async fn enqueue(
        &self,
        task_id: Uuid,
        job_token: Uuid,
        schedule_for: Option<OffsetDateTime>,
    ) -> anyhow::Result<()> {
        let job = TaskJob {
            task_id,
            job_token,
            manager: self.clone(),
        };

        self.inner.job_queue.push(job, schedule_for).await
    }

    /// Records the failure, then ends the record.
    ///
    /// If the failure cannot be recorded, nothing is dropped, since the record may still run, and the error is returned.
    async fn fail(
        &self,
        task_id: Uuid,
        job_token: Uuid,
        error: &Permanent<T::Failure, T::Recoverable>,
        last: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.inner
            .store
            .fail(
                task_id,
                self.inner.task.failed_payload(error, last),
                OffsetDateTime::now_utc(),
            )
            .await
            .context("record the Task failure")?;

        self.end(task_id, job_token).await
    }

    /// Fails a record no job will run.
    async fn fail_not_queued(&self, task_id: Uuid, job_token: Uuid, last: &serde_json::Value) {
        if let Err(error) = self.fail(task_id, job_token, &Permanent::NotQueued, last).await {
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

    /// Does what the finished record leaves to do; a record still unfinished is left to its attempt.
    async fn end_record(&self, record: &ProvisionerTaskRecord, job_token: Uuid) -> anyhow::Result<()> {
        if !record.state.is_finished() {
            return Ok(());
        }

        match self.inner.task.on_end(record).await {
            Ok(()) => Ok(()),
            Err(error) => self.end_later(record.id, job_token, error).await,
        }
    }

    /// Wakes the record up again later, to end it then; an error means that job could not be stored.
    async fn end_later(&self, task_id: Uuid, job_token: Uuid, error: anyhow::Error) -> anyhow::Result<()> {
        warn!(task.id = %task_id, error = format!("{error:#}"), "Failed to end the Task; it is ended again later");

        self.enqueue(task_id, job_token, Some(OffsetDateTime::now_utc() + END_RETRY_DELAY))
            .await
            .context("queue the end of the Task again")
    }
}

/// The deadline `timeout` after `now`, in whole seconds as the store keeps it, so the manager, the job and the store
/// agree on when it passes.
fn deadline(now: OffsetDateTime, timeout: time::Duration) -> OffsetDateTime {
    (now + timeout).truncate_to_second()
}

#[derive(Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobDef {
    task_id: Uuid,
    job_token: Uuid,
}

/// The job of a record of the task `T`: it wakes the record up, and the record decides what runs.
///
/// It runs one attempt of `T` in three steps: the prelude records its start, the body runs [`ProvisionerTask::run`],
/// and the completion records how it ended. A record that has ended is ended instead.
pub struct TaskJob<T> {
    task_id: Uuid,
    job_token: Uuid,
    manager: ProvisionerTaskManager<T>,
}

/// A [`TaskJob<T>`] read back from its JSON, before it gets the manager of `T`.
pub struct TaskJobUnhydrated<T> {
    task_id: Uuid,
    job_token: Uuid,
    task: PhantomData<T>,
}

impl<T: ProvisionerTask> TaskJobUnhydrated<T> {
    pub fn into_job(self, manager: ProvisionerTaskManager<T>) -> TaskJob<T> {
        TaskJob {
            task_id: self.task_id,
            job_token: self.job_token,
            manager,
        }
    }
}

impl<T: ProvisionerTask> TaskJob<T> {
    /// The name its jobs are stored under.
    pub const NAME: &'static str = T::KIND;

    pub fn read_json(json: &str) -> anyhow::Result<TaskJobUnhydrated<T>> {
        let JobDef { task_id, job_token }: JobDef =
            serde_json::from_str(json).context("failed to deserialize TaskJob")?;

        Ok(TaskJobUnhydrated {
            task_id,
            job_token,
            task: PhantomData,
        })
    }

    /// The prelude: marks the start of one more attempt on the record, unless another job holds it, it has ended, or
    /// it has no attempt left.
    ///
    /// A record that has ended is ended instead.
    async fn prelude(&self) -> anyhow::Result<Option<ProvisionerTaskRecord>> {
        let Inner { task, store, .. } = self.manager.inner.as_ref();
        let now = OffsetDateTime::now_utc();

        // The starting payload carries over what earlier attempts reported, so the record is read first.
        let Some(record) = store.get(self.task_id, now).await? else {
            debug!(task.id = %self.task_id, "Task is unknown, so this attempt does not run");
            return Ok(None);
        };

        if record.kind != T::KIND {
            debug!(task.id = %self.task_id, task.kind = %record.kind, "Task of another kind, so this attempt does not run");
            return Ok(None);
        }

        if record.job_token != self.job_token {
            debug!(task.id = %self.task_id, "Another job runs this Task, so this one stops");
            return Ok(None);
        }

        if record.state.is_finished() {
            debug!(task.id = %self.task_id, "Task is over, so this attempt does not run");
            self.manager.end_record(&record, self.job_token).await?;
            return Ok(None);
        }

        // A job run again after its last attempt could not record how it ended would otherwise start one past the last.
        if MAX_ATTEMPTS <= record.attempts {
            warn!(
                task.id = %self.task_id,
                task.kind = %record.kind,
                attempts = record.attempts,
                "Task has no attempt left, so it fails without running another"
            );
            self.fail_terminal(&Permanent::Internal, &record.payload, record.deadline_at)
                .await?;
            return Ok(None);
        }

        let starting_payload = task.starting_payload(&record.payload);
        let deadline_at = deadline(now, task.progress_timeout());

        match store
            .start_attempt(self.task_id, self.job_token, starting_payload, deadline_at, now)
            .await?
        {
            AttemptStart::Started(record) => Ok(Some(record)),
            AttemptStart::Finished(record) => {
                debug!(task.id = %self.task_id, "Task is over, so this attempt does not run");
                self.manager.end_record(&record, self.job_token).await?;
                Ok(None)
            }
            AttemptStart::Superseded => {
                debug!(task.id = %self.task_id, "Another job runs this Task, so this one stops");
                Ok(None)
            }
            AttemptStart::Unknown => {
                debug!(task.id = %self.task_id, "Task is unknown, so this attempt does not run");
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
            progress_timeout: self.manager.inner.task.progress_timeout(),
            store: Arc::clone(&self.manager.inner.store),
            latest: Arc::clone(&latest),
        };

        info!(task.id = %record.id, task.kind = %record.kind, attempts = record.attempts, "Task attempt started");

        // The attempt has its own Tokio task, so a panic fails the record instead of leaving it running.
        let mut handle = tokio::spawn({
            let manager = self.manager.clone();
            async move { manager.inner.task.run(&attempt, params).await }
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

    /// The completion: records how the attempt ended, then ends the record, or returns a recoverable failure to the job
    /// queue, which runs this job again later for the next attempt.
    ///
    /// An end that cannot be recorded never goes back to the job queue, since that would run the attempt again, see
    /// [`TaskJob::fail_terminal`].
    /// Recording the end and dropping what the record kept are separate steps, so a failed drop never undoes the end.
    async fn completion(
        &self,
        record: &ProvisionerTaskRecord,
        outcome: Result<T::Output, AttemptError<T::Failure, T::Recoverable>>,
        latest: Latest,
    ) -> anyhow::Result<()> {
        let store = &self.manager.inner.store;
        let (task_id, attempts) = (record.id, record.attempts);
        let last = &latest.payload;

        match outcome {
            Ok(output) => {
                let output = match serde_json::to_value(output) {
                    Ok(output) => output,
                    Err(error) => {
                        error!(task.id = %task_id, %error, "Failed to serialize the Task result");
                        return self.fail_terminal(&Permanent::Internal, last, latest.deadline_at).await;
                    }
                };

                match store.succeed(task_id, output, OffsetDateTime::now_utc()).await {
                    Ok(true) => info!(task.id = %task_id, task.kind = %record.kind, attempts, "Task succeeded"),
                    Ok(false) => warn!(
                        task.id = %task_id,
                        task.kind = %record.kind,
                        "Task attempt succeeded after the Task had ended, such as past its deadline; the Task keeps its earlier end"
                    ),
                    // A retry would do the work again, such as paying for a second analysis.
                    Err(error) => {
                        error!(
                            task.id = %task_id,
                            error = format!("{error:#}"),
                            "Failed to record the Task success; the Task fails instead"
                        );
                        return self.fail_terminal(&Permanent::Internal, last, latest.deadline_at).await;
                    }
                }

                self.manager.end(task_id, self.job_token).await
            }
            Err(AttemptError::Recoverable(error)) if attempts < MAX_ATTEMPTS => {
                let error = log_json(&error);
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    %error,
                    "Task attempt failed; the job queue runs it again later"
                );
                anyhow::bail!("Task attempt {attempts} failed with {error}, to be retried")
            }
            Err(AttemptError::Recoverable(error)) => {
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    error = %log_json(&error),
                    "Task failed after its last attempt"
                );
                self.fail_terminal(&Permanent::AttemptsExhausted { last: error }, last, latest.deadline_at)
                    .await
            }
            Err(AttemptError::Permanent(error)) => {
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    error = %log_json(&error),
                    "Task failed"
                );
                self.fail_terminal(&error, last, latest.deadline_at).await
            }
        }
    }

    /// Records that the record failed with `failure`, then ends it.
    ///
    /// If the failure cannot be recorded, no error goes back to the job queue, since it would run the attempt again
    /// before the deadline: a job is stored to wake the record up past `deadline_at` instead, once the store has failed
    /// it and only its end is left.
    async fn fail_terminal(
        &self,
        failure: &Permanent<T::Failure, T::Recoverable>,
        last: &serde_json::Value,
        deadline_at: OffsetDateTime,
    ) -> anyhow::Result<()> {
        let Inner { task, store, .. } = self.manager.inner.as_ref();

        let recorded = store
            .fail(
                self.task_id,
                task.failed_payload(failure, last),
                OffsetDateTime::now_utc(),
            )
            .await;

        if let Err(error) = recorded {
            error!(
                task.id = %self.task_id,
                error = format!("{error:#}"),
                "Failed to fail the Task; it fails at its deadline"
            );

            let after_deadline = deadline_at + time::Duration::SECOND;

            if let Err(error) = self
                .manager
                .enqueue(self.task_id, self.job_token, Some(after_deadline))
                .await
            {
                error!(task.id = %self.task_id, error = format!("{error:#}"), "Failed to queue the end of the Task");
            }

            return Ok(());
        }

        self.manager.end(self.task_id, self.job_token).await
    }
}

#[async_trait]
impl<T: ProvisionerTask> job_queue::Job for TaskJob<T> {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn write_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(&JobDef {
            task_id: self.task_id,
            job_token: self.job_token,
        })
        .context("failed to serialize TaskJob")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        let Some(record) = self.prelude().await? else {
            return Ok(());
        };

        let (outcome, latest) = self.body(&record).await;

        self.completion(&record, outcome, latest).await
    }
}
