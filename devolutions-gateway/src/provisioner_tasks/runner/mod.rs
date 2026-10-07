//! Runs provisioner tasks: the one place that keeps a task's record and the job running it in step.
//!
//! Each kind of work is a [`ProvisionerTask`]: what one attempt does, and what to clean up once it has ended.
//! [`ProvisionerTaskRunner`] does the rest for every task. It creates the record, queues the job, starts each attempt,
//! retries transient failures, enforces the attempt timeout and records how the task ended.
//!
//! The record is the source of truth and the job only wakes it up. Each record names the one job allowed to run it, by
//! its token, so a stale or duplicate job stops without running anything. At startup, before any job runs,
//! [`ProvisionerTaskRunner::resume`] hands every unfinished record to a new job, which also covers a record created just
//! before a crash, before its job was queued.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use provisioner_task::{
    AttemptStart, CreateOutcome, DynProvisionerTaskStore, NewProvisionerTaskRecord, ProvisionerTaskRecord,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::AttemptError;
use crate::job_queue::{JobQueueHandle, MAX_ATTEMPTS};

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

    /// Time from the creation of a record to its end, waiting and retries included.
    fn deadline(&self) -> time::Duration;

    /// Time one attempt gets before it is cancelled and retried.
    fn attempt_timeout(&self) -> std::time::Duration;

    /// Runs one attempt.
    ///
    /// The attempt should stop soon after [`Attempt::cancel`] is cancelled, and return [`AttemptError::Cancelled`].
    async fn run(&self, attempt: &Attempt, params: Self::Params) -> Result<Self::Output, AttemptError>;

    /// Drops what is kept only while the record runs, once it has ended, however it ended.
    ///
    /// It may be called again for a record that already ended, so it must be idempotent.
    async fn on_end(&self, _record: &ProvisionerTaskRecord) {}
}

/// One attempt of a record, as its task sees it.
pub struct Attempt {
    pub task_id: Uuid,
    pub target: String,
    /// Attempts started so far, this one included.
    pub attempts: u32,
    pub cancel: CancellationToken,
    store: DynProvisionerTaskStore,
}

impl Attempt {
    /// Replaces the payload of the running record, so whoever asks about it sees how the attempt goes.
    pub async fn report_progress(&self, payload: serde_json::Value) {
        if let Err(error) = self.store.update_running(self.task_id, payload).await {
            warn!(task.id = %self.task_id, error = format!("{error:#}"), "Failed to record the Task progress");
        }
    }
}

/// [`ProvisionerTask`] with its types erased, so the runner can hold every task together.
#[async_trait]
trait AnyProvisionerTask: Send + Sync {
    fn deadline(&self) -> time::Duration;

    fn attempt_timeout(&self) -> std::time::Duration;

    async fn run(&self, attempt: &Attempt, params: serde_json::Value) -> Result<serde_json::Value, AttemptError>;

    async fn on_end(&self, record: &ProvisionerTaskRecord);
}

#[async_trait]
impl<T: ProvisionerTask> AnyProvisionerTask for T {
    fn deadline(&self) -> time::Duration {
        ProvisionerTask::deadline(self)
    }

    fn attempt_timeout(&self) -> std::time::Duration {
        ProvisionerTask::attempt_timeout(self)
    }

    async fn run(&self, attempt: &Attempt, params: serde_json::Value) -> Result<serde_json::Value, AttemptError> {
        let params = serde_json::from_value(params).map_err(|error| AttemptError::Failed {
            reason: "invalid task",
            details: format!("invalid parameters: {error}"),
        })?;

        let output = ProvisionerTask::run(self, attempt, params).await?;

        serde_json::to_value(output).map_err(|error| AttemptError::Permanent(format!("invalid result: {error}")))
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) {
        ProvisionerTask::on_end(self, record).await;
    }
}

/// Creates provisioner task records and runs them as jobs on the job queue.
#[derive(Clone)]
pub struct ProvisionerTaskRunner {
    inner: Arc<Inner>,
}

struct Inner {
    store: DynProvisionerTaskStore,
    job_queue: JobQueueHandle,
    /// Kind → the task that runs records of this kind.
    tasks: HashMap<&'static str, Arc<dyn AnyProvisionerTask>>,
}

pub struct ProvisionerTaskRunnerBuilder {
    store: DynProvisionerTaskStore,
    job_queue: JobQueueHandle,
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

/// Initial payload of a running record, until its task reports progress.
fn starting_payload() -> serde_json::Value {
    json!({ "step": "preparing" })
}

impl ProvisionerTaskRunner {
    pub fn builder(store: DynProvisionerTaskStore, job_queue: JobQueueHandle) -> ProvisionerTaskRunnerBuilder {
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
                    deadline_at: now + task.deadline(),
                    job_token,
                },
                now,
            )
            .await?;

        let CreateOutcome::Created(record) = &outcome else {
            return Ok(outcome);
        };

        if let Err(error) = on_created(record) {
            error!(task.id = %id, task.kind = T::KIND, error = format!("{error:#}"), "Failed to prepare the Task");
            self.fail(task.as_ref(), id, failure("not queued", &format!("{error:#}"), 0))
                .await;
            return Err(error);
        }

        if let Err(error) = self.enqueue(id, job_token).await {
            error!(task.id = %id, task.kind = T::KIND, error = format!("{error:#}"), "Failed to queue the Task");
            self.fail(task.as_ref(), id, failure("not queued", &format!("{error:#}"), 0))
                .await;
            return Err(error);
        }

        info!(task.id = %id, task.kind = T::KIND, "Task queued");

        Ok(outcome)
    }

    /// Hands every unfinished record to a new job queued with `push`: the jobs queued before stop at their next attempt.
    ///
    /// Call it at startup, before the job runner claims any job, so no earlier job is running an attempt meanwhile.
    pub async fn resume<F, Fut>(&self, push: F) -> anyhow::Result<()>
    where
        F: Fn(ProvisionerTaskJob) -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        let now = OffsetDateTime::now_utc();
        let records = self.inner.store.list_unfinished(now).await?;

        for record in records {
            let job_token = Uuid::new_v4();

            if !self.inner.store.replace_job_token(record.id, job_token, now).await? {
                continue;
            }

            let job = ProvisionerTaskJob {
                task_id: record.id,
                job_token,
                runner: self.clone(),
            };

            match push(job).await {
                Ok(()) => info!(task.id = %record.id, task.kind = %record.kind, "Task queued again"),
                Err(error) => error!(
                    task.id = %record.id,
                    task.kind = %record.kind,
                    error = format!("{error:#}"),
                    "Failed to queue the Task again; it fails at its deadline"
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

    async fn enqueue(&self, task_id: Uuid, job_token: Uuid) -> anyhow::Result<()> {
        self.inner
            .job_queue
            .enqueue(ProvisionerTaskJob {
                task_id,
                job_token,
                runner: self.clone(),
            })
            .await
    }

    /// Runs one attempt for the job holding `job_token`; returns an error only to ask the job queue for a retry.
    async fn run_attempt(&self, task_id: Uuid, job_token: Uuid) -> anyhow::Result<()> {
        let store = &self.inner.store;
        let now = OffsetDateTime::now_utc();

        let record = match store.start_attempt(task_id, job_token, starting_payload(), now).await? {
            AttemptStart::Started(record) => record,
            AttemptStart::Finished(record) => {
                debug!(task.id = %task_id, "Task is over, so this attempt does not run");
                if let Some(task) = self.task(&record.kind) {
                    task.on_end(&record).await;
                }
                return Ok(());
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

        let Some(task) = self.task(&record.kind) else {
            error!(task.id = %task_id, task.kind = %record.kind, "Task of an unknown kind");
            let details = format!("unknown task kind {}", record.kind);
            if let Err(error) = store
                .fail(task_id, failure("invalid task", &details, record.attempts), now)
                .await
            {
                error!(task.id = %task_id, error = format!("{error:#}"), "Failed to record the Task failure");
            }
            return Ok(());
        };

        let attempts = record.attempts;
        let attempt_timeout = task.attempt_timeout();
        let cancel = CancellationToken::new();
        let attempt = Attempt {
            task_id,
            target: record.target.clone(),
            attempts,
            cancel: cancel.clone(),
            store: Arc::clone(store),
        };

        info!(task.id = %task_id, task.kind = %record.kind, attempts, "Task attempt started");

        // The attempt has its own Tokio task, so a panic fails the record instead of leaving it running.
        let mut handle = tokio::spawn({
            let task = Arc::clone(&task);
            let params = record.params.clone();
            async move { task.run(&attempt, params).await }
        });

        let joined = match tokio::time::timeout(attempt_timeout, &mut handle).await {
            Ok(joined) => joined,
            Err(_) => {
                // Aborting cannot stop blocking steps, so the attempt is cancelled and awaited instead: the next
                // attempt never runs alongside it.
                cancel.cancel();
                handle.await
            }
        };

        let outcome = match joined {
            Ok(Err(AttemptError::Cancelled)) => Err(AttemptError::Transient(format!(
                "the attempt took longer than {attempt_timeout:?}"
            ))),
            Ok(outcome) => outcome,
            Err(_) => Err(AttemptError::Permanent("the attempt panicked".to_owned())),
        };

        match outcome {
            Ok(output) => {
                // An error here must not ask for a retry: the work is done.
                match store.succeed(task_id, output, OffsetDateTime::now_utc()).await {
                    Ok(true) => info!(task.id = %task_id, task.kind = %record.kind, attempts, "Task succeeded"),
                    Ok(false) => warn!(
                        task.id = %task_id,
                        task.kind = %record.kind,
                        "Task attempt succeeded after the Task had ended, such as past its deadline; the Task keeps its earlier end"
                    ),
                    Err(error) => error!(
                        task.id = %task_id,
                        error = format!("{error:#}"),
                        "Failed to record the Task result"
                    ),
                }

                self.end(task.as_ref(), task_id).await;
            }
            Err(AttemptError::Transient(details)) if attempts < MAX_ATTEMPTS => {
                warn!(task.id = %task_id, task.kind = %record.kind, attempts, %details, "Task attempt failed; it will be retried");
                anyhow::bail!("Task attempt failed: {details}");
            }
            Err(AttemptError::Transient(details)) => {
                warn!(task.id = %task_id, task.kind = %record.kind, attempts, %details, "Task failed after its last attempt");
                self.fail(
                    task.as_ref(),
                    task_id,
                    failure("attempts exhausted", &details, attempts),
                )
                .await;
            }
            Err(AttemptError::Permanent(details)) => {
                warn!(task.id = %task_id, task.kind = %record.kind, attempts, %details, "Task failed");
                self.fail(task.as_ref(), task_id, failure("permanent error", &details, attempts))
                    .await;
            }
            Err(AttemptError::Failed { reason, details }) => {
                warn!(task.id = %task_id, task.kind = %record.kind, attempts, reason, %details, "Task failed");
                self.fail(task.as_ref(), task_id, failure(reason, &details, attempts))
                    .await;
            }
            Err(AttemptError::Cancelled) => unreachable!("a cancelled attempt is reported as a timeout above"),
        }

        Ok(())
    }

    async fn fail(&self, task: &dyn AnyProvisionerTask, task_id: Uuid, payload: serde_json::Value) {
        if let Err(error) = self.inner.store.fail(task_id, payload, OffsetDateTime::now_utc()).await {
            error!(task.id = %task_id, error = format!("{error:#}"), "Failed to record the Task failure");
        }

        self.end(task, task_id).await;
    }

    async fn end(&self, task: &dyn AnyProvisionerTask, task_id: Uuid) {
        match self.inner.store.get(task_id, OffsetDateTime::now_utc()).await {
            Ok(Some(record)) => task.on_end(&record).await,
            Ok(None) => {}
            Err(error) => error!(task.id = %task_id, error = format!("{error:#}"), "Failed to read the ended Task"),
        }
    }
}

fn failure(reason: &str, details: &str, attempts: u32) -> serde_json::Value {
    json!({ "reason": reason, "details": details, "attempts": attempts })
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
