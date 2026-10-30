use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use parking_lot::Mutex;
use provisioner_task::{AttemptStart, DynProvisionerTaskStore, ProvisionerTaskRecord};
use serde::Serialize;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{Attempt, AttemptError, MAX_ATTEMPTS, Permanent, ProvisionerTask, deadline};

/// `value` as JSON for the logs, empty if it cannot be written.
fn log_json(value: &impl Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_default()
}

/// The job of a record of the task `T`: it wakes the record up, and the record decides what runs.
///
/// It runs the attempts of `T` until the record ends, each in three steps: the prelude records its start, the body runs
/// [`ProvisionerTask::run`], and the completion records how the last one ended. A record that has ended is ended
/// instead.
pub struct TaskJob<T> {
    pub(super) task_id: Uuid,
    job_token: Uuid,
    task: T,
    store: DynProvisionerTaskStore,
}

/// What the job queue stores of a [`TaskJob<T>`]: the ID of its record and the token recorded with it.
#[derive(Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", bound = "")]
struct TaskJobUnhydrated<T> {
    task_id: Uuid,
    /// Matches [`ProvisionerTaskRecord::job_token`] of the record this job was stored with.
    job_token: Uuid,
    #[serde(skip)]
    task: PhantomData<T>,
}

impl<T: ProvisionerTask> TaskJob<T> {
    /// The name its jobs are stored under.
    pub const NAME: &'static str = T::KIND;

    /// The job of the record `task_id`, recorded with `job_token`.
    pub(super) fn new(task_id: Uuid, job_token: Uuid, task: T, store: DynProvisionerTaskStore) -> Self {
        Self {
            task_id,
            job_token,
            task,
            store,
        }
    }

    /// The job read back from what the job queue stored of it, with its task and the task store.
    pub fn read_json(json: &str, task: T, store: DynProvisionerTaskStore) -> anyhow::Result<Self> {
        let TaskJobUnhydrated::<T> { task_id, job_token, .. } =
            serde_json::from_str(json).context("failed to deserialize TaskJob")?;

        Ok(Self::new(task_id, job_token, task, store))
    }

    /// Records the failure, from the payload the record has, then ends the record.
    async fn fail(&self, error: &Permanent<T::Failure, T::Recoverable>) -> anyhow::Result<()> {
        let now = OffsetDateTime::now_utc();
        let last = self
            .store
            .get(self.task_id, now)
            .await
            .context("read the Task before its failure")?
            .map_or(serde_json::Value::Null, |record| record.payload);

        self.store
            .fail(self.task_id, self.task.failed_payload(error, &last), now)
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
    /// A record that has ended is ended instead. A record not there yet is an error, so the job queue runs the job
    /// again once it is; a record with another job token belongs to another job, so this one does nothing.
    async fn prelude(&self) -> anyhow::Result<Option<ProvisionerTaskRecord>> {
        let Self { task, store, .. } = self;
        let now = OffsetDateTime::now_utc();

        // The starting payload carries over what earlier attempts reported, so the record is read first.
        let Some(record) = store.get(self.task_id, now).await? else {
            anyhow::bail!("Task {} is not recorded yet", self.task_id);
        };

        if record.job_token != self.job_token {
            debug!(task.id = %self.task_id, "Task has another job, so this attempt does not run");
            return Ok(None);
        }

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
            self.fail(&Permanent::Internal).await?;
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
            AttemptStart::Unknown => anyhow::bail!("Task {} is not recorded anymore", self.task_id),
        }
    }

    /// The body: runs the attempt of `T`, and cancels it once the record is past its deadline.
    async fn body(
        &self,
        record: &ProvisionerTaskRecord,
    ) -> Result<T::Output, AttemptError<T::Failure, T::Recoverable>> {
        let params = match serde_json::from_value::<T::Params>(record.params.clone()) {
            Ok(params) => params,
            Err(error) => {
                warn!(task.id = %record.id, %error, "Invalid Task parameters");
                return Err(AttemptError::Permanent(Permanent::InvalidTask));
            }
        };

        // Progress moves the deadline, so the attempt shares it with the loop below that enforces it.
        let deadline_at = Arc::new(Mutex::new(record.deadline_at));
        let cancel = CancellationToken::new();
        let attempt = Attempt {
            task_id: record.id,
            target: record.target.clone(),
            attempts: record.attempts,
            payload: record.payload.clone(),
            cancel: cancel.clone(),
            progress_timeout: self.task.progress_timeout(),
            store: Arc::clone(&self.store),
            deadline_at: Arc::clone(&deadline_at),
        };

        info!(task.id = %record.id, task.kind = %record.kind, attempts = record.attempts, "Task attempt started");

        let run = self.task.run(&attempt, params);
        tokio::pin!(run);

        let mut past_deadline = false;
        let outcome = loop {
            let wait =
                std::time::Duration::try_from(*deadline_at.lock() - OffsetDateTime::now_utc()).unwrap_or_default();

            tokio::select! {
                outcome = &mut run => break outcome,
                () = tokio::time::sleep(wait) => {
                    // Progress may have moved the deadline while the timer ran.
                    if OffsetDateTime::now_utc() < *deadline_at.lock() {
                        continue;
                    }

                    warn!(
                        task.id = %record.id,
                        task.kind = %record.kind,
                        attempts = record.attempts,
                        "Task went past its deadline; its attempt is cancelled"
                    );
                    past_deadline = true;
                    // Dropping cannot stop blocking steps, so the attempt is cancelled and awaited instead: what runs
                    // once the Task ends never runs alongside it.
                    cancel.cancel();
                    break run.await;
                }
            }
        };

        match outcome {
            // The attempt stopped because it was cancelled, whatever error it reports for it.
            Err(_) if past_deadline => Err(AttemptError::Permanent(Permanent::DeadlinePassed)),
            outcome => outcome,
        }
    }

    /// The completion: publishes and records how the last attempt ended, then ends the record.
    ///
    /// A success is published in the step that records it, so a `succeeded` record always has its output published.
    /// Recording the end and dropping what the record kept are separate steps, so a failed drop never undoes the end.
    async fn completion(
        &self,
        record: &ProvisionerTaskRecord,
        outcome: Result<T::Output, Permanent<T::Failure, T::Recoverable>>,
    ) -> anyhow::Result<()> {
        let store = &self.store;
        let (task_id, attempts) = (record.id, record.attempts);

        match outcome {
            Ok(output) => {
                let payload = match serde_json::to_value(&output) {
                    Ok(payload) => payload,
                    Err(error) => {
                        error!(task.id = %task_id, %error, "Failed to serialize the Task result");
                        return self.fail(&Permanent::Internal).await;
                    }
                };

                let publish = Box::pin(async {
                    self.task
                        .publish(record, &output)
                        .await
                        .context("publish the Task result")
                });
                let succeeded = store
                    .succeed(task_id, payload, OffsetDateTime::now_utc(), publish)
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
            Err(error) => {
                warn!(
                    task.id = %task_id,
                    task.kind = %record.kind,
                    attempts,
                    error = %log_json(&error),
                    "Task failed"
                );
                self.fail(&error).await
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
        serde_json::to_string(&TaskJobUnhydrated::<T> {
            task_id: self.task_id,
            job_token: self.job_token,
            task: PhantomData,
        })
        .context("failed to serialize TaskJob")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let Some(record) = self.prelude().await? else {
                return Ok(());
            };

            // The body ends the attempt; the completion ends the record, so only what ends it reaches the completion.
            let outcome = match self.body(&record).await {
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
                    continue;
                }
                Err(AttemptError::Recoverable(last)) => Err(Permanent::AttemptsExhausted { last }),
                Err(AttemptError::Permanent(error)) => Err(error),
                Ok(output) => Ok(output),
            };

            return self.completion(&record, outcome).await;
        }
    }
}
