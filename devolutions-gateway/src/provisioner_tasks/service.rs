//! The one task that records Tasks: it holds the task store and the job queue, so a Task and its job are written
//! together or not at all, and the handlers only ask it.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use job_queue::{DynJob, DynJobQueue};
use provisioner_task::{CreateOutcome, DynProvisionerTaskStore, NewProvisionerTaskRecord, ProvisionerTaskRecord};
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::{ProvisionerTask, TaskJob, deadline};

/// What is done for a new Task once its record is written and before it is committed, such as keeping its secrets.
type OnCreated = Box<dyn FnOnce(&NewProvisionerTaskRecord) -> anyhow::Result<()> + Send>;

/// Builds the job of a new Task from the task store, which only the service holds.
type JobOf = Box<dyn FnOnce(DynProvisionerTaskStore) -> DynJob + Send>;

enum Message {
    Create {
        record: NewProvisionerTaskRecord,
        job_of: JobOf,
        on_created: OnCreated,
        reply: oneshot::Sender<anyhow::Result<CreateOutcome>>,
    },
    Get {
        id: Uuid,
        reply: oneshot::Sender<anyhow::Result<Option<ProvisionerTaskRecord>>>,
    },
}

/// Asks the provisioner task service to record or read Tasks.
#[derive(Clone)]
pub struct ProvisionerTaskHandle(mpsc::Sender<Message>);

pub struct ProvisionerTaskReceiver(mpsc::Receiver<Message>);

pub fn provisioner_task_channel() -> (ProvisionerTaskHandle, ProvisionerTaskReceiver) {
    let (tx, rx) = mpsc::channel(64);
    (ProvisionerTaskHandle(tx), ProvisionerTaskReceiver(rx))
}

impl ProvisionerTaskHandle {
    /// Records a Task of `task` and stores the job that runs it, both or neither.
    ///
    /// `on_created` runs only for a new record, before its job is stored, so what the job needs is in place before it
    /// can run; if it or storing the job fails, nothing is recorded. A known ID or a busy target creates nothing and
    /// stores nothing.
    pub async fn create<T: ProvisionerTask>(
        &self,
        task: T,
        id: Uuid,
        target: String,
        params: &T::Params,
        on_created: impl FnOnce(&NewProvisionerTaskRecord) -> anyhow::Result<()> + Send + 'static,
    ) -> anyhow::Result<CreateOutcome> {
        let params = serde_json::to_value(params).context("serialize the task parameters")?;
        let now = OffsetDateTime::now_utc();
        let job_token = Uuid::new_v4();
        let record = NewProvisionerTaskRecord {
            id,
            kind: T::KIND.to_owned(),
            target,
            params,
            deadline_at: deadline(now, T::START_WINDOW),
            job_token,
        };
        let job_of: JobOf = Box::new(move |store| Box::new(TaskJob::new(id, job_token, task, store)));

        let (reply, outcome) = oneshot::channel();
        self.0
            .send(Message::Create {
                record,
                job_of,
                on_created: Box::new(on_created),
                reply,
            })
            .await
            .ok()
            .context("couldn't send Create message")?;
        outcome.await.context("couldn't receive Create result")?
    }

    /// Reads a Task, after failing it if it is past its deadline.
    pub async fn get(&self, id: Uuid) -> anyhow::Result<Option<ProvisionerTaskRecord>> {
        let (reply, record) = oneshot::channel();
        self.0
            .send(Message::Get { id, reply })
            .await
            .ok()
            .context("couldn't send Get message")?;
        record.await.context("couldn't receive Get result")?
    }
}

/// The provisioner task service: the only one to write Tasks and their jobs from a request.
pub struct ProvisionerTaskService {
    store: DynProvisionerTaskStore,
    job_queue: DynJobQueue,
    rx: ProvisionerTaskReceiver,
}

impl ProvisionerTaskService {
    pub fn new(store: DynProvisionerTaskStore, job_queue: DynJobQueue, rx: ProvisionerTaskReceiver) -> Self {
        Self { store, job_queue, rx }
    }

    async fn create(
        &self,
        record: NewProvisionerTaskRecord,
        job_of: JobOf,
        on_created: OnCreated,
    ) -> anyhow::Result<CreateOutcome> {
        let now = OffsetDateTime::now_utc();
        let job = job_of(Arc::clone(&self.store));

        let store_job = async {
            on_created(&record).context("prepare the Task")?;
            self.job_queue.push_job(&job, None).await
        };
        let outcome = self.store.create(record.clone(), now, Box::pin(store_job)).await?;

        if matches!(outcome, CreateOutcome::Created(_)) {
            info!(task.id = %record.id, task.kind = %record.kind, "Task queued");
        }

        Ok(outcome)
    }
}

#[async_trait]
impl Task for ProvisionerTaskService {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "provisioner task service";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        provisioner_task_service(self, shutdown_signal).await
    }
}

#[instrument(skip_all)]
async fn provisioner_task_service(
    mut service: ProvisionerTaskService,
    mut shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    debug!("Task started");

    loop {
        tokio::select! {
            message = service.rx.0.recv() => {
                let Some(message) = message else {
                    debug!("All senders are dead");
                    break;
                };

                match message {
                    Message::Create { record, job_of, on_created, reply } => {
                        let _ = reply.send(service.create(record, job_of, on_created).await);
                    }
                    Message::Get { id, reply } => {
                        let _ = reply.send(service.store.get(id, OffsetDateTime::now_utc()).await);
                    }
                }
            }
            () = shutdown_signal.wait() => break,
        }
    }

    debug!("Task terminated");

    Ok(())
}
