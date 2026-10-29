use std::future::Future;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ChildTask, ShutdownSignal, Task};
use job_queue::{DynJob, DynJobQueue, Job, JobCtx, JobQueue, JobReader, JobRunner, RunnerWaker};
use job_queue_libsql::libsql;
use provisioner_task::DynProvisionerTaskStore;
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc};

use crate::config::ConfHandle;
use crate::provisioner_tasks::recording_ai_analysis::RecordingAiAnalysis;
use crate::provisioner_tasks::runner::TaskJob;
use crate::recording::RecordingMessageSender;
use crate::secret_store::SecretStore;

pub struct JobQueueCtx {
    notify_runner: Arc<Notify>,
    runner_waker: RunnerWaker,
    queue: DynJobQueue,
    job_queue_rx: JobQueueReceiver,
    pub job_queue_handle: JobQueueHandle,
}

pub struct JobMessage {
    pub job: Box<dyn Job>,
    pub schedule_for: Option<OffsetDateTime>,
}

#[derive(Clone)]
pub struct JobQueueHandle {
    sender: mpsc::Sender<JobMessage>,
    in_memory_job_dependencies: Arc<OnceLock<InMemoryJobDependencies>>,
}

pub type JobQueueReceiver = mpsc::Receiver<JobMessage>;

/// What jobs need to run beyond their stored JSON, kept in memory only, such as the secrets of a Task.
#[derive(Clone)]
pub struct InMemoryJobDependencies {
    pub conf_handle: ConfHandle,
    pub recordings: RecordingMessageSender,
    pub secrets: SecretStore,
    pub task_store: DynProvisionerTaskStore,
    pub job_queue: DurableJobQueue,
}

/// A job read back from its JSON that still needs the in-memory dependencies to run.
pub trait UnhydratedJob {
    fn hydrate(self, dependencies: &InMemoryJobDependencies) -> DynJob;
}

pub struct JobQueueTask {
    queue: DynJobQueue,
    job_queue_rx: JobQueueReceiver,
}

pub struct JobRunnerTask {
    notify_runner: Arc<Notify>,
    runner_waker: RunnerWaker,
    queue: DynJobQueue,
    in_memory_job_dependencies: Arc<OnceLock<InMemoryJobDependencies>>,
}

impl JobQueueCtx {
    pub async fn init(database_path: &Path) -> anyhow::Result<Self> {
        let notify_runner = Arc::new(Notify::new());

        let runner_waker = RunnerWaker::new({
            let notify_runner = Arc::clone(&notify_runner);
            move || notify_runner.notify_one()
        });

        let database = libsql::Builder::new_local(database_path)
            .build()
            .await
            .context("build database")?;

        let conn = database.connect().context("open database connection")?;

        let queue = job_queue_libsql::LibSqlJobQueue::builder()
            .runner_waker(runner_waker.clone())
            .conn(conn)
            .build();

        let queue = Arc::new(queue);

        queue.setup().await.context("queue setup")?;

        queue
            .reset_claimed_jobs()
            .await
            .context("failed to reset claimed jobs")?;

        queue.clear_failed().await.context("failed to clear failed jobs")?;

        let (handle, rx) = JobQueueHandle::new();

        Ok(Self {
            notify_runner,
            runner_waker,
            queue,
            job_queue_rx: rx,
            job_queue_handle: handle,
        })
    }

    /// The queue itself, for jobs whose callers must know they are stored.
    pub fn durable(&self) -> DurableJobQueue {
        DurableJobQueue(Arc::clone(&self.queue))
    }
}

/// The job queue database: a job pushed here is stored before `push` returns, unlike with [`JobQueueHandle`].
#[derive(Clone)]
pub struct DurableJobQueue(DynJobQueue);

impl DurableJobQueue {
    /// Stores `job` to run at `schedule_for`, or at once without it.
    pub async fn push<T: Job + 'static>(&self, job: T, schedule_for: Option<OffsetDateTime>) -> anyhow::Result<()> {
        let job: DynJob = Box::new(job);
        self.0.push_job(&job, schedule_for).await
    }
}

impl JobQueueHandle {
    pub fn new() -> (Self, JobQueueReceiver) {
        let (tx, rx) = mpsc::channel(512);
        let handle = Self {
            sender: tx,
            in_memory_job_dependencies: Arc::default(),
        };
        (handle, rx)
    }

    /// Sets the dependencies the job runner hydrates each job with; once only.
    pub fn set_in_memory_job_dependencies(&self, dependencies: InMemoryJobDependencies) -> anyhow::Result<()> {
        self.in_memory_job_dependencies
            .set(dependencies)
            .map_err(|_| anyhow::anyhow!("the in-memory job dependencies are already set"))
    }

    pub fn in_memory_job_dependencies(&self) -> Option<&InMemoryJobDependencies> {
        self.in_memory_job_dependencies.get()
    }

    pub fn blocking_enqueue<T: Job + 'static>(&self, job: T) -> anyhow::Result<()> {
        self.sender
            .blocking_send(JobMessage {
                job: Box::new(job),
                schedule_for: None,
            })
            .context("couldn't enqueue job")
    }

    pub async fn enqueue<T: Job + 'static>(&self, job: T) -> anyhow::Result<()> {
        self.sender
            .send(JobMessage {
                job: Box::new(job),
                schedule_for: None,
            })
            .await
            .context("couldn't enqueue job")
    }

    pub async fn blocking_schedule<T: Job + 'static>(
        &self,
        job: T,
        schedule_for: OffsetDateTime,
    ) -> anyhow::Result<()> {
        self.sender
            .blocking_send(JobMessage {
                job: Box::new(job),
                schedule_for: Some(schedule_for),
            })
            .context("couldn't enqueue job")
    }

    pub async fn schedule<T: Job + 'static>(&self, job: T, schedule_for: OffsetDateTime) -> anyhow::Result<()> {
        self.sender
            .send(JobMessage {
                job: Box::new(job),
                schedule_for: Some(schedule_for),
            })
            .await
            .context("couldn't enqueue job")
    }
}

impl JobQueueTask {
    pub fn new(ctx: JobQueueCtx) -> Self {
        Self {
            queue: ctx.queue,
            job_queue_rx: ctx.job_queue_rx,
        }
    }
}

#[async_trait]
impl Task for JobQueueTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "job queue";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        job_queue_task(self, shutdown_signal).await
    }
}

#[instrument(skip_all)]
async fn job_queue_task(ctx: JobQueueTask, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
    debug!("Task started");

    let JobQueueTask {
        queue,
        mut job_queue_rx,
    } = ctx;

    loop {
        tokio::select! {
            msg = job_queue_rx.recv() => {
                let Some(msg) = msg else {
                    debug!("All senders are dead");
                    break;
                };

                ChildTask::spawn({
                    let queue = Arc::clone(&queue);

                    async move {
                        for _ in 0..5 {
                            match queue.push_job(&msg.job, msg.schedule_for).await {
                                Ok(()) => break,
                                Err(e) => {
                                    warn!(error = format!("{e:#}"), "Failed to push job");
                                    tokio::time::sleep(Duration::from_secs(20)).await;
                                }
                            }
                        }
                    }
                })
                .detach();
            }
            () = shutdown_signal.wait() => break,
        }
    }

    debug!("Task terminated");

    Ok(())
}

impl JobRunnerTask {
    pub fn new(ctx: &JobQueueCtx) -> Self {
        Self {
            notify_runner: Arc::clone(&ctx.notify_runner),
            runner_waker: RunnerWaker::clone(&ctx.runner_waker),
            queue: Arc::clone(&ctx.queue),
            in_memory_job_dependencies: Arc::clone(&ctx.job_queue_handle.in_memory_job_dependencies),
        }
    }
}

#[async_trait]
impl Task for JobRunnerTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "job queue";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        job_runner_task(self, shutdown_signal).await
    }
}

#[instrument(skip_all)]
async fn job_runner_task(ctx: JobRunnerTask, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
    debug!("Task started");

    let JobRunnerTask {
        notify_runner,
        runner_waker,
        queue,
        in_memory_job_dependencies,
    } = ctx;

    let reader = DgwJobReader {
        in_memory_job_dependencies,
    };

    let spawn = |mut ctx: JobCtx, callback: job_queue::SpawnCallback| {
        tokio::spawn(async move {
            let result = ctx.job.run().await;
            (callback)(result).await;
        });
    };

    let sleep =
        |duration: Duration| (Box::new(tokio::time::sleep(duration)) as Box<dyn Future<Output = ()> + Send>).into();

    let wait_notified = {
        let notify_runner = Arc::clone(&notify_runner);
        move || {
            let notify_runner = Arc::clone(&notify_runner);
            (Box::new(async move { notify_runner.notified().await }) as Box<dyn Future<Output = ()> + Send>).into()
        }
    };

    let wait_notified_timeout = move |timeout: Duration| {
        let notify_runner = Arc::clone(&notify_runner);
        (Box::new(async move {
            tokio::select! {
                () = notify_runner.notified() => {}
                () = tokio::time::sleep(timeout) => {}
            }
        }) as Box<dyn Future<Output = ()> + Send>)
            .into()
    };

    let runner = JobRunner {
        queue,
        reader: &reader,
        spawn: &spawn,
        sleep: &sleep,
        wait_notified: &wait_notified,
        wait_notified_timeout: &wait_notified_timeout,
        waker: runner_waker,
        max_batch_size: 16,
    };

    tokio::select! {
        () = runner.run() => {}
        () = shutdown_signal.wait() => {}
    }

    debug!("Task terminated");

    Ok(())
}

struct DgwJobReader {
    in_memory_job_dependencies: Arc<OnceLock<InMemoryJobDependencies>>,
}

impl DgwJobReader {
    fn hydrate(&self, job: impl UnhydratedJob) -> anyhow::Result<DynJob> {
        let dependencies = self
            .in_memory_job_dependencies
            .get()
            .context("the in-memory job dependencies are not set")?;
        Ok(job.hydrate(dependencies))
    }
}

impl JobReader for DgwJobReader {
    fn read_json(&self, name: &str, json: &str) -> anyhow::Result<DynJob> {
        use crate::api::jrec::DeleteRecordingsJob;
        use crate::recording::RemuxJob;

        match name {
            RemuxJob::NAME => {
                let job: RemuxJob = serde_json::from_str(json).context("failed to deserialize RemuxJob")?;
                Ok(Box::new(job))
            }
            DeleteRecordingsJob::NAME => {
                let job: DeleteRecordingsJob =
                    serde_json::from_str(json).context("failed to deserialize DeleteRecordingsJob")?;
                Ok(Box::new(job))
            }
            TaskJob::<RecordingAiAnalysis>::NAME => self.hydrate(TaskJob::<RecordingAiAnalysis>::read_json(json)?),
            _ => anyhow::bail!("unknown job name: {name}"),
        }
    }
}

/// A job the job queue of tests stored, as the job runner reads it back.
#[cfg(test)]
pub(crate) struct StoredJob {
    pub(crate) name: String,
    pub(crate) json: String,
    pub(crate) schedule_for: Option<OffsetDateTime>,
}

/// The job queue of tests: the queue Gateway runs, in memory, which also hands each job it stores to the test, and
/// refuses every job once closed, as a database that can't be written does.
#[cfg(test)]
pub(crate) struct TestJobQueue {
    inner: job_queue_libsql::LibSqlJobQueue,
    stored: parking_lot::Mutex<std::collections::VecDeque<StoredJob>>,
    closed: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl TestJobQueue {
    pub(crate) async fn new() -> Arc<Self> {
        let conn = libsql::Builder::new_local(":memory:")
            .build()
            .await
            .expect("build database")
            .connect()
            .expect("open database connection");
        let inner = job_queue_libsql::LibSqlJobQueue::builder()
            .runner_waker(RunnerWaker::new(|| {}))
            .conn(conn)
            .build();
        inner.setup().await.expect("queue setup");

        Arc::new(Self {
            inner,
            stored: parking_lot::Mutex::default(),
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Takes the oldest job stored and not taken yet.
    pub(crate) fn take(&self) -> Option<StoredJob> {
        self.stored.lock().pop_front()
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// This queue, as [`JobQueueCtx::durable`] hands out the queue Gateway runs.
    pub(crate) fn durable(self: &Arc<Self>) -> DurableJobQueue {
        DurableJobQueue(Arc::<Self>::clone(self))
    }
}

#[cfg(test)]
#[async_trait]
impl JobQueue for TestJobQueue {
    async fn setup(&self) -> anyhow::Result<()> {
        self.inner.setup().await
    }

    async fn reset_claimed_jobs(&self) -> anyhow::Result<()> {
        self.inner.reset_claimed_jobs().await
    }

    async fn push_job(&self, job: &DynJob, schedule_for: Option<OffsetDateTime>) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.closed.load(std::sync::atomic::Ordering::SeqCst),
            "the job queue is closed"
        );
        self.inner.push_job(job, schedule_for).await?;
        self.stored.lock().push_back(StoredJob {
            name: job.name().to_owned(),
            json: job.write_json()?,
            schedule_for,
        });
        Ok(())
    }

    async fn claim_jobs(&self, reader: &dyn JobReader, number_of_jobs: usize) -> anyhow::Result<Vec<JobCtx>> {
        self.inner.claim_jobs(reader, number_of_jobs).await
    }

    async fn delete_job(&self, job_id: uuid::Uuid) -> anyhow::Result<()> {
        self.inner.delete_job(job_id).await
    }

    async fn fail_job(&self, job_id: uuid::Uuid, schedule_for: OffsetDateTime) -> anyhow::Result<()> {
        self.inner.fail_job(job_id, schedule_for).await
    }

    async fn clear_failed(&self) -> anyhow::Result<()> {
        self.inner.clear_failed().await
    }

    async fn next_scheduled_date(&self) -> anyhow::Result<Option<OffsetDateTime>> {
        self.inner.next_scheduled_date().await
    }
}
