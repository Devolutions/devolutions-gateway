use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, path::Path};

use anyhow::Context as _;
use axum::async_trait;
use devolutions_gateway_task::{ChildTask, ShutdownSignal, Task};
use job_queue::{DynJobQueue, Job, JobCtx, JobQueue, JobReader, JobRunner, RunnerWaker};
use job_queue_libsql::libsql;
use time::OffsetDateTime;
use tokio::sync::{mpsc, Notify};

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
pub struct JobQueueHandle(mpsc::Sender<JobMessage>);

pub type JobQueueReceiver = mpsc::Receiver<JobMessage>;

pub struct JobQueueTask {
    queue: DynJobQueue,
    job_queue_rx: JobQueueReceiver,
}

pub struct JobRunnerTask {
    notify_runner: Arc<Notify>,
    runner_waker: RunnerWaker,
    queue: DynJobQueue,
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

        queue.setup().await.context("database migration")?;

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
}

impl JobQueueHandle {
    pub fn new() -> (Self, JobQueueReceiver) {
        let (tx, rx) = mpsc::channel(512);
        (Self(tx), rx)
    }

    pub fn blocking_enqueue<T: Job + 'static>(&self, job: T) -> anyhow::Result<()> {
        self.0
            .blocking_send(JobMessage {
                job: Box::new(job),
                schedule_for: None,
            })
            .context("couldn't enqueue job")
    }

    pub async fn enqueue<T: Job + 'static>(&self, job: T) -> anyhow::Result<()> {
        self.0
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
        self.0
            .blocking_send(JobMessage {
                job: Box::new(job),
                schedule_for: Some(schedule_for),
            })
            .context("couldn't enqueue job")
    }

    pub async fn schedule<T: Job + 'static>(&self, job: T, schedule_for: OffsetDateTime) -> anyhow::Result<()> {
        self.0
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
    } = ctx;

    let reader = DgwJobReader;

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

struct DgwJobReader;

impl JobReader for DgwJobReader {
    fn read_json(&self, name: &str, json: &str) -> anyhow::Result<job_queue::DynJob> {
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
            _ => anyhow::bail!("unknown job name: {name}"),
        }
    }
}
