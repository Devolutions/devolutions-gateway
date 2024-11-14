#[macro_use]
extern crate tracing;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

pub type DynJob = Box<dyn Job>;

pub type DynJobQueue = Arc<dyn JobQueue>;

#[async_trait]
pub trait Job: Send + Sync {
    fn name(&self) -> &str;

    fn write_json(&self) -> anyhow::Result<String>;

    /// Run the associated job
    ///
    /// You should assume that the execution could be stopped at any point and write cancel-safe code.
    async fn run(&mut self) -> anyhow::Result<()>;
}

pub trait JobReader: Send + Sync {
    fn read_json(&self, name: &str, json: &str) -> anyhow::Result<DynJob>;
}

#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Performs migrations as required
    ///
    /// This function should be called first, before using any of the other functions.
    async fn migrate(&self) -> anyhow::Result<()>;

    /// Resets the status for the jobs claimed
    ///
    /// Uses this at startup to re-enqueue jobs that didn't run to completion.
    async fn reset_claimed_jobs(&self) -> anyhow::Result<()>;

    /// Pushes a new job into the queue
    ///
    /// This function should ideally call `RunnerWaker::wake()` once the job is enqueued.
    async fn push_job(&self, job: &DynJob) -> anyhow::Result<()>;

    /// Fetches at most `number_of_jobs` from the queue
    async fn claim_jobs(&self, reader: &dyn JobReader, number_of_jobs: usize) -> anyhow::Result<Vec<JobCtx>>;

    /// Removes a job from the queue
    async fn delete_job(&self, job_id: Uuid) -> anyhow::Result<()>;

    /// Marks a job as failed
    ///
    /// Failed jobs are re-queued to be tried again later.
    async fn fail_job(&self, job_id: Uuid) -> anyhow::Result<()>;

    /// Removes jobs which can't be retried
    async fn clear_failed(&self) -> anyhow::Result<()>;
}

pub struct JobCtx {
    pub id: Uuid,
    pub job: DynJob,
}

#[derive(Clone)]
pub struct RunnerWaker(Arc<dyn Fn() + Send + Sync>);

impl RunnerWaker {
    pub fn new<F: Fn() + Send + Sync + 'static>(f: F) -> Self {
        Self(Arc::new(f))
    }

    pub fn wake(&self) {
        (self.0)()
    }
}

pub type SpawnCallback = Box<dyn FnOnce(anyhow::Result<()>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

pub type DynFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub struct JobRunner<'a> {
    pub queue: DynJobQueue,
    pub reader: &'a dyn JobReader,
    pub spawn: &'a (dyn Fn(JobCtx, SpawnCallback) + Sync),
    pub sleep: &'a (dyn Fn(std::time::Duration) -> DynFuture + Sync),
    pub wait_notified: &'a (dyn Fn() -> DynFuture + Sync),
    pub waker: RunnerWaker,
    pub max_batch_size: usize,
}

impl JobRunner<'_> {
    pub async fn run(self) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        const MINIMUM_WAIT_DURATION: Duration = Duration::from_millis(200);

        let Self {
            queue,
            reader,
            spawn,
            sleep,
            waker,
            wait_notified,
            max_batch_size,
        } = self;

        let running_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

        loop {
            let batch_size = max_batch_size - running_count.load(Ordering::SeqCst);

            let jobs = match queue.claim_jobs(reader, batch_size).await {
                Ok(jobs) => jobs,
                Err(e) => {
                    error!(error = format!("{e:#}"), "Failed to pull jobs");
                    (sleep)(Duration::from_secs(10)).await;
                    continue;
                }
            };

            let number_of_jobs = jobs.len();
            if number_of_jobs > 0 {
                trace!(number_of_jobs, "Fetched jobs");
            }

            for job in jobs {
                let job_id = job.id;

                let callback = Box::new({
                    let queue = Arc::clone(&queue);
                    let running_count = Arc::clone(&running_count);
                    let waker = waker.clone();

                    move |result: anyhow::Result<()>| {
                        let fut = async move {
                            match result {
                                Ok(()) => {
                                    if let Err(e) = queue.delete_job(job_id).await {
                                        error!(error = format!("{e:#}"), "Failed to delete job");
                                    }
                                }
                                Err(e) => {
                                    warn!(error = format!("{e:#}"), %job_id, "Job failed");

                                    if let Err(e) = queue.fail_job(job_id).await {
                                        error!(error = format!("{e:#}"), "Failed to mark job as failed")
                                    }
                                }
                            }

                            running_count.fetch_sub(1, Ordering::SeqCst);
                            waker.wake();
                        };

                        (Box::new(fut) as Box<dyn Future<Output = ()> + Send>).into()
                    }
                });

                (spawn)(job, callback);

                running_count.fetch_add(1, Ordering::SeqCst);
            }

            // Wait for something to happen.
            // This could be a notification that a new job has been pushed, or that a running job is terminated.
            let before_wait = Instant::now();
            (wait_notified)().await;
            let elapsed = before_wait.elapsed();

            // Make sure we wait a little bit to avoid overloading the database.
            if elapsed < MINIMUM_WAIT_DURATION {
                let sleep_duration = MINIMUM_WAIT_DURATION - elapsed;
                (sleep)(sleep_duration).await;
            }
        }
    }
}
