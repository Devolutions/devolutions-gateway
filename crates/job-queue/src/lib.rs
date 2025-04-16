#[macro_use]
extern crate tracing;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
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

pub enum ScheduleFor {
    Now,
    Once(OffsetDateTime),
    Cron(cron_clock::Schedule),
}

#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Performs initial setup required before actually using the queue
    ///
    /// This function should be called first, before using any of the other functions.
    async fn setup(&self) -> anyhow::Result<()>;

    /// Resets the status for the jobs claimed
    ///
    /// Uses this at startup to re-enqueue jobs that didn't run to completion.
    async fn reset_claimed_jobs(&self) -> anyhow::Result<()>;

    /// Pushes a new job into the queue
    ///
    /// This function should ideally call `RunnerWaker::wake()` once the job is enqueued.
    async fn push_job_raw(&self, job_name: &str, job_def: String, schedule_for: ScheduleFor) -> anyhow::Result<()>;

    /// Fetches at most `number_of_jobs` from the queue
    async fn claim_jobs(&self, reader: &dyn JobReader, number_of_jobs: usize) -> anyhow::Result<Vec<JobCtx>>;

    /// Removes a job from the queue
    async fn delete_job(&self, job_id: Uuid) -> anyhow::Result<()>;

    /// Marks a job as failed
    ///
    /// Failed jobs are re-queued to be tried again later.
    async fn fail_job(&self, job_id: Uuid, schedule_for: OffsetDateTime) -> anyhow::Result<()>;

    /// Removes jobs which can't be retried
    async fn clear_failed(&self) -> anyhow::Result<()>;

    /// Retrieves the closest future scheduled date
    async fn next_scheduled_date(&self) -> anyhow::Result<Option<OffsetDateTime>>;

    /// Reschedule the cron job
    async fn schedule_next_cron_job(&self, id: Uuid) -> anyhow::Result<u64>;

    /// Retrive cron jobs, used for re-scheduling or deleting
    async fn get_cron_jobs(&self) -> anyhow::Result<Vec<CronJobCompact>>;
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CronJobCompact {
    pub id: Uuid,
    pub name: String,
    pub cron: String,
}

#[async_trait]
pub trait JobQueueExt {
    async fn push_job(&self, job: &DynJob, schedule_for: ScheduleFor) -> anyhow::Result<()>;
}

#[async_trait]
impl<T: JobQueue + ?Sized> JobQueueExt for T {
    async fn push_job(&self, job: &DynJob, schedule_for: ScheduleFor) -> anyhow::Result<()> {
        let job_name = job.name().to_string();
        let job_def = job.write_json()?;
        self.push_job_raw(&job_name, job_def, schedule_for).await
    }
}

pub struct JobCtx {
    pub id: Uuid,
    pub failed_attempts: u32,
    pub job: DynJob,
    pub cron: Option<cron_clock::Schedule>,
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
    pub wait_notified_timeout: &'a (dyn Fn(std::time::Duration) -> DynFuture + Sync),
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
            wait_notified_timeout,
            max_batch_size,
        } = self;

        let running_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

        loop {
            let batch_size = max_batch_size - running_count.load(Ordering::SeqCst);

            let jobs = match queue.claim_jobs(reader, batch_size).await {
                Ok(jobs) => jobs,
                Err(e) => {
                    error!(error = format!("{e:#}"), "Failed to pull jobs");
                    (sleep)(Duration::from_secs(30)).await;
                    continue;
                }
            };

            trace!(number_of_jobs = jobs.len(), "Fetched jobs");

            for job in jobs {
                let job_id = job.id;
                let failed_attempts = job.failed_attempts;
                let job_name = job.job.name().to_string();

                if let Some(cron) = &job.cron {
                    let now = OffsetDateTime::now_utc();
                    debug!(
                        job_id = %job_id,
                        job_name = %job_name,
                        cron = %cron,
                        ?now,
                        "Re scheduling cron job"
                    );
                    let _ = queue.schedule_next_cron_job(job_id.clone()).await.inspect_err(|e| {
                        error!(error = format!("{e:#}"), "Failed to schedule cron job");
                    });
                }

                let callback = Box::new({
                    let queue = Arc::clone(&queue);
                    let running_count = Arc::clone(&running_count);
                    let waker = waker.clone();
                    let cron = job.cron.clone();
                    move |result: anyhow::Result<()>| {
                        let fut = async move {
                            match (result, cron) {
                                // Regular run once job
                                (Ok(()), None) => {
                                    if let Err(e) = queue.delete_job(job_id).await {
                                        error!(error = format!("{e:#}"), "Failed to delete job");
                                    }
                                }
                                // Regular run once job that failed
                                (Err(e), None) => {
                                    warn!(error = format!("{e:#}"), %job_id, "Job failed");

                                    let schedule_for =
                                        OffsetDateTime::now_utc() + (1 << failed_attempts) * Duration::from_secs(30);

                                    if let Err(e) = queue.fail_job(job_id, schedule_for).await {
                                        error!(error = format!("{e:#}"), "Failed to mark job as failed")
                                    }
                                }
                                // Cron job that failed, delete anyway, we scheduled a new one
                                (Err(e), Some(_)) => {
                                    error!(error = format!("{e:#}"), "Failed to delete job");
                                }
                                (Ok(_), Some(_)) => {
                                    // Cron job that succeeded, we don't need to do anything
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

            let next_scheduled = if running_count.load(Ordering::SeqCst) < max_batch_size {
                queue
                    .next_scheduled_date()
                    .await
                    .ok()
                    .flatten()
                    .map(|date| date.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp())
                    .inspect(|next_scheduled| trace!("Next task in {next_scheduled} seconds"))
            } else {
                None
            };

            let before_wait = Instant::now();

            // Wait for something to happen.
            // This could be a notification that a new job has been pushed, or that a running job is terminated.
            if let Some(timeout) = next_scheduled {
                // If the next task was scheduled in < 0 seconds, skip the wait step.
                // This happens because there is a delay between the moment the jobs to run are claimed, and the moment
                // we check for the next closest scheduled job.
                if let Ok(timeout) = u64::try_from(timeout) {
                    (wait_notified_timeout)(Duration::from_secs(timeout)).await;
                }
            } else {
                (wait_notified)().await;
            }

            let elapsed = before_wait.elapsed();

            // Make sure we wait a little bit to avoid overloading the database.
            if elapsed < MINIMUM_WAIT_DURATION {
                let sleep_duration = MINIMUM_WAIT_DURATION - elapsed;
                (sleep)(sleep_duration).await;
            }
        }
    }
}
