use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use job_queue::{DynJob, Job, JobCtx, JobQueue, JobQueueExt, JobReader, RunnerWaker, ScheduleFor, SpawnCallback};
use job_queue_libsql::{libsql, LibSqlJobQueue}; // assume your modules
use time::OffsetDateTime;

// A simple Job implementation.
// We just print a message and then sleep.
#[derive(Debug)]
struct ExampleJob {
    message: String,
}

#[async_trait]
impl Job for ExampleJob {
    fn name(&self) -> &str {
        "example-job"
    }

    fn write_json(&self) -> anyhow::Result<String> {
        // You can serialize your fields here.
        // In real-world usage, use serde_json or similar.
        let content = format!("{{ \"message\": \"{}\" }}", self.message);
        Ok(content)
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        println!("Running ExampleJob with message: {}", self.message);
        // Simulate some long work.
        tokio::time::sleep(Duration::from_secs(2)).await;
        println!("ExampleJob finished. : {}", self.message);
        Ok(())
    }
}

// A very simple JobReader that always returns an ExampleJob, ignoring JSON.
// In a real application, you would parse the JSON string into the correct Job type.
struct ExampleReader;

impl ExampleReader {
    fn new() -> Self {
        ExampleReader
    }
}

#[async_trait]
impl JobReader for ExampleReader {
    fn read_json(&self, _name: &str, json_str: &str) -> anyhow::Result<DynJob> {
        let value: serde_json::Value = serde_json::from_str(json_str)?;
        let message = value["message"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'message' field"))?;

        let job = ExampleJob {
            message: message.to_owned(),
        };

        // Return the job as a boxed trait object.
        Ok(Box::new(job) as DynJob)
    }
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::SubscriberBuilder::default()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(true)
        .init();

    // 1) Build an in-memory libSQL database.
    let db = libsql::Builder::new_local(":memory:")
        .build()
        .await
        .context("failed to build libSQL in-memory db")?;

    // 2) Get a connection.
    let conn = db.connect()?;

    // 3) Build our job queue.
    let runner_waker = RunnerWaker::new(|| {
        // This callback is triggered whenever a new job is queued, etc.
        // For a real application, you might notify a condition variable or something.
        // Here, we do nothing.
    });

    let queue = Arc::new(
        LibSqlJobQueue::builder()
            .conn(conn)
            .runner_waker(runner_waker.clone())
            .build(),
    );

    // 4) Prepare the queue (apply PRAGMA, migrate, etc.)
    queue.setup().await?;

    // 5) Reset any claimed jobs from previous runs.
    //    If you often restart your app, call this once at startup.
    queue.reset_claimed_jobs().await?;

    // 6) Define a function that spawns job execution.
    //    The JobRunner requires a closure for spawning tasks.
    let spawn = move |mut job_ctx: JobCtx, callback: SpawnCallback| {
        // Use tokio's task system.
        tokio::spawn(async move {
            // Actually run the job.
            let result = job_ctx.job.run().await;
            // Then call the callback so the queue can mark success/failure.
            callback(result).await;
        });
    };

    // 7) Define our sleeping and notification logic.
    //    The runner needs to know how to wait.

    let sleep = move |dur: Duration| {
        // Return a pinned future that sleeps.
        Box::pin(tokio::time::sleep(dur)) as Pin<Box<dyn Future<Output = ()> + Send>>
    };

    // We'll keep it simple and create a small channel for wake notifications.
    use tokio::sync::Notify;
    let notify = Arc::new(Notify::new());

    let wait_notified = {
        let notify = Arc::clone(&notify);
        move || {
            let notify = Arc::clone(&notify);
            Box::pin(async move {
                notify.notified().await;
            }) as Pin<Box<dyn Future<Output = ()> + Send>>
        }
    };

    let wait_notified_timeout = {
        let notify = notify.clone();
        move |dur: Duration| {
            let notify = notify.clone();
            Box::pin(async move {
                tokio::select! {
                    _ = tokio::time::sleep(dur) => {},
                    _ = notify.notified() => {},
                }
            }) as Pin<Box<dyn Future<Output = ()> + Send>>
        }
    };

    // 8) Create the runner.
    //    We'll run the job runner in the background so we can demonstrate queue usage.
    let reader = ExampleReader::new();

    let runner = job_queue::JobRunner {
        queue: queue.clone(),
        reader: &reader,
        spawn: &spawn,
        sleep: &sleep,
        wait_notified: &wait_notified,
        wait_notified_timeout: &wait_notified_timeout,
        waker: runner_waker.clone(),
        max_batch_size: 5,
    };

    {
        let job1 = Box::new(ExampleJob {
            message: "First queued job".to_owned(),
        }) as DynJob;
        queue.push_job(&job1, ScheduleFor::Now).await?;
    }

    {
        // We'll schedule one a bit into the future.
        let job2 = Box::new(ExampleJob {
            message: "Scheduled job in 10 seconds".to_owned(),
        }) as DynJob;
        let future_time = OffsetDateTime::now_utc() + time::Duration::seconds(10);
        queue.push_job(&job2, ScheduleFor::Once(future_time)).await?;
    }

    {
        // We'll queue up a cron job that runs every 5 seconds.
        let cron_schedule = "0/3 * * * * *".parse()?;
        let job3 = Box::new(ExampleJob {
            message: "Recurring cron job every 3 seconds".to_owned(),
        }) as DynJob;
        queue.push_job(&job3, ScheduleFor::Cron(cron_schedule)).await?;
    }

    // 11) We'll wait for a while to see the runner do its thing, then exit.
    //     In a real app, you'd probably keep running.
    println!("Main: waiting 30 seconds before exit...");
    tokio::select! {
        () = runner.run() => {}
        () = tokio::time::sleep(Duration::from_secs(30)) => {}
    }

    println!("Main: done.");

    Ok(())
}
