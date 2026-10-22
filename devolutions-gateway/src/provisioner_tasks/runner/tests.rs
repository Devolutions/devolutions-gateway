use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use provisioner_task::ProvisionerTaskState;

use super::*;
use crate::job_queue::{JobMessage, JobQueueReceiver};
use crate::provisioner_tasks::Recoverable;
use crate::token::AccessScope;

const KIND: &str = "test.echo";

/// A value whose attempt waits until it is cancelled.
const HANG: u32 = u32::MAX;

/// A value whose attempt reports progress five times, half a second apart, then succeeds.
const PROGRESS: u32 = u32::MAX - 1;

#[derive(Debug, Serialize, serde::Deserialize)]
struct EchoParams {
    value: u32,
}

/// A task whose attempts return `outcome`, counting its runs and the records it ended.
struct Echo {
    outcome: fn(u32) -> Result<serde_json::Value, AttemptError>,
    progress_timeout: time::Duration,
    runs: Arc<AtomicUsize>,
    ended: Arc<Mutex<Vec<Uuid>>>,
}

#[async_trait]
impl ProvisionerTask for Echo {
    const KIND: &'static str = KIND;

    const START_SCOPE: AccessScope = AccessScope::Wildcard;

    const READ_SCOPE: AccessScope = AccessScope::Wildcard;

    type Params = EchoParams;

    type Output = serde_json::Value;

    fn start_window(&self) -> time::Duration {
        time::Duration::hours(1)
    }

    fn progress_timeout(&self) -> time::Duration {
        self.progress_timeout
    }

    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value {
        json!({ "after": last })
    }

    fn failed_payload(&self, error: &Permanent, last: &serde_json::Value) -> serde_json::Value {
        json!({ "error": error, "last": last })
    }

    async fn run(&self, attempt: &Attempt, params: EchoParams) -> Result<serde_json::Value, AttemptError> {
        self.runs.fetch_add(1, Ordering::SeqCst);

        match params.value {
            HANG => {
                attempt.cancel.cancelled().await;
                Err(AttemptError::Recoverable(Recoverable::Storage))
            }
            PROGRESS => {
                for step in 0..5 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    attempt.report_progress(json!({ "step": step })).await;
                }
                Ok(json!("done"))
            }
            value => (self.outcome)(value),
        }
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()> {
        self.ended.lock().push(record.id);
        Ok(())
    }
}

struct Harness {
    runner: ProvisionerTaskRunner,
    job_queue_rx: JobQueueReceiver,
    runs: Arc<AtomicUsize>,
    ended: Arc<Mutex<Vec<Uuid>>>,
}

impl Harness {
    async fn new(outcome: fn(u32) -> Result<serde_json::Value, AttemptError>) -> Self {
        Self::with_progress_timeout(outcome, time::Duration::hours(1)).await
    }

    async fn with_progress_timeout(
        outcome: fn(u32) -> Result<serde_json::Value, AttemptError>,
        progress_timeout: time::Duration,
    ) -> Self {
        let conn = gateway_db::GatewayDb::open_path(":memory:")
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect");
        let store = Arc::new(
            provisioner_task_libsql::LibSqlProvisionerTaskStore::open(conn)
                .await
                .expect("open task store"),
        );
        let (job_queue, job_queue_rx) = JobQueueHandle::new();
        let runs = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(Mutex::new(Vec::new()));

        let runner = ProvisionerTaskRunner::builder(store, Arc::new(job_queue))
            .register(Echo {
                outcome,
                progress_timeout,
                runs: Arc::clone(&runs),
                ended: Arc::clone(&ended),
            })
            .build();

        Self {
            runner,
            job_queue_rx,
            runs,
            ended,
        }
    }

    async fn create(&self, value: u32) -> Uuid {
        let id = Uuid::new_v4();
        let outcome = self
            .runner
            .create::<Echo>(id, format!("target-{id}"), &EchoParams { value }, |_| Ok(()))
            .await
            .expect("create");
        assert!(matches!(outcome, CreateOutcome::Created(_)), "{outcome:?}");
        id
    }

    fn queued_job(&mut self) -> Box<dyn job_queue::Job> {
        let JobMessage { job, .. } = self.job_queue_rx.try_recv().expect("a queued job");
        job
    }

    async fn task(&self, id: Uuid) -> ProvisionerTaskRecord {
        self.runner
            .get(id, OffsetDateTime::now_utc())
            .await
            .expect("read task")
            .expect("task exists")
    }
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn only_a_new_task_runs_on_created_and_gets_a_job() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = Uuid::new_v4();
    let created = AtomicUsize::new(0);
    let create = || {
        harness
            .runner
            .create::<Echo>(id, "target".to_owned(), &EchoParams { value: 1 }, |_| {
                created.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
    };

    assert!(matches!(create().await.expect("create"), CreateOutcome::Created(_)));
    assert!(matches!(create().await.expect("again"), CreateOutcome::Existing(_)));

    assert_eq!(created.load(Ordering::SeqCst), 1);
    harness.queued_job();
    assert!(harness.job_queue_rx.try_recv().is_err(), "one job only");
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_task_whose_job_cannot_be_queued_fails() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    harness.job_queue_rx.close();
    let id = Uuid::new_v4();

    harness
        .runner
        .create::<Echo>(id, "target".to_owned(), &EchoParams { value: 1 }, |_| Ok(()))
        .await
        .expect_err("the job queue is gone");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload, json!({ "error": { "kind": "notQueued" }, "last": null }));
    assert_eq!(*harness.ended.lock(), [id], "what was set up for the Task is dropped");
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_task_that_cannot_be_prepared_fails_without_a_job() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = Uuid::new_v4();

    harness
        .runner
        .create::<Echo>(id, "target".to_owned(), &EchoParams { value: 1 }, |_| {
            anyhow::bail!("no room for the secret")
        })
        .await
        .expect_err("preparing fails");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "notQueued" }));
    assert!(harness.job_queue_rx.try_recv().is_err(), "no job is queued");
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_superseded_job_runs_nothing_once_the_task_is_resumed() {
    let mut harness = Harness::new(|value| Ok(json!({ "echo": value }))).await;
    let id = harness.create(7).await;
    let mut stale = harness.queued_job();

    harness.runner.resume().await.expect("resume");
    let mut resumed = harness.queued_job();
    assert!(
        harness.job_queue_rx.try_recv().is_err(),
        "the unfinished Task gets one new job"
    );

    stale.run().await.expect("the stale job stops");
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);
    assert_eq!(harness.task(id).await.attempts, 0, "a stale job counts no attempt");
    assert!(harness.ended.lock().is_empty(), "a stale job ends nothing");

    resumed.run().await.expect("the new job runs");
    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded);
    assert_eq!(task.payload, json!({ "echo": 7 }));
    assert_eq!(*harness.ended.lock(), [id]);

    harness.runner.resume().await.expect("resume again");
    assert!(
        harness.job_queue_rx.try_recv().is_err(),
        "a finished Task gets no new job"
    );
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_task_that_cannot_be_queued_again_fails() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    harness.queued_job();
    harness.job_queue_rx.close();

    harness.runner.resume().await.expect("resume");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed, "no job is left to run it");
    assert_eq!(task.payload["error"], json!({ "kind": "notQueued" }));
    assert_eq!(*harness.ended.lock(), [id]);
}

/// A job queue that remembers the jobs it stores, as the job queue database does.
#[derive(Default)]
struct StoredJobs(Mutex<Vec<String>>);

#[async_trait]
impl ProvisionerTaskJobQueue for StoredJobs {
    async fn push(&self, job: ProvisionerTaskJob) -> anyhow::Result<()> {
        self.0.lock().push(job_queue::Job::write_json(&job)?);
        Ok(())
    }

    async fn stored_jobs(&self, name: &str) -> anyhow::Result<Vec<String>> {
        assert_eq!(name, ProvisionerTaskJob::NAME);
        Ok(self.0.lock().clone())
    }
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn resume_queues_only_the_tasks_left_without_a_job() {
    let conn = gateway_db::GatewayDb::open_path(":memory:")
        .await
        .expect("open gateway database")
        .connect()
        .await
        .expect("connect");
    let store = Arc::new(
        provisioner_task_libsql::LibSqlProvisionerTaskStore::open(conn)
            .await
            .expect("open task store"),
    );
    let queue = Arc::new(StoredJobs::default());
    let runner = ProvisionerTaskRunner::builder(store, Arc::clone(&queue) as DynProvisionerTaskJobQueue)
        .register(Echo {
            outcome: |value| Ok(json!(value)),
            progress_timeout: time::Duration::hours(1),
            runs: Arc::default(),
            ended: Arc::default(),
        })
        .build();
    let create = |id: Uuid| runner.create::<Echo>(id, format!("target-{id}"), &EchoParams { value: 1 }, |_| Ok(()));
    let with_job = Uuid::new_v4();
    let without_job = Uuid::new_v4();
    create(with_job).await.expect("create");
    create(without_job).await.expect("create");
    let token_with_job = runner
        .get(with_job, OffsetDateTime::now_utc())
        .await
        .expect("read")
        .expect("record")
        .job_token;

    // The job of the second record is lost, as when Gateway stops right after creating the record.
    queue.0.lock().retain(|json| json.contains(&with_job.to_string()));

    runner.resume().await.expect("resume");

    let stored = queue.0.lock().clone();
    assert_eq!(stored.len(), 2, "one new job, for the record without one: {stored:?}");
    assert!(stored[1].contains(&without_job.to_string()));
    assert_eq!(
        runner
            .get(with_job, OffsetDateTime::now_utc())
            .await
            .expect("read")
            .expect("record")
            .job_token,
        token_with_job,
        "a record with its job keeps it"
    );
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_panicking_attempt_fails_the_task() {
    let mut harness = Harness::new(|_| panic!("the attempt panics")).await;
    let id = harness.create(1).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(
        task.payload,
        json!({ "error": { "kind": "panicked" }, "last": { "after": null } }),
        "the failure keeps what the attempt started with"
    );
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_permanent_failure_fails_the_task_at_once() {
    let mut harness = Harness::new(|_| Err(AttemptError::Permanent(Permanent::KeyLost))).await;
    let id = harness.create(1).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.attempts, 1);
    assert_eq!(task.payload["error"], json!({ "kind": "keyLost" }));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_recoverable_failure_is_retried_up_to_the_last_attempt() {
    let mut harness = Harness::new(|_| Err(AttemptError::Recoverable(Recoverable::AiBusy { status: 429 }))).await;
    let id = harness.create(1).await;
    let mut job = harness.queued_job();

    for attempt in 1..MAX_ATTEMPTS {
        job.run().await.expect_err("the job queue retries");
        assert_eq!(harness.task(id).await.state, ProvisionerTaskState::Running, "{attempt}");
    }
    job.run().await.expect("the last attempt");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.attempts, MAX_ATTEMPTS);
    assert_eq!(
        task.payload["error"],
        json!({ "kind": "attemptsExhausted", "last": { "kind": "aiBusy", "status": 429 } })
    );
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn invalid_parameters_and_unknown_kinds_fail_the_task() {
    let harness = Harness::new(|value| Ok(json!(value))).await;
    let store = harness.runner.store();
    let now = OffsetDateTime::now_utc();

    for (kind, params) in [(KIND, json!({ "value": "not a number" })), ("test.unknown", json!({}))] {
        let id = Uuid::new_v4();
        let job_token = Uuid::new_v4();
        store
            .create(
                NewProvisionerTaskRecord {
                    id,
                    kind: kind.to_owned(),
                    target: id.to_string(),
                    params,
                    deadline_at: now + time::Duration::hours(1),
                    job_token,
                },
                now,
            )
            .await
            .expect("create");

        harness.runner.run_attempt(id, job_token).await.expect("no retry");

        let task = harness.task(id).await;
        assert_eq!(task.state, ProvisionerTaskState::Failed, "{kind}");
        assert_eq!(task.payload["error"], json!({ "kind": "invalidTask" }), "{kind}");
    }

    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);
}

// oracle: intent crates/provisioner-task/INTENT.md §Invariants
#[tokio::test]
async fn an_attempt_without_progress_is_cancelled_at_the_deadline() {
    let mut harness = Harness::with_progress_timeout(|value| Ok(json!(value)), time::Duration::seconds(2)).await;
    let id = harness.create(HANG).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "deadlinePassed" }));
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: intent crates/provisioner-task/INTENT.md §Invariants
#[tokio::test]
async fn progress_keeps_an_attempt_running_past_its_first_deadline() {
    let mut harness = Harness::with_progress_timeout(|value| Ok(json!(value)), time::Duration::seconds(2)).await;
    let id = harness.create(PROGRESS).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded, "{:?}", task.payload);
    assert_eq!(task.payload, json!("done"));
}

// oracle: property round-trip
#[tokio::test]
async fn the_job_is_read_back_from_its_json() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let job = harness.queued_job();

    let json = job.write_json().expect("job JSON");
    let read = ProvisionerTaskJob::read_json(&json, harness.runner.clone()).expect("valid job");

    assert_eq!(read.task_id, id);
    assert_eq!(read.job_token, harness.task(id).await.job_token);
    assert_eq!(job.name(), ProvisionerTaskJob::NAME);
}
