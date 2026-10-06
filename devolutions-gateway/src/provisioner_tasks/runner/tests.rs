use std::sync::atomic::{AtomicUsize, Ordering};

use job_queue::Job as _;
use parking_lot::Mutex;
use provisioner_task::ProvisionerTaskState;

use super::*;
use crate::job_queue::{JobMessage, JobQueueReceiver};
use crate::token::AccessScope;

const KIND: &str = "test.echo";

#[derive(Debug, Serialize, serde::Deserialize)]
struct EchoParams {
    value: u32,
}

/// A task whose attempts return `outcome`, counting its runs and the records it ended.
struct Echo {
    outcome: fn(u32) -> Result<serde_json::Value, AttemptError>,
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

    fn deadline(&self) -> time::Duration {
        time::Duration::hours(1)
    }

    fn attempt_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    async fn run(&self, _attempt: &Attempt, params: EchoParams) -> Result<serde_json::Value, AttemptError> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        (self.outcome)(params.value)
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) {
        self.ended.lock().push(record.id);
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

        let runner = ProvisionerTaskRunner::builder(store, job_queue)
            .register(Echo {
                outcome,
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
    assert_eq!(task.payload["reason"], "not queued");
    assert_eq!(*harness.ended.lock(), [id], "what was set up for the Task is dropped");
}

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
    assert_eq!(task.payload["reason"], "not queued");
    assert!(harness.job_queue_rx.try_recv().is_err(), "no job is queued");
    assert_eq!(*harness.ended.lock(), [id]);
}

#[tokio::test]
async fn a_superseded_job_runs_nothing_once_the_task_is_resumed() {
    let mut harness = Harness::new(|value| Ok(json!({ "echo": value }))).await;
    let id = harness.create(7).await;
    let mut stale = harness.queued_job();

    let resumed = Mutex::new(Vec::new());
    harness
        .runner
        .resume(|job| {
            resumed.lock().push(job);
            async { Ok(()) }
        })
        .await
        .expect("resume");
    let mut resumed = resumed.into_inner();
    assert_eq!(resumed.len(), 1, "the unfinished Task gets a new job");

    stale.run().await.expect("the stale job stops");
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);
    assert_eq!(harness.task(id).await.attempts, 0, "a stale job counts no attempt");
    assert!(harness.ended.lock().is_empty(), "a stale job ends nothing");

    resumed[0].run().await.expect("the new job runs");
    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded);
    assert_eq!(task.payload, json!({ "echo": 7 }));
    assert_eq!(*harness.ended.lock(), [id]);

    let queued_again = AtomicUsize::new(0);
    harness
        .runner
        .resume(|_| {
            queued_again.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        })
        .await
        .expect("resume again");
    assert_eq!(
        queued_again.load(Ordering::SeqCst),
        0,
        "a finished Task gets no new job"
    );
}

#[tokio::test]
async fn a_panicking_attempt_fails_the_task() {
    let mut harness = Harness::new(|_| panic!("the attempt panics")).await;
    let id = harness.create(1).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(
        task.payload,
        json!({ "reason": "permanent error", "details": "the attempt panicked", "attempts": 1 })
    );
    assert_eq!(*harness.ended.lock(), [id]);
}

#[tokio::test]
async fn a_failure_keeps_the_reason_of_its_kind() {
    let mut harness = Harness::new(|_| {
        Err(AttemptError::Failed {
            reason: "key lost",
            details: "gone".to_owned(),
        })
    })
    .await;
    let id = harness.create(1).await;

    harness.queued_job().run().await.expect("no retry");

    assert_eq!(
        harness.task(id).await.payload,
        json!({ "reason": "key lost", "details": "gone", "attempts": 1 })
    );
}

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
        assert_eq!(task.payload["reason"], "invalid task", "{kind}");
    }

    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_job_is_read_back_from_its_json() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let job = harness.queued_job();

    let json = job.write_json().expect("job JSON");
    let read = ProvisionerTaskJob::read_json(&json, harness.runner.clone()).expect("valid job");

    assert_eq!(read.task_id, id);
    assert_eq!(Some(read.job_token), harness.task(id).await.job_token);
    assert_eq!(job.name(), ProvisionerTaskJob::NAME);
}
