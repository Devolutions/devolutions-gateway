use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use devolutions_gateway_task::ShutdownHandle;
use job_queue::Job as _;
use parking_lot::Mutex;
use provisioner_task::{CreateOutcome, DynProvisionerTaskStore, NewProvisionerTaskRecord, ProvisionerTaskState};
use serde_json::json;
use uuid::Uuid;

use super::*;
use crate::job_queue::{StoredJob, TestJobQueue};

const KIND: &str = "test.echo";

/// A value whose attempt waits until it is cancelled.
const HANG: u32 = u32::MAX;

/// A value whose attempt reports progress five times, half a second apart, then succeeds.
const PROGRESS: u32 = u32::MAX - 1;

/// Why an Echo attempt fails for good.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum EchoFailure {
    /// What the attempt needed is gone.
    Gone,
}

/// Why an Echo attempt fails for now.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum EchoRecoverable {
    Busy,
}

type EchoError = AttemptError<EchoFailure, EchoRecoverable>;

#[derive(Debug, Serialize, serde::Deserialize)]
struct EchoParams {
    value: u32,
}

/// A task whose attempts return `outcome`, counting its runs and the records it ended.
struct Echo {
    outcome: fn(u32) -> Result<serde_json::Value, EchoError>,
    progress_timeout: time::Duration,
    runs: Arc<AtomicUsize>,
    ended: Arc<Mutex<Vec<Uuid>>>,
    /// Ends that fail before one succeeds.
    end_failures: Arc<AtomicUsize>,
    /// Publications that fail before one succeeds.
    publish_failures: Arc<AtomicUsize>,
    /// The records whose output was published.
    published: Arc<Mutex<Vec<Uuid>>>,
}

#[async_trait]
impl ProvisionerTask for Echo {
    const KIND: &'static str = KIND;

    const START_WINDOW: time::Duration = time::Duration::hours(1);

    type Params = EchoParams;

    type Output = serde_json::Value;

    type Failure = EchoFailure;

    type Recoverable = EchoRecoverable;

    fn progress_timeout(&self) -> time::Duration {
        self.progress_timeout
    }

    fn retry_delay(&self, _: u32) -> time::Duration {
        time::Duration::ZERO
    }

    fn starting_payload(&self, last: &serde_json::Value) -> serde_json::Value {
        json!({ "after": last })
    }

    fn failed_payload(
        &self,
        error: &Permanent<EchoFailure, EchoRecoverable>,
        last: &serde_json::Value,
    ) -> serde_json::Value {
        json!({ "error": error, "last": last })
    }

    async fn run(&self, attempt: &Attempt, params: EchoParams) -> Result<serde_json::Value, EchoError> {
        self.runs.fetch_add(1, Ordering::SeqCst);

        match params.value {
            HANG => {
                attempt.cancel.cancelled().await;
                Err(AttemptError::Recoverable(EchoRecoverable::Busy))
            }
            PROGRESS => {
                // 4 s of work outlasts the first deadline, 2 to 3 s away, so only the progress keeps the attempt running.
                for step in 0..8 {
                    tokio::select! {
                        () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                        () = attempt.cancel.cancelled() => return Err(AttemptError::Recoverable(EchoRecoverable::Busy)),
                    }
                    attempt.report_progress(json!({ "step": step })).await;
                }
                Ok(json!("done"))
            }
            value => (self.outcome)(value),
        }
    }

    async fn publish(&self, record: &ProvisionerTaskRecord, _: &serde_json::Value) -> anyhow::Result<()> {
        if self
            .publish_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
            .is_ok()
        {
            anyhow::bail!("the publication failed");
        }

        self.published.lock().push(record.id);
        Ok(())
    }

    async fn on_end(&self, record: &ProvisionerTaskRecord) -> anyhow::Result<()> {
        if self
            .end_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
            .is_ok()
        {
            anyhow::bail!("the end failed");
        }

        self.ended.lock().push(record.id);
        Ok(())
    }
}

struct Harness {
    outcome: fn(u32) -> Result<serde_json::Value, EchoError>,
    progress_timeout: time::Duration,
    store: DynProvisionerTaskStore,
    job_queue: Arc<TestJobQueue>,
    tasks: ProvisionerTaskHandle,
    /// Keeps the provisioner task service running.
    _service_shutdown: ShutdownHandle,
    runs: Arc<AtomicUsize>,
    ended: Arc<Mutex<Vec<Uuid>>>,
    end_failures: Arc<AtomicUsize>,
    publish_failures: Arc<AtomicUsize>,
    published: Arc<Mutex<Vec<Uuid>>>,
}

impl Harness {
    async fn new(outcome: fn(u32) -> Result<serde_json::Value, EchoError>) -> Self {
        Self::with_progress_timeout(outcome, time::Duration::hours(1)).await
    }

    async fn with_progress_timeout(
        outcome: fn(u32) -> Result<serde_json::Value, EchoError>,
        progress_timeout: time::Duration,
    ) -> Self {
        let conn = gateway_db::GatewayDb::open_path(":memory:")
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect");
        let store: DynProvisionerTaskStore = Arc::new(
            provisioner_task_libsql::LibSqlProvisionerTaskStore::open(conn)
                .await
                .expect("open task store"),
        );
        let job_queue = TestJobQueue::new().await;
        let (tasks, rx) = provisioner_task_channel();
        let (service_shutdown, shutdown_signal) = ShutdownHandle::new();
        let service = ProvisionerTaskService::new(Arc::clone(&store), Arc::<TestJobQueue>::clone(&job_queue), rx);
        tokio::spawn(devolutions_gateway_task::Task::run(service, shutdown_signal));
        let runs = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(Mutex::new(Vec::new()));
        let end_failures = Arc::new(AtomicUsize::new(0));
        let publish_failures = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(Mutex::new(Vec::new()));

        Self {
            outcome,
            progress_timeout,
            store,
            job_queue,
            tasks,
            _service_shutdown: service_shutdown,
            runs,
            ended,
            end_failures,
            publish_failures,
            published,
        }
    }

    /// The task of this harness: every one shares its counters.
    fn echo(&self) -> Echo {
        Echo {
            outcome: self.outcome,
            progress_timeout: self.progress_timeout,
            runs: Arc::clone(&self.runs),
            ended: Arc::clone(&self.ended),
            end_failures: Arc::clone(&self.end_failures),
            publish_failures: Arc::clone(&self.publish_failures),
            published: Arc::clone(&self.published),
        }
    }

    async fn create(&self, value: u32) -> Uuid {
        let id = Uuid::new_v4();
        let outcome = self
            .create_task(id, format!("target-{id}"), &EchoParams { value }, |_| Ok(()))
            .await
            .expect("create");
        assert!(matches!(outcome, CreateOutcome::Created(_)), "{outcome:?}");
        id
    }

    async fn create_task(
        &self,
        id: Uuid,
        target: String,
        params: &EchoParams,
        on_created: impl FnOnce(&NewProvisionerTaskRecord) -> anyhow::Result<()> + Send + 'static,
    ) -> anyhow::Result<CreateOutcome> {
        self.tasks.create(self.echo(), id, target, params, on_created).await
    }

    /// Records a Task directly, with the job token `job_token` and no job.
    async fn record_task(&self, id: Uuid, params: serde_json::Value, job_token: Uuid) {
        let now = OffsetDateTime::now_utc();
        self.store
            .create(
                NewProvisionerTaskRecord {
                    id,
                    kind: KIND.to_owned(),
                    target: id.to_string(),
                    params,
                    deadline_at: now + time::Duration::hours(1),
                    job_token,
                },
                now,
                Box::pin(async { Ok(()) }),
            )
            .await
            .expect("create");
    }

    /// The job of Task `id` with the job token `job_token`, as the job runner reads it.
    fn job(&self, id: Uuid, job_token: Uuid) -> TaskJob<Echo> {
        let json = json!({ "taskId": id, "jobToken": job_token }).to_string();
        TaskJob::read_json(&json, self.echo(), Arc::clone(&self.store)).expect("valid job")
    }

    /// Takes the oldest queued job, read back as the job runner reads it.
    fn queued_job(&mut self) -> Box<dyn job_queue::Job> {
        let StoredJob { name, json, .. } = self.job_queue.take().expect("a queued job");
        assert_eq!(name, KIND);
        Box::new(TaskJob::read_json(&json, self.echo(), Arc::clone(&self.store)).expect("valid job"))
    }

    async fn task(&self, id: Uuid) -> ProvisionerTaskRecord {
        self.store
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
    let created = Arc::new(AtomicUsize::new(0));
    let create = || {
        let created = Arc::clone(&created);
        harness.create_task(id, "target".to_owned(), &EchoParams { value: 1 }, move |_| {
            created.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    };

    assert!(matches!(create().await.expect("create"), CreateOutcome::Created(_)));
    assert!(matches!(create().await.expect("again"), CreateOutcome::Existing(_)));

    assert_eq!(created.load(Ordering::SeqCst), 1);
    harness.queued_job();
    assert!(harness.job_queue.take().is_none(), "one job only");
}

// oracle: mutant the job is queued before the Task is prepared, so a Task that cannot be prepared still gets a job
#[tokio::test]
async fn a_task_that_cannot_be_prepared_gets_no_job() {
    let harness = Harness::new(|value| Ok(json!(value))).await;
    let id = Uuid::new_v4();

    harness
        .create_task(id, "target".to_owned(), &EchoParams { value: 1 }, |_| {
            anyhow::bail!("no room for the secret")
        })
        .await
        .expect_err("preparing fails");

    assert!(harness.job_queue.take().is_none(), "no job is queued");
    assert!(
        harness
            .store
            .get(id, OffsetDateTime::now_utc())
            .await
            .expect("read task")
            .is_none(),
        "no Task is recorded"
    );
}

// oracle: mutant a job claimed before its Task is committed is dropped as done, and the Task never runs
#[tokio::test]
async fn a_job_whose_task_is_not_recorded_yet_is_run_again_later() {
    let harness = Harness::new(|value| Ok(json!(value))).await;
    let id = Uuid::new_v4();
    let job_token = Uuid::new_v4();
    let mut job = harness.job(id, job_token);

    job.run().await.expect_err("the job queue runs the job again");
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);

    harness.record_task(id, json!({ "value": 1 }), job_token).await;
    job.run().await.expect("the Task is recorded now");

    assert_eq!(harness.task(id).await.state, ProvisionerTaskState::Succeeded);
    assert_eq!(harness.runs.load(Ordering::SeqCst), 1);
}

// oracle: mutant the job stored for a Task that was never committed runs the Task recorded since under the same ID
#[tokio::test]
async fn only_the_job_recorded_with_the_task_runs_it() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let mut other_job = harness.job(id, Uuid::new_v4());

    other_job.run().await.expect("the other job is done for good");
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);
    assert_eq!(harness.task(id).await.state, ProvisionerTaskState::Queued);

    harness.queued_job().run().await.expect("the job of the Task runs it");
    assert_eq!(harness.task(id).await.state, ProvisionerTaskState::Succeeded);
    assert_eq!(harness.runs.load(Ordering::SeqCst), 1);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_permanent_failure_fails_the_task_at_once() {
    let mut harness = Harness::new(|_| Err(AttemptError::of_kind(EchoFailure::Gone))).await;
    let id = harness.create(1).await;

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.attempts, 1);
    assert_eq!(task.payload["error"], json!({ "kind": "gone" }));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn a_recoverable_failure_is_retried_up_to_the_last_attempt() {
    let mut harness = Harness::new(|_| Err(AttemptError::Recoverable(EchoRecoverable::Busy))).await;
    let id = harness.create(1).await;
    harness
        .queued_job()
        .run()
        .await
        .expect("the job runs every attempt itself");
    assert!(harness.job_queue.take().is_none(), "no other job is queued");
    assert_eq!(
        harness.runs.load(Ordering::SeqCst),
        usize::try_from(MAX_ATTEMPTS).expect("a few attempts")
    );

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.attempts, MAX_ATTEMPTS);
    assert_eq!(
        task.payload["error"],
        json!({ "kind": "attemptsExhausted", "last": { "kind": "busy" } })
    );
}

// oracle: mutant the prelude starts an attempt whatever the attempts made, so a restart during the last attempt runs one past it
#[tokio::test]
async fn a_job_delivered_again_after_the_last_attempt_fails_the_task() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let now = OffsetDateTime::now_utc();
    for _ in 0..MAX_ATTEMPTS {
        harness
            .store
            .start_attempt(id, json!(null), now + time::Duration::hours(1), now)
            .await
            .expect("start an attempt");
    }

    harness.queued_job().run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "internal" }));
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0, "no attempt past the last");
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: mutant a Task whose parameters cannot be read runs its attempt, or stays unfinished
#[tokio::test]
async fn invalid_parameters_fail_the_task() {
    let harness = Harness::new(|value| Ok(json!(value))).await;
    let id = Uuid::new_v4();
    let job_token = Uuid::new_v4();
    harness
        .record_task(id, json!({ "value": "not a number" }), job_token)
        .await;
    let mut job = harness.job(id, job_token);

    job.run().await.expect("no retry");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "invalidTask" }));
    assert_eq!(harness.runs.load(Ordering::SeqCst), 0);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_success_is_recorded_only_once_its_output_is_published() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let mut job = harness.queued_job();
    harness.publish_failures.store(1, Ordering::SeqCst);

    job.run().await.expect_err("the job queue runs the job again");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Running, "{:?}", task.payload);
    assert!(harness.published.lock().is_empty());
    assert!(harness.ended.lock().is_empty());

    job.run().await.expect("the publication succeeds");

    let task = harness.task(id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded, "{:?}", task.payload);
    assert_eq!(task.attempts, 2, "the output comes from a new attempt");
    assert_eq!(*harness.published.lock(), [id]);
    assert_eq!(*harness.ended.lock(), [id]);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn an_end_that_fails_is_done_again_when_the_job_queue_runs_the_job_again() {
    let mut harness = Harness::new(|value| Ok(json!(value))).await;
    let id = harness.create(1).await;
    let mut job = harness.queued_job();
    harness.end_failures.store(2, Ordering::SeqCst);

    for _ in 0..2 {
        job.run().await.expect_err("the job queue runs the job again");
        assert!(harness.ended.lock().is_empty());
    }

    job.run().await.expect("the end succeeds");

    assert_eq!(harness.task(id).await.state, ProvisionerTaskState::Succeeded);
    assert_eq!(harness.runs.load(Ordering::SeqCst), 1, "the work is not done again");
    assert_eq!(*harness.ended.lock(), [id]);
    assert!(harness.job_queue.take().is_none(), "no job is left");
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
    let mut harness = Harness::with_progress_timeout(|value| Ok(json!(value)), time::Duration::seconds(3)).await;
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
    let read = TaskJob::read_json(&json, harness.echo(), Arc::clone(&harness.store)).expect("valid job");

    assert_eq!(read.task_id, id);
    assert_eq!(job.name(), KIND);
}
