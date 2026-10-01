use job_queue::Job as _;
use provisioner_task_store_libsql::TaskState;

use super::ai_log::{AiLogTarget, AiLogTask};
use super::*;
use crate::MockHandles;

const API_KEY: &str = "sk-task-unit-test-secret";

const CONFIG: &str = r#"{
    "ProvisionerPublicKeyData": {
        "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
    },
    "Listeners": [{ "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" }],
    "Proxy": { "Mode": "Off" }
}"#;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum Outcome {
    Succeed,
    Transient,
    Permanent,
    Hang,
    Panic,
}

#[derive(Default, Serialize)]
struct Step {
    step: u32,
}

/// Durable test task doing what its parameters say, attempted at most `N` times.
struct Scripted<const N: u32>;

impl<const N: u32> TaskKind for Scripted<N> {
    const KIND: &'static str = "scripted";
    const RETRY: RetryPolicy = RetryPolicy { max_attempts: N };

    type Target = ();
    type Params = Outcome;
    type Substate = Step;
    type Output = u32;

    async fn run(ctx: TaskCtx<Self>) -> Result<u32, TaskError> {
        ctx.progress.set(&Step { step: ctx.attempt }).await;

        match ctx.params {
            Outcome::Succeed => Ok(42),
            Outcome::Transient => Err(TaskError::Transient("rate limited".to_owned())),
            Outcome::Permanent => Err(TaskError::Permanent("unauthorized".to_owned())),
            Outcome::Hang => std::future::pending().await,
            Outcome::Panic => panic!("scripted panic"),
        }
    }
}

impl<const N: u32> DurableTask for Scripted<N> {
    fn prepare(_: &DgwState, _: &(), _: &Outcome) -> Result<(), TaskErrorCode> {
        Ok(())
    }
}

/// Durable test task that makes the task records unwritable, then succeeds or fails for good as its parameters say.
struct LosesStore;

impl TaskKind for LosesStore {
    const KIND: &'static str = "loses-store";
    const RETRY: RetryPolicy = RetryPolicy::JOB_QUEUE;

    /// Path of the task database.
    type Target = String;
    type Params = Outcome;
    type Substate = Step;
    type Output = u32;

    async fn run(ctx: TaskCtx<Self>) -> Result<u32, TaskError> {
        let conn = libsql::Builder::new_local(ctx.target.as_str())
            .build()
            .await
            .expect("database")
            .connect()
            .expect("connection");

        conn.execute("ALTER TABLE task RENAME TO task_gone", ())
            .await
            .expect("rename");

        match ctx.params {
            Outcome::Succeed => Ok(42),
            _ => Err(TaskError::Permanent("unauthorized".to_owned())),
        }
    }
}

impl DurableTask for LosesStore {
    fn prepare(_: &DgwState, _: &String, _: &Outcome) -> Result<(), TaskErrorCode> {
        Ok(())
    }
}

struct Harness {
    state: DgwState,
    tasks: TaskService,
    _handles: MockHandles,
    _dir: tempfile::TempDir,
    db_path: String,
}

impl Harness {
    async fn new() -> Self {
        Self::with_timeout(TASK_TIMEOUT).await
    }

    async fn with_timeout(timeout: Duration) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir
            .path()
            .join("provisioner_tasks.db")
            .to_str()
            .expect("UTF-8")
            .to_owned();

        let (state, handles) = DgwState::mock(CONFIG).expect("mock state");
        let tasks = TaskService::open(&db_path, timeout).await.expect("task service");

        Self {
            state,
            tasks,
            _handles: handles,
            _dir: dir,
            db_path,
        }
    }

    /// Reads back the job of a task from the task job queue.
    async fn queued_job(&self, id: Uuid) -> TaskJob {
        let json = self
            .tasks
            .inner
            .queue
            .job_defs(TaskJob::NAME)
            .await
            .expect("job definitions")
            .into_iter()
            .find(|json| serde_json::from_str::<TaskJobDef>(json).is_ok_and(|def| def.task_id == id))
            .expect("queued job");

        TaskJob::read_json(&json, self.tasks.clone(), self.state.clone()).expect("valid job")
    }

    async fn start_scripted<const N: u32>(&self, outcome: Outcome) -> TaskJob {
        let body = serde_json::to_vec(&outcome).expect("JSON");

        let snapshot = self
            .tasks
            .start_durable::<Scripted<N>>(&self.state, (), &body, Uuid::new_v4())
            .await
            .expect("task starts");

        self.queued_job(snapshot.id).await
    }

    async fn run_scripted<const N: u32>(&self, job: &TaskJob) -> anyhow::Result<()> {
        self.tasks
            .execute_durable::<Scripted<N>>(&self.state, job.def.clone())
            .await
    }

    async fn start_ai_log(&self) -> TaskSnapshot {
        let body = serde_json::json!({ "provider": "openai", "model": "gpt-test", "apiKey": API_KEY }).to_string();
        let target = AiLogTarget {
            session_id: Uuid::new_v4(),
        };

        self.tasks
            .start_ephemeral::<AiLogTask>(&self.state, target, body.as_bytes(), Uuid::new_v4())
            .await
            .expect("task starts")
    }

    async fn record(&self, id: Uuid) -> TaskRecord {
        self.tasks.store().get(id).await.expect("read").expect("record exists")
    }
}

#[tokio::test]
async fn success_stores_the_result() {
    let harness = Harness::new().await;
    let job = harness.start_scripted::<5>(Outcome::Succeed).await;

    let record = harness.record(job.def.task_id).await;
    assert_eq!(record.state, TaskState::NotStarted);
    assert_eq!(record.kind, "scripted");

    harness.run_scripted::<5>(&job).await.expect("no retry");

    let record = harness.record(job.def.task_id).await;
    assert_eq!(record.state, TaskState::Success);
    assert_eq!(record.result.as_deref(), Some("42"));
    assert_eq!(record.attempts, 1);
}

#[tokio::test]
async fn transient_error_asks_the_job_queue_for_a_retry() {
    let harness = Harness::new().await;
    let job = harness.start_scripted::<3>(Outcome::Transient).await;
    let id = job.def.task_id;

    for attempt in 1..3 {
        assert!(
            harness.run_scripted::<3>(&job).await.is_err(),
            "attempt {attempt} is retried"
        );

        let record = harness.record(id).await;
        assert_eq!(record.state, TaskState::NotStarted);
        assert_eq!(record.attempts, attempt);
        assert_eq!(record.error.as_deref(), Some("rate limited"));
    }

    harness
        .run_scripted::<3>(&job)
        .await
        .expect("last attempt is not retried");

    let record = harness.record(id).await;
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(record.attempts, 3);
    assert_eq!(record.error.as_deref(), Some("rate limited"));
}

#[tokio::test]
async fn retry_policy_is_capped_by_the_job_queue() {
    let harness = Harness::new().await;
    let job = harness.start_scripted::<100>(Outcome::Transient).await;

    let mut retried = 0;
    while harness.run_scripted::<100>(&job).await.is_err() {
        retried += 1;
    }

    assert_eq!(retried, TASK_MAX_ATTEMPTS - 1);
    assert_eq!(harness.record(job.def.task_id).await.state, TaskState::Failed);
}

#[tokio::test]
async fn permanent_error_fails_without_retry() {
    let harness = Harness::new().await;
    let job = harness.start_scripted::<5>(Outcome::Permanent).await;

    harness.run_scripted::<5>(&job).await.expect("no retry");

    let record = harness.record(job.def.task_id).await;
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(record.error.as_deref(), Some("unauthorized"));
    assert_eq!(record.attempts, 1);
    assert!(record.finished_at.is_some());
}

#[tokio::test]
async fn finished_task_is_not_run_again() {
    let harness = Harness::new().await;
    let job = harness.start_scripted::<5>(Outcome::Succeed).await;

    harness.run_scripted::<5>(&job).await.expect("first run");
    harness.run_scripted::<5>(&job).await.expect("second run");

    assert_eq!(harness.record(job.def.task_id).await.attempts, 1);
}

#[tokio::test]
async fn timeout_and_panic_are_permanent_failures() {
    let harness = Harness::with_timeout(Duration::from_millis(20)).await;

    for (outcome, error) in [(Outcome::Hang, "task timed out"), (Outcome::Panic, "task panicked")] {
        let job = harness.start_scripted::<5>(outcome).await;
        harness.run_scripted::<5>(&job).await.expect("no retry");

        let record = harness.record(job.def.task_id).await;
        assert_eq!(record.state, TaskState::Failed);
        assert_eq!(record.error.as_deref(), Some(error));
    }
}

#[tokio::test]
async fn ephemeral_task_fails_without_retry_after_a_restart() {
    let harness = Harness::new().await;
    let snapshot = harness.start_ai_log().await;

    let json = harness.queued_job(snapshot.id).await.write_json().expect("job JSON");
    assert!(!json.contains(API_KEY), "{json}");

    // A restart keeps the database but loses the secrets held in memory.
    let restarted = TaskService::open(&harness.db_path, TASK_TIMEOUT)
        .await
        .expect("task service");
    let mut job = TaskJob::read_json(&json, restarted, harness.state.clone()).expect("valid job");

    job.run().await.expect("no retry");

    let record = harness.record(snapshot.id).await;
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(record.error.as_deref(), Some(SECRETS_LOST_ERROR));
    assert_eq!(record.attempts, 0);
}

#[tokio::test]
async fn secrets_are_dropped_when_the_task_finishes() {
    let harness = Harness::new().await;
    let snapshot = harness.start_ai_log().await;

    assert!(harness.tasks.inner.secrets.lock().contains_key(&snapshot.id));

    let mut job = harness.queued_job(snapshot.id).await;
    job.run().await.expect("no retry");

    assert!(harness.tasks.inner.secrets.lock().is_empty());

    let record = harness.record(snapshot.id).await;
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(record.error.as_deref(), Some("ai-log task not implemented yet"));
    assert!(!record.params.contains(API_KEY), "{}", record.params);
}

#[tokio::test]
async fn final_state_is_not_run_again_when_its_record_cannot_be_written() {
    for outcome in [Outcome::Succeed, Outcome::Permanent] {
        let harness = Harness::new().await;
        let body = serde_json::to_vec(&outcome).expect("JSON");

        let snapshot = harness
            .tasks
            .start_durable::<LosesStore>(&harness.state, harness.db_path.clone(), &body, Uuid::new_v4())
            .await
            .expect("task starts");
        let job = harness.queued_job(snapshot.id).await;

        harness
            .tasks
            .execute_durable::<LosesStore>(&harness.state, job.def.clone())
            .await
            .unwrap_or_else(|error| panic!("{outcome:?} run is retried: {error:#}"));
    }
}

#[tokio::test]
async fn reconcile_fails_unfinished_tasks_without_a_job() {
    let harness = Harness::new().await;

    let queued = harness.start_scripted::<5>(Outcome::Succeed).await;
    let lost = harness.start_scripted::<5>(Outcome::Succeed).await;
    let running_lost = harness.start_scripted::<5>(Outcome::Succeed).await;
    let finished = harness.start_scripted::<5>(Outcome::Succeed).await;

    let store = harness.tasks.store();
    store
        .start_attempt(running_lost.def.task_id, "null")
        .await
        .expect("start");
    harness.run_scripted::<5>(&finished).await.expect("run");

    let defs = vec![queued.write_json().expect("JSON"), "not a task job".to_owned()];
    harness.tasks.reconcile_with_job_defs(&defs).await.expect("reconcile");

    assert_eq!(harness.record(queued.def.task_id).await.state, TaskState::NotStarted);
    assert_eq!(harness.record(finished.def.task_id).await.state, TaskState::Success);

    for id in [lost.def.task_id, running_lost.def.task_id] {
        let record = harness.record(id).await;
        assert_eq!(record.state, TaskState::Failed);
        assert_eq!(record.error.as_deref(), Some(JOB_LOST_ERROR));
    }
}

#[tokio::test]
async fn snapshot_reflects_the_record() {
    let harness = Harness::new().await;
    let job = harness.start_scripted::<5>(Outcome::Succeed).await;
    let id = job.def.task_id;

    let snapshot = harness.tasks.get(id).await.expect("read").expect("exists");
    assert_eq!(snapshot.kind, "scripted");
    assert_eq!(snapshot.status, TaskStatus::NotStarted);

    let store = harness.tasks.store();
    store.start_attempt(id, r#"{"step":1}"#).await.expect("start");
    assert_eq!(
        harness.tasks.get(id).await.expect("read").expect("exists").status,
        TaskStatus::Running {
            substate: serde_json::json!({ "step": 1 })
        }
    );

    assert!(harness.tasks.get(Uuid::new_v4()).await.expect("read").is_none());
}
