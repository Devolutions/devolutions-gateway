use axum::http::StatusCode;
use camino::Utf8Path;
use job_queue::Job as _;
use provisioner_task_store_libsql::TaskState;

use super::ai_log::{AiLogTarget, AiLogTask};
use super::*;
use crate::MockHandles;
use crate::recording::RecordingManagerTask;

const API_KEY: &str = "sk-task-unit-test-secret";

fn config(recording_path: &Utf8Path) -> String {
    serde_json::json!({
        "ProvisionerPublicKeyData": {
            "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
        },
        "Listeners": [{ "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" }],
        "Proxy": { "Mode": "Off" },
        "RecordingPath": recording_path,
    })
    .to_string()
}

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
    _handles: Box<dyn Send>,
    _dir: tempfile::TempDir,
    db_path: String,
    recording_path: Utf8PathBuf,
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

        let recording_path = Utf8PathBuf::from_path_buf(dir.path().join("recordings")).expect("UTF-8");

        let (state, handles) = DgwState::mock(&config(&recording_path)).expect("mock state");
        let MockHandles {
            session_manager_rx,
            recording_manager_rx,
            subscriber_rx,
            job_queue_rx,
            traffic_audit_rx,
            shutdown_handle,
        } = handles;

        let recording_manager = RecordingManagerTask::new(
            recording_manager_rx,
            recording_path.clone(),
            state.sessions.clone(),
            state.job_queue_handle.clone(),
        );
        let (recording_shutdown_handle, recording_shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
        tokio::spawn(recording_manager.run(recording_shutdown_signal));

        let tasks = TaskService::open(&db_path, recording_path.join(WORKSPACES_DIR), timeout)
            .await
            .expect("task service");

        Self {
            state,
            tasks,
            _handles: Box::new((
                session_manager_rx,
                subscriber_rx,
                job_queue_rx,
                traffic_audit_rx,
                shutdown_handle,
                recording_shutdown_handle,
            )),
            _dir: dir,
            db_path,
            recording_path,
        }
    }

    async fn reopen(&self) -> TaskService {
        TaskService::open(&self.db_path, self.recording_path.join(WORKSPACES_DIR), TASK_TIMEOUT)
            .await
            .expect("task service")
    }

    fn workspace(&self, id: Uuid) -> Utf8PathBuf {
        self.recording_path.join(WORKSPACES_DIR).join(id.to_string())
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
        let body = serde_json::json!({ "provider": "openai", "model": "gpt-test", "apiKey": API_KEY });
        self.start_ai_log_with(Uuid::new_v4(), body).await
    }

    async fn start_ai_log_with(&self, session_id: Uuid, body: serde_json::Value) -> TaskSnapshot {
        self.tasks
            .start_ephemeral::<AiLogTask>(
                &self.state,
                AiLogTarget { session_id },
                body.to_string().as_bytes(),
                Uuid::new_v4(),
            )
            .await
            .expect("task starts")
    }

    /// Writes a finished session whose terminal output is `lines` lines of about 100 bytes each.
    fn write_long_session(&self, lines: usize) -> Uuid {
        let session_id = Uuid::new_v4();
        let dir = self.recording_path.join(session_id.to_string());
        std::fs::create_dir_all(&dir).expect("session dir");

        let manifest = serde_json::json!({
            "sessionId": session_id,
            "startTime": 1_787_255_035,
            "duration": lines,
            "files": [{ "fileName": "recording-0.cast", "startTime": 1_787_255_035, "duration": lines }],
        });
        std::fs::write(dir.join("recording.json"), manifest.to_string()).expect("manifest");

        let mut cast = String::from("{\"version\": 2}\n");
        for line in 0..lines {
            cast.push_str(&format!("[{line}.0,\"o\",\"line {line} {}\\r\\n\"]\n", "x".repeat(80)));
        }
        std::fs::write(dir.join("recording-0.cast"), cast).expect("cast");

        session_id
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
    let restarted = harness.reopen().await;
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
    assert_eq!(record.error.as_deref(), Some("session has no recording"));
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

        // A durable task has no secrets; this placeholder checks that the path forgets them like the others.
        harness.tasks.inner.secrets.lock().insert(snapshot.id, Arc::new(()));

        harness
            .tasks
            .execute_durable::<LosesStore>(&harness.state, job.def.clone())
            .await
            .unwrap_or_else(|error| panic!("{outcome:?} run is retried: {error:#}"));

        assert!(
            !harness.tasks.inner.secrets.lock().contains_key(&snapshot.id),
            "{outcome:?} run keeps the secrets"
        );
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

/// A mock OpenAI-compatible provider: `status` picks the answer of the n-th request, 0 being a valid answer.
async fn spawn_ai_provider(
    status: impl Fn(usize) -> u16 + Send + Sync + 'static,
) -> (serde_json::Value, Arc<Mutex<Vec<String>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let status = Arc::new(status);

    let app = axum::Router::new().fallback(axum::routing::post({
        let requests = Arc::clone(&requests);
        move |body: String| {
            let requests = Arc::clone(&requests);
            let status = Arc::clone(&status);
            async move {
                let index = {
                    let mut requests = requests.lock();
                    requests.push(body);
                    requests.len() - 1
                };

                let answer = serde_json::json!({
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "gpt-test",
                    "choices": [{
                        "index": 0,
                        "message": { "role": "assistant", "content": format!("{{\"offsetSeconds\":{index},\"description\":\"Step {index}\"}}") },
                        "finish_reason": "stop"
                    }],
                    "usage": { "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30 }
                });

                match status(index) {
                    0 => (StatusCode::OK, axum::Json(answer)),
                    code => (
                        StatusCode::from_u16(code).expect("valid status"),
                        axum::Json(serde_json::json!({ "error": { "message": "scripted failure" } })),
                    ),
                }
            }
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let body = serde_json::json!({
        "provider": "openai-compatible",
        "model": "gpt-test",
        "apiKey": API_KEY,
        "baseUrl": format!("http://{addr}/v1/"),
    });

    (body, requests)
}

fn first_line(path: &Utf8Path) -> String {
    std::fs::read_to_string(path)
        .expect("chunk")
        .lines()
        .next()
        .expect("line")
        .to_owned()
}

#[tokio::test]
async fn ai_log_retry_resumes_at_the_first_chunk_without_a_checkpoint() {
    let harness = Harness::new().await;
    // About 1 MB of transcript: three chunks.
    let session_id = harness.write_long_session(10_000);
    let (body, requests) = spawn_ai_provider(|index| if index == 1 { 503 } else { 0 }).await;
    let snapshot = harness.start_ai_log_with(session_id, body).await;
    let workspace = harness.workspace(snapshot.id);
    let mut job = harness.queued_job(snapshot.id).await;

    assert!(job.run().await.is_err(), "a provider outage is retried");

    assert_eq!(harness.record(snapshot.id).await.state, TaskState::NotStarted);
    assert!(workspace.starts_with(&harness.recording_path));
    assert_eq!(
        std::fs::read_to_string(workspace.join("chunks.done")).expect("chunks"),
        "3"
    );
    assert!(workspace.join("chunk-0000.actions.jsonl").exists());
    assert!(!workspace.join("chunk-0001.actions.jsonl").exists());
    let chunk_starts = (0..3)
        .map(|index| first_line(&workspace.join(format!("chunk-{index:04}.txt"))))
        .collect::<Vec<_>>();
    assert_eq!(requests.lock().len(), 2);

    job.run().await.expect("second attempt succeeds");

    let record = harness.record(snapshot.id).await;
    assert_eq!(record.state, TaskState::Success, "{:?}", record.error);
    assert_eq!(record.attempts, 2);

    let requests = requests.lock().clone();
    assert_eq!(requests.len(), 4, "only chunks 1 and 2 are sent again");
    for (request, chunk) in requests.iter().zip([0, 1, 1, 2]) {
        assert!(request.contains(&chunk_starts[chunk]), "request for chunk {chunk}");
    }

    let log = std::fs::read_to_string(
        harness
            .recording_path
            .join(session_id.to_string())
            .join("ai-analysis-0.slog"),
    )
    .expect("log");
    let descriptions = log
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSON")["description"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        descriptions,
        ["Session started", "Step 0", "Step 2", "Step 3", "Session ended"].map(serde_json::Value::from)
    );

    assert!(!workspace.exists(), "the workspace is deleted on success");
}

#[tokio::test]
async fn ai_log_workspace_is_deleted_when_the_task_fails() {
    let harness = Harness::new().await;
    let session_id = harness.write_long_session(10);
    let (body, requests) = spawn_ai_provider(|_| 401).await;
    let snapshot = harness.start_ai_log_with(session_id, body).await;

    harness.queued_job(snapshot.id).await.run().await.expect("no retry");

    let record = harness.record(snapshot.id).await;
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(requests.lock().len(), 1);
    assert!(!harness.workspace(snapshot.id).exists());
    assert!(
        !harness
            .recording_path
            .join(WORKSPACES_DIR)
            .read_dir()
            .expect("workspaces")
            .any(|_| true)
    );
}

#[tokio::test]
async fn stale_workspaces_are_removed_at_startup() {
    let harness = Harness::new().await;
    let unfinished = harness.start_ai_log().await;
    let finished = harness.start_scripted::<5>(Outcome::Succeed).await;
    harness.run_scripted::<5>(&finished).await.expect("run");

    let workspaces = harness.recording_path.join(WORKSPACES_DIR);
    for name in [
        unfinished.id.to_string(),
        finished.def.task_id.to_string(),
        Uuid::new_v4().to_string(),
        "not-a-task".to_owned(),
    ] {
        std::fs::create_dir_all(workspaces.join(&name)).expect("workspace");
        std::fs::write(workspaces.join(&name).join("chunk-0000.txt"), "[0.0] x\n").expect("chunk");
    }
    std::fs::write(workspaces.join("stray-file"), "x").expect("file");

    harness.reopen().await;

    let left = workspaces
        .read_dir()
        .expect("workspaces")
        .map(|entry| entry.expect("entry").file_name().into_string().expect("UTF-8"))
        .collect::<Vec<_>>();
    assert_eq!(left, [unfinished.id.to_string()]);
}
