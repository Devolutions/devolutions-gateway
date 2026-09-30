#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{self, Request, StatusCode};
use base64::Engine as _;
use devolutions_gateway::recording::RecordingManagerTask;
use devolutions_gateway::tasks::{SECRETS_LOST_ERROR, TaskRunnerTask, TaskService};
use devolutions_gateway::{DgwState, MockHandles};
use devolutions_gateway_task::{ChildTask, ShutdownHandle, Task as _};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use uuid::Uuid;

const API_KEY: &str = "sk-task-api-test-secret";

/// Gateway configuration keeping the task database in `dir`, so a later start on the same `dir` acts as a restart.
fn config(dir: &Path, enable_unstable: bool) -> String {
    json!({
        "ProvisionerPublicKeyData": {
            "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
        },
        "Listeners": [
            {
                "InternalUrl": "http://*:7171",
                "ExternalUrl": "https://*:7171"
            }
        ],
        "Proxy": { "Mode": "Off" },
        "ProvisionerTasksDatabase": tasks_db(dir),
        "RecordingPath": dir.join("recordings"),
        "__debug__": {
            "disable_token_validation": true,
            "enable_unstable": enable_unstable
        }
    })
    .to_string()
}

struct Gateway {
    app: Router,
    shutdown_handle: ShutdownHandle,
    job_tasks: Vec<ChildTask<anyhow::Result<()>>>,
    _mock_handles: Box<dyn Send>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Jobs {
    Run,
    QueueOnly,
}

impl Gateway {
    /// Starts a Gateway with the task system enabled, keeping the task database in `dir`.
    async fn start(dir: &Path, jobs: Jobs) -> anyhow::Result<Self> {
        Self::start_with_config(&config(dir, true), jobs).await
    }

    async fn start_with_config(config: &str, jobs: Jobs) -> anyhow::Result<Self> {
        let (mut state, handles) = DgwState::mock(config)?;
        let MockHandles {
            session_manager_rx,
            recording_manager_rx,
            subscriber_rx,
            job_queue_rx,
            traffic_audit_rx,
            shutdown_handle: mock_shutdown_handle,
        } = handles;

        // The auth middleware asks the session manager about any token carrying `jet_aid`; nothing answers in the mock.
        drop(session_manager_rx);

        let recording_manager = RecordingManagerTask::new(
            recording_manager_rx,
            state.conf_handle.get_conf().recording_path.clone(),
            state.sessions.clone(),
            state.job_queue_handle.clone(),
        );

        state.tasks = TaskService::open_if_enabled(&state.conf_handle.get_conf()).await?;

        let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let mut job_tasks = Vec::new();

        if let (Some(tasks), Jobs::Run) = (state.tasks.clone(), jobs) {
            let runner = TaskRunnerTask::new(tasks, state.clone());
            job_tasks.push(ChildTask::spawn(runner.run(shutdown_signal.clone())));
        }

        job_tasks.push(ChildTask::spawn(recording_manager.run(shutdown_signal)));

        let app = devolutions_gateway::make_http_service(state)
            .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))));

        Ok(Self {
            app,
            shutdown_handle,
            job_tasks,
            _mock_handles: Box::new((subscriber_rx, job_queue_rx, traffic_audit_rx, mock_shutdown_handle)),
        })
    }

    async fn stop(self) {
        self.shutdown_handle.signal();

        for task in self.job_tasks {
            task.join().await.unwrap().unwrap();
        }
    }
}

fn tasks_db(dir: &Path) -> PathBuf {
    dir.join("provisioner_tasks.db")
}

/// Jobs in the task job queue, which lives in the task database.
async fn queued_job_count(dir: &Path) -> u64 {
    let conn = job_queue_libsql::libsql::Builder::new_local(tasks_db(dir))
        .build()
        .await
        .unwrap()
        .connect()
        .unwrap();

    let row = conn
        .query("SELECT count(*) FROM job_queue", ())
        .await
        .unwrap()
        .next()
        .await
        .unwrap()
        .unwrap();

    row.get::<u64>(0).unwrap()
}

async fn wait_for_queued_jobs(dir: &Path, expected: u64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while queued_job_count(dir).await != expected {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("job queue reaches the expected size");
}

/// Every file of the task database, WAL included, since SQLite may not have checkpointed yet.
fn database_bytes(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.to_str().unwrap().contains(".db"))
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle.as_bytes())
}

fn assert_database_holds_settings_but_not_the_key(dir: &Path) {
    let files = database_bytes(dir);
    assert!(files.iter().any(|(path, _)| path.ends_with("provisioner_tasks.db")));

    let all = files
        .iter()
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect::<Vec<_>>();
    assert!(contains(&all, "gpt-test"), "the scan sees the persisted settings");

    for (path, bytes) in &files {
        assert!(!contains(bytes, API_KEY), "{} holds the API key", path.display());
    }
}

fn unsigned_jws(cty: &str, payload: &Value) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(json!({ "alg": "RS256", "cty": cty }).to_string());
    let payload = engine.encode(payload.to_string());
    let signature = engine.encode(b"signature");
    format!("{header}.{payload}.{signature}")
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn task_token() -> String {
    session_task_token(Uuid::new_v4())
}

fn session_task_token(session_id: Uuid) -> String {
    unsigned_jws(
        "TASK",
        &json!({
            "jet_tk": "ai-log",
            "jet_aid": session_id,
            "nbf": now(),
            "exp": now() + 600,
            "jti": Uuid::new_v4(),
        }),
    )
}

fn scope_token(scope: &str) -> String {
    unsigned_jws(
        "SCOPE",
        &json!({ "scope": scope, "exp": now() + 600, "jti": Uuid::new_v4() }),
    )
}

fn ai_params() -> Value {
    json!({ "provider": "openai", "model": "gpt-test", "apiKey": API_KEY })
}

fn start_request(token: Option<&str>, params: &Value) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/jet/tasks")
        .header(http::header::CONTENT_TYPE, "application/json");

    if let Some(token) = token {
        request = request.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    }

    request.body(Body::from(params.to_string())).unwrap()
}

fn status_request(token: Option<&str>, id: Uuid) -> Request<Body> {
    let mut request = Request::builder().method("GET").uri(format!("/jet/tasks/{id}"));

    if let Some(token) = token {
        request = request.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    }

    request.body(Body::empty()).unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

async fn start_task(app: &Router) -> Value {
    let (status, body) = send(app, start_request(Some(&task_token()), &ai_params())).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    serde_json::from_str(&body).unwrap()
}

async fn wait_until_finished(app: &Router, id: Uuid) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (status, body) = send(app, status_request(Some(&scope_token("gateway.tasks.read")), id)).await;
            assert_eq!(status, StatusCode::OK, "{body}");

            let info: Value = serde_json::from_str(&body).unwrap();
            if info["state"] == "success" || info["state"] == "failed" {
                return info;
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("task finishes")
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn capture_logs() -> (CapturedLogs, impl Sized) {
    let logs = CapturedLogs::default();
    let writer = logs.clone();
    let guard = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .set_default();

    // With one registered dispatcher, tracing takes callsite interest from the thread that hits it first,
    // so a parallel test thread without a subscriber would disable these events for everyone.
    let second_dispatcher = tracing::Dispatch::new(tracing_subscriber::registry());

    (logs, (guard, second_dispatcher))
}

#[tokio::test]
async fn ai_log_task_without_recording_fails() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let app = gateway.app.clone();

    let started = start_task(&app).await;
    assert_eq!(started["kind"], "ai-log");
    assert_eq!(started["state"], "not-started");

    let id = started["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    let finished = wait_until_finished(&app, id).await;

    assert_eq!(
        finished,
        json!({
            "id": id,
            "kind": "ai-log",
            "state": "failed",
            "error": "session has no recording",
        })
    );
}

#[tokio::test]
async fn start_requires_a_task_token() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let app = gateway.app.clone();

    let (status, _) = send(&app, start_request(None, &ai_params())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(&app, start_request(Some(&scope_token("*")), &ai_params())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn status_requires_the_tasks_read_scope() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let app = gateway.app.clone();
    let id = start_task(&app).await["id"].as_str().unwrap().parse::<Uuid>().unwrap();

    let (status, _) = send(&app, status_request(None, id)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = send(&app, status_request(Some(&task_token()), id)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(&app, status_request(Some(&scope_token("gateway.sessions.read")), id)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(&app, status_request(Some(&scope_token("*")), id)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_task_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let app = gateway.app.clone();

    let (status, body) = send(
        &app,
        status_request(Some(&scope_token("gateway.tasks.read")), Uuid::new_v4()),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({ "error": "task_not_found" })
    );
}

#[tokio::test]
async fn invalid_ai_settings_are_typed_bad_requests() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let app = gateway.app.clone();

    for (params, expected) in [
        (json!({ "provider": "openai", "model": "gpt-test" }), "invalid_params"),
        (
            json!({ "provider": "openai", "model": "gpt-test", "apiKey": "" }),
            "missing_api_key",
        ),
        (
            json!({ "provider": "openai", "model": " ", "apiKey": API_KEY }),
            "missing_model",
        ),
        (
            json!({ "provider": "openai-compatible", "model": "gpt-test", "apiKey": API_KEY }),
            "missing_base_url",
        ),
        (
            json!({ "provider": "ollama", "model": "llama", "baseUrl": "http://localhost:11434/" }),
            "invalid_params",
        ),
        (json!({ "model": "gpt-test", "apiKey": API_KEY }), "invalid_params"),
    ] {
        let (status, body) = send(&app, start_request(Some(&task_token()), &params)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{params}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({ "error": expected })
        );
    }
}

#[tokio::test]
async fn api_key_never_appears_in_responses_or_logs() {
    let (logs, _guard) = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let app = gateway.app.clone();

    let started = start_task(&app).await;
    assert!(!started.to_string().contains(API_KEY));

    let id = started["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    let finished = wait_until_finished(&app, id).await;
    assert!(!finished.to_string().contains(API_KEY));

    // A key sent in the wrong field must not be echoed by the parameter error either.
    let misplaced = json!({ "provider": "openai", "model": "gpt-test", "apiKey": "sk", "maxOutputTokens": API_KEY });
    let (status, body) = send(&app, start_request(Some(&task_token()), &misplaced)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.contains(API_KEY));

    let logs = logs.text();
    assert!(logs.contains("Background task failed"), "{logs}");
    assert!(!logs.contains(API_KEY), "{logs}");
}

#[tokio::test]
async fn stable_gateway_never_touches_the_task_database() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start_with_config(&config(dir.path(), false), Jobs::Run)
        .await
        .unwrap();
    let app = gateway.app.clone();

    let (status, _) = send(&app, start_request(Some(&task_token()), &ai_params())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = send(
        &app,
        status_request(Some(&scope_token("gateway.tasks.read")), Uuid::new_v4()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    gateway.stop().await;

    assert!(
        database_bytes(dir.path()).is_empty(),
        "no task database file is created"
    );
}

#[tokio::test]
async fn unstable_gateway_opens_the_task_database_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();

    assert!(tasks_db(dir.path()).exists());
    assert_eq!(queued_job_count(dir.path()).await, 0);

    gateway.stop().await;
}

#[tokio::test]
async fn neither_database_ever_holds_the_api_key() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();

    let started = start_task(&gateway.app).await;
    let id = started["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    assert_eq!(wait_until_finished(&gateway.app, id).await["state"], "failed");
    wait_for_queued_jobs(dir.path(), 0).await;

    gateway.stop().await;

    assert_database_holds_settings_but_not_the_key(dir.path());
}

#[tokio::test]
async fn after_a_restart_the_ephemeral_task_fails_without_retry() {
    let dir = tempfile::tempdir().unwrap();

    let before = Gateway::start(dir.path(), Jobs::QueueOnly).await.unwrap();
    let started = start_task(&before.app).await;
    let id = started["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    wait_for_queued_jobs(dir.path(), 1).await;
    before.stop().await;

    assert_database_holds_settings_but_not_the_key(dir.path());

    let after = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let finished = wait_until_finished(&after.app, id).await;

    assert_eq!(
        finished,
        json!({
            "id": id,
            "kind": "ai-log",
            "state": "failed",
            "error": SECRETS_LOST_ERROR,
        })
    );

    wait_for_queued_jobs(dir.path(), 0).await;
    after.stop().await;

    assert_database_holds_settings_but_not_the_key(dir.path());
}

#[tokio::test]
async fn task_records_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();

    let before = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let id = start_task(&before.app).await["id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let finished = wait_until_finished(&before.app, id).await;
    before.stop().await;

    let after = Gateway::start(dir.path(), Jobs::Run).await.unwrap();
    let (status, body) = send(&after.app, status_request(Some(&scope_token("gateway.tasks.read")), id)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), finished);

    after.stop().await;
}

const SESSION_START: i64 = 1_787_255_035;

const CAST: &str = r#"{"version": 2, "width": 80, "height": 24}
[0.5,"o","user@host:~$ "]
[1.5,"o","whoami\r\n"]
[1.6,"o","user\r\n"]
"#;

const AI_ANSWER: &str =
    r#"{"offsetSeconds":0.5,"description":"Checked the current user","parameters":{"Command":"whoami"}}"#;

/// Writes a finished session to the recording folder of the Gateway working in `dir`.
fn write_session(dir: &Path, files: &[(&str, &str)]) -> (Uuid, PathBuf) {
    let session_id = Uuid::new_v4();
    let session_dir = dir.join("recordings").join(session_id.to_string());
    std::fs::create_dir_all(&session_dir).unwrap();

    let manifest_files = files
        .iter()
        .map(|(name, _)| json!({ "fileName": name, "startTime": SESSION_START, "duration": 10 }))
        .collect::<Vec<_>>();

    let manifest = json!({
        "sessionId": session_id,
        "startTime": SESSION_START,
        "duration": 10,
        "files": manifest_files,
    });
    std::fs::write(session_dir.join("recording.json"), manifest.to_string()).unwrap();

    for (name, contents) in files {
        std::fs::write(session_dir.join(name), contents).unwrap();
    }

    (session_id, session_dir)
}

fn read_manifest(session_dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(session_dir.join("recording.json")).unwrap()).unwrap()
}

/// Model the mock AI provider reports, as a real one reports a dated version of the requested model.
const REPORTED_MODEL: &str = "gpt-test-2026-09-30";

/// Result of a successful `ai-log` task run against the mock AI provider.
fn expected_result(file_name: &str, input_tokens: u64, output_tokens: u64) -> Value {
    json!({
        "fileName": file_name,
        "model": REPORTED_MODEL,
        "usage": { "inputTokens": input_tokens, "outputTokens": output_tokens }
    })
}

/// A mock OpenAI-compatible provider that answers every request with the same action and keeps the request bodies.
async fn spawn_ai_provider() -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_truncating_ai_provider(|_| false).await
}

/// Like [`spawn_ai_provider`], but answers as cut at the token limit when `truncated` says so for the request body.
async fn spawn_truncating_ai_provider(
    truncated: impl Fn(&str) -> bool + Clone + Send + Sync + 'static,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));

    let app = Router::new().fallback(axum::routing::post({
        let requests = Arc::clone(&requests);
        move |body: String| {
            let requests = Arc::clone(&requests);
            let finish_reason = if truncated(&body) { "length" } else { "stop" };
            async move {
                requests
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str::<Value>(&body).unwrap());
                axum::Json(json!({
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "created": 0,
                    "model": REPORTED_MODEL,
                    "choices": [{
                        "index": 0,
                        "message": { "role": "assistant", "content": AI_ANSWER },
                        "finish_reason": finish_reason
                    }],
                    "usage": { "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30 }
                }))
            }
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{addr}/v1/"), requests)
}

async fn run_ai_log(app: &Router, session_id: Uuid, base_url: &str) -> Value {
    let params = json!({
        "provider": "openai-compatible",
        "model": "gpt-test",
        "apiKey": API_KEY,
        "baseUrl": base_url,
    });

    let (status, body) = send(app, start_request(Some(&session_task_token(session_id)), &params)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    let id = serde_json::from_str::<Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();

    wait_until_finished(app, id).await
}

#[tokio::test]
async fn ai_log_task_appends_a_generated_log_to_the_session() {
    let dir = tempfile::tempdir().unwrap();
    let (session_id, session_dir) = write_session(dir.path(), &[("recording-0.cast", CAST)]);
    let files_before = read_manifest(&session_dir)["files"].clone();
    let (base_url, requests) = spawn_ai_provider().await;
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();

    let first = run_ai_log(&gateway.app, session_id, &base_url).await;
    assert_eq!(first["state"], "success", "{first}");
    assert_eq!(first["result"], expected_result("ai-analysis-0.slog", 10, 20));

    let requests_so_far = requests.lock().unwrap().clone();
    assert_eq!(requests_so_far.len(), 1);
    let sent = requests_so_far[0].to_string();
    assert!(sent.contains(r"[0.5] user@host:~$ whoami\n[1.6] user\n"), "{sent}");
    assert_eq!(
        requests_so_far[0]["model"], "gpt-test",
        "the requested model is sent as is"
    );

    let expected = [
        r#"{"timestamp":"2026-08-20T19:43:55.000Z","seq":0,"event":"session.start","description":"Session started","source":"ai","model":"gpt-test-2026-09-30","promptVersion":"session-actions-1"}"#,
        r#"{"timestamp":"2026-08-20T19:43:55.500Z","seq":1,"event":"session.action","description":"Checked the current user","parameters":{"Command":"whoami"}}"#,
        r#"{"timestamp":"2026-08-20T19:44:05.000Z","seq":2,"event":"session.end","description":"Session ended"}"#,
    ]
    .map(|line| format!("{line}\n"))
    .concat();
    assert_eq!(
        std::fs::read_to_string(session_dir.join("ai-analysis-0.slog")).unwrap(),
        expected
    );

    let manifest = read_manifest(&session_dir);
    assert_eq!(
        manifest["artifacts"],
        json!({ "ai-analysis": [{ "fileName": "ai-analysis-0.slog" }] })
    );
    assert_eq!(manifest["files"], files_before);

    let second = run_ai_log(&gateway.app, session_id, &base_url).await;
    assert_eq!(
        second["result"],
        expected_result("ai-analysis-1.slog", 10, 20),
        "{second}"
    );
    assert_eq!(
        std::fs::read_to_string(session_dir.join("ai-analysis-1.slog")).unwrap(),
        expected
    );

    let manifest = read_manifest(&session_dir);
    assert_eq!(
        manifest["artifacts"],
        json!({ "ai-analysis": [{ "fileName": "ai-analysis-0.slog" }, { "fileName": "ai-analysis-1.slog" }] })
    );
    assert_eq!(manifest["files"], files_before);

    wait_for_queued_jobs(dir.path(), 0).await;
    gateway.stop().await;

    assert_database_holds_settings_but_not_the_key(dir.path());
    assert_no_file_holds_the_key(dir.path());
    assert_workspaces_are_gone(dir.path());
}

fn assert_no_file_holds_the_key(dir: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_file_holds_the_key(&path);
        } else {
            assert!(!contains(&std::fs::read(&path).unwrap(), API_KEY), "{}", path.display());
        }
    }
}

fn assert_workspaces_are_gone(dir: &Path) {
    let workspaces = dir.join("recordings").join(devolutions_gateway::tasks::WORKSPACES_DIR);
    let left = std::fs::read_dir(&workspaces).map_or(0, |entries| entries.count());
    assert_eq!(left, 0, "{}", workspaces.display());
}

/// A finished session whose transcript is `lines` lines of about 100 bytes, marked `line <n>`.
fn write_long_session(dir: &Path, lines: usize) -> (Uuid, PathBuf) {
    let mut cast = String::from("{\"version\": 2}\n");
    for line in 0..lines {
        cast.push_str(&format!("[{line}.0,\"o\",\"line {line} {}\\r\\n\"]\n", "x".repeat(80)));
    }

    write_session(dir, &[("recording-0.cast", &cast)])
}

#[tokio::test]
async fn ai_log_task_splits_a_chunk_whose_answer_is_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let (session_id, session_dir) = write_long_session(dir.path(), 60);
    let (base_url, requests) =
        spawn_truncating_ai_provider(|body| body.contains("] line 0 ") && body.contains("] line 59 ")).await;
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();

    let finished = run_ai_log(&gateway.app, session_id, &base_url).await;
    assert_eq!(finished["state"], "success", "{finished}");
    assert_eq!(
        finished["result"],
        expected_result("ai-analysis-0.slog", 30, 60),
        "the cut answer counts too"
    );

    let requests = requests
        .lock()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3, "the whole chunk, then its two halves");
    assert!(requests[1].contains("] line 0 ") && !requests[1].contains("] line 59 "));
    assert!(!requests[2].contains("] line 0 ") && requests[2].contains("] line 59 "));

    let log = std::fs::read_to_string(session_dir.join("ai-analysis-0.slog")).unwrap();
    assert_eq!(log.lines().filter(|line| line.contains("session.action")).count(), 2);

    wait_for_queued_jobs(dir.path(), 0).await;
    gateway.stop().await;
    assert_workspaces_are_gone(dir.path());
}

#[tokio::test]
async fn ai_log_task_fails_when_even_a_short_part_is_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let (session_id, session_dir) = write_long_session(dir.path(), 60);
    let (base_url, requests) = spawn_truncating_ai_provider(|_| true).await;
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();

    let finished = run_ai_log(&gateway.app, session_id, &base_url).await;

    assert_eq!(finished["state"], "failed");
    assert_eq!(finished["error"], devolutions_gateway::tasks::ai_log::TRUNCATED_ERROR);
    assert_eq!(
        requests.lock().unwrap().len(),
        3,
        "6 KB, then 3 KB, then 1.5 KB, below the split floor"
    );
    assert!(read_manifest(&session_dir).get("artifacts").is_none());

    wait_for_queued_jobs(dir.path(), 0).await;
    gateway.stop().await;
    assert_workspaces_are_gone(dir.path());
}

#[tokio::test]
async fn ai_log_task_fails_for_a_video_only_session() {
    let dir = tempfile::tempdir().unwrap();
    let (session_id, session_dir) = write_session(dir.path(), &[("recording-0.webm", "not a video")]);
    let (base_url, requests) = spawn_ai_provider().await;
    let gateway = Gateway::start(dir.path(), Jobs::Run).await.unwrap();

    let finished = run_ai_log(&gateway.app, session_id, &base_url).await;

    assert_eq!(finished["state"], "failed");
    assert_eq!(finished["error"], "unsupported recording type: webm");
    assert!(requests.lock().unwrap().is_empty());
    assert!(read_manifest(&session_dir).get("artifacts").is_none());

    // A permanent failure is not retried.
    wait_for_queued_jobs(dir.path(), 0).await;
    gateway.stop().await;
}
