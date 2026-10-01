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

        state.tasks = TaskService::open_if_enabled(&state.conf_handle.get_conf()).await?;

        let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let mut job_tasks = Vec::new();

        if let (Some(tasks), Jobs::Run) = (state.tasks.clone(), jobs) {
            let runner = TaskRunnerTask::new(tasks, state.clone());
            job_tasks.push(ChildTask::spawn(runner.run(shutdown_signal)));
        }

        let app = devolutions_gateway::make_http_service(state)
            .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))));

        Ok(Self {
            app,
            shutdown_handle,
            job_tasks,
            _mock_handles: Box::new((
                recording_manager_rx,
                subscriber_rx,
                job_queue_rx,
                traffic_audit_rx,
                mock_shutdown_handle,
            )),
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
    unsigned_jws(
        "TASK",
        &json!({
            "jet_tk": "ai-log",
            "jet_aid": Uuid::new_v4(),
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
async fn ai_log_task_is_accepted_then_fails_as_not_implemented() {
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
            "error": "ai-log task not implemented yet",
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
