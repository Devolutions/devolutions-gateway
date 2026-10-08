#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway::job_queue::{JobMessage, JobQueueReceiver};
use devolutions_gateway::recording::RecordingManagerTask;
use devolutions_gateway::{DgwState, MockHandles};
use devolutions_gateway_task::ShutdownHandle;
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use uuid::Uuid;

const API_KEY: &str = "sk-ai-analysis-endpoint-test-secret";

fn config(recording_path: &Utf8Path) -> String {
    json!({
        "ProvisionerPublicKeyData": {
            "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
        },
        "Listeners": [{ "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" }],
        "Proxy": { "Mode": "Off" },
        "RecordingPath": recording_path,
        "__debug__": { "disable_token_validation": true },
    })
    .to_string()
}

fn scope_token(scope: &str) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(r#"{"alg":"RS256","typ":"JWT","cty":"SCOPE"}"#);
    let payload = engine.encode(
        json!({
            "jti": Uuid::new_v4(),
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "scope": scope,
        })
        .to_string(),
    );
    let signature = engine.encode(b"signature");
    format!("{header}.{payload}.{signature}")
}

/// Collects every log line, so a test can check that no secret reaches the logs.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

struct Harness {
    app: Router,
    job_queue_rx: JobQueueReceiver,
    recording_path: Utf8PathBuf,
    db_path: Utf8PathBuf,
    task_store: provisioner_task::DynProvisionerTaskStore,
    _keep: Box<dyn Send>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let recording_path = root.join("recordings");
        let db_path = root.join("gateway.db");

        let (mut state, handles) = DgwState::mock(&config(&recording_path)).await.unwrap();

        // A file, unlike the in-memory default, can be searched for secrets afterwards.
        let connection = gateway_db::GatewayDb::open_path(db_path.as_str())
            .await
            .unwrap()
            .connect()
            .await
            .unwrap();
        let task_store: provisioner_task::DynProvisionerTaskStore = Arc::new(
            provisioner_task_libsql::LibSqlProvisionerTaskStore::open(connection)
                .await
                .unwrap(),
        );
        state.provisioner_tasks = devolutions_gateway::provisioner_tasks::task_runner(
            Arc::clone(&task_store),
            Arc::new(state.job_queue_handle.clone()),
            state.conf_handle.clone(),
            state.recordings.clone(),
            state.provisioning.clone(),
        );

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
        let (recording_shutdown_handle, recording_shutdown_signal) = ShutdownHandle::new();
        tokio::spawn(devolutions_gateway_task::Task::run(
            recording_manager,
            recording_shutdown_signal,
        ));

        let app = devolutions_gateway::make_http_service(state)
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 3000))));

        Self {
            app,
            job_queue_rx,
            recording_path,
            db_path,
            task_store,
            _keep: Box::new((
                session_manager_rx,
                subscriber_rx,
                traffic_audit_rx,
                shutdown_handle,
                recording_shutdown_handle,
            )),
            _dir: dir,
        }
    }

    fn write_session(&self) -> Uuid {
        let session_id = Uuid::new_v4();
        let dir = self.recording_path.join(session_id.to_string());
        std::fs::create_dir_all(&dir).unwrap();

        let manifest = json!({
            "sessionId": session_id,
            "startTime": 1_787_255_035,
            "duration": 3,
            "files": [{ "fileName": "recording-0.cast", "startTime": 1_787_255_035, "duration": 3 }],
        });
        std::fs::write(dir.join("recording.json"), manifest.to_string()).unwrap();
        std::fs::write(
            dir.join("recording-0.cast"),
            "{\"version\": 2}\n[0.5,\"o\",\"$ ls\\r\\n\"]\n[1.0,\"o\",\"file.txt\\r\\n\"]\n",
        )
        .unwrap();

        session_id
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, body)
    }

    async fn post_raw(&self, session_id: Uuid, scope: &str, body: String) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/jet/jrec/{session_id}/ai-analysis"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scope_token(scope)))
            .body(Body::from(body))
            .unwrap();
        self.send(request).await
    }

    async fn post(&self, session_id: Uuid, body: &Value) -> (StatusCode, Value) {
        self.post_raw(
            session_id,
            "gateway.tasks.recording-ai-analysis.start",
            body.to_string(),
        )
        .await
    }

    async fn get_analysis(&self, session_id: Uuid, task_id: Uuid, scope: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .uri(format!("/jet/jrec/{session_id}/ai-analysis/{task_id}"))
            .header("authorization", format!("Bearer {}", scope_token(scope)))
            .body(Body::empty())
            .unwrap();
        self.send(request).await
    }

    async fn run_queued_job(&mut self) {
        let JobMessage { mut job, .. } = self.job_queue_rx.try_recv().expect("a queued job");
        job.run().await.unwrap();
    }

    fn database_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for suffix in ["", "-wal"] {
            if let Ok(content) = std::fs::read(format!("{}{suffix}", self.db_path)) {
                bytes.extend(content);
            }
        }
        bytes
    }
}

fn request(task_id: Uuid, model: &str) -> Value {
    json!({ "taskId": task_id, "provider": "openai", "model": model, "apiKey": API_KEY })
}

/// A mock OpenAI-compatible provider answering every request with one action, or with `status` when it is not 200.
async fn spawn_ai_provider(status: u16) -> String {
    let app = Router::new().fallback(axum::routing::post(move || async move {
        if status != 200 {
            return (
                StatusCode::from_u16(status).unwrap(),
                axum::Json(json!({ "error": { "message": "scripted failure" } })),
            );
        }

        let answer = json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-test-2026-09-30",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "{\"line\":\"L1\",\"description\":\"Listed files\"}" },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30 }
        });
        (StatusCode::OK, axum::Json(answer))
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    format!("http://{addr}/v1/")
}

fn assert_rfc3339(value: &Value) {
    let text = value.as_str().unwrap_or_else(|| panic!("not a string: {value}"));
    OffsetDateTime::parse(text, &Rfc3339).unwrap_or_else(|error| panic!("{text}: {error}"));
}

#[tokio::test]
async fn start_returns_202_then_200_for_the_same_request() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = Uuid::new_v4();

    let (status, created) = harness.post(session_id, &request(task_id, "gpt-test")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    assert_eq!(created["id"], task_id.to_string());
    assert_eq!(created["kind"], "recording-ai-analysis");
    assert_eq!(created["target"], session_id.to_string());
    assert_eq!(
        created["params"],
        json!({ "provider": "openai", "model": "gpt-test", "maxOutputTokens": null })
    );
    assert_eq!(created["state"], "queued");
    assert_eq!(created["payload"], Value::Null);
    assert_eq!(created["attempts"], 0);
    assert_rfc3339(&created["createdAt"]);
    assert_rfc3339(&created["deadlineAt"]);
    assert_eq!(created["startedAt"], Value::Null);
    assert_eq!(created["finishedAt"], Value::Null);

    let (status, again) = harness.post(session_id, &request(task_id, "gpt-test")).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again, created);
}

#[tokio::test]
async fn start_conflicts_return_409_with_a_code() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = Uuid::new_v4();
    harness.post(session_id, &request(task_id, "gpt-test")).await;

    let (status, body) = harness.post(session_id, &request(task_id, "gpt-other")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({ "code": "task_id_conflict" }));

    let (status, body) = harness.post(session_id, &request(Uuid::new_v4(), "gpt-test")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({ "code": "analysis_in_progress", "taskId": task_id }));
}

#[tokio::test]
async fn start_without_recording_returns_404() {
    let harness = Harness::new().await;

    let (status, _) = harness.post(Uuid::new_v4(), &request(Uuid::new_v4(), "gpt-test")).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_bodies_and_settings_return_400() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = Uuid::new_v4();

    let mut unknown_field = request(task_id, "gpt-test");
    unknown_field["temperature"] = json!(0.5);

    let mut no_key = request(task_id, "gpt-test");
    no_key.as_object_mut().unwrap().remove("apiKey");

    let mut empty_key = request(task_id, "gpt-test");
    empty_key["apiKey"] = json!("");

    let mut no_base_url = request(task_id, "gpt-test");
    no_base_url["provider"] = json!("openai-compatible");

    let mut bad_base_url = request(task_id, "gpt-test");
    bad_base_url["baseUrl"] = json!("ftp://ai.example/v1/");

    let mut unknown_provider = request(task_id, "gpt-test");
    unknown_provider["provider"] = json!("skynet");

    for (case, body) in [
        ("unknown field", unknown_field.to_string()),
        ("missing API key", no_key.to_string()),
        ("empty API key", empty_key.to_string()),
        ("empty model", request(task_id, " ").to_string()),
        ("missing base URL", no_base_url.to_string()),
        ("unsupported base URL", bad_base_url.to_string()),
        ("unknown provider", unknown_provider.to_string()),
        ("not JSON", "{".to_owned()),
    ] {
        let (status, _) = harness
            .post_raw(session_id, "gateway.tasks.recording-ai-analysis.start", body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{case}");
    }

    let (status, _) = harness
        .get_analysis(session_id, task_id, "gateway.tasks.recording-ai-analysis.read")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no Task is recorded");
}

#[tokio::test]
async fn endpoints_require_their_scope() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let body = request(Uuid::new_v4(), "gpt-test").to_string();

    for scope in [
        "gateway.tasks.recording-ai-analysis.read",
        "gateway.recording.delete",
        "gateway.recordings.read",
    ] {
        let (status, _) = harness.post_raw(session_id, scope, body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{scope}");
    }

    for scope in ["gateway.tasks.recording-ai-analysis.start", "gateway.sessions.read"] {
        let (status, _) = harness.get_analysis(session_id, Uuid::new_v4(), scope).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{scope}");
    }

    let (status, _) = harness.post_raw(session_id, "*", body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the wildcard scope is accepted");

    let (status, _) = harness.get_analysis(session_id, Uuid::new_v4(), "*").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the wildcard scope is accepted");
}

#[tokio::test]
async fn an_analysis_is_found_at_its_location_only() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = Uuid::new_v4();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/jet/jrec/{session_id}/ai-analysis"))
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", scope_token("gateway.tasks.recording-ai-analysis.start")),
        )
        .body(Body::from(request(task_id, "gpt-test").to_string()))
        .unwrap();

    let response = harness.app.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(location, format!("/jet/jrec/{session_id}/ai-analysis/{task_id}"));

    let (status, task) = harness
        .get_analysis(session_id, task_id, "gateway.tasks.recording-ai-analysis.read")
        .await;
    assert_eq!(status, StatusCode::OK, "{task}");
    assert_eq!(task["id"], task_id.to_string());

    let (status, _) = harness
        .get_analysis(Uuid::new_v4(), task_id, "gateway.tasks.recording-ai-analysis.read")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "not under another session");

    // A Task of another kind is not an AI analysis, whatever the scope.
    let now = OffsetDateTime::now_utc();
    let other_kind = Uuid::new_v4();
    harness
        .task_store
        .create(
            provisioner_task::NewProvisionerTaskRecord {
                id: other_kind,
                kind: "test.other-kind".to_owned(),
                target: session_id.to_string(),
                params: json!({}),
                deadline_at: now + time::Duration::hours(1),
                job_token: Uuid::new_v4(),
            },
            now,
        )
        .await
        .unwrap();
    let (status, _) = harness.get_analysis(session_id, other_kind, "*").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn get_analysis_returns_404_for_an_unknown_id() {
    let harness = Harness::new().await;

    let (status, _) = harness
        .get_analysis(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "gateway.tasks.recording-ai-analysis.read",
        )
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn analysis_succeeds_without_leaking_the_key_or_the_base_url() {
    let logs = LogBuffer::default();
    let _guard = tracing_subscriber::fmt()
        .with_writer({
            let logs = logs.clone();
            move || logs.clone()
        })
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .set_default();

    let mut harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = Uuid::new_v4();
    let base_url = spawn_ai_provider(200).await;

    let body = json!({
        "taskId": task_id,
        "provider": "openai-compatible",
        "model": "gpt-test",
        "baseUrl": base_url,
        "maxOutputTokens": 1000,
        "apiKey": API_KEY,
    });

    let (status, created) = harness.post(session_id, &body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");

    harness.run_queued_job().await;

    let (status, task) = harness
        .get_analysis(session_id, task_id, "gateway.tasks.recording-ai-analysis.read")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(task["state"], "succeeded", "{task}");
    assert_eq!(task["attempts"], 1);
    assert_eq!(task["payload"]["fileName"], "ai-analysis-0.slog");
    assert_eq!(task["payload"]["model"], "gpt-test-2026-09-30");
    assert_eq!(
        task["payload"]["usage"],
        json!({ "inputTokens": 10, "outputTokens": 20 })
    );
    assert_rfc3339(&task["startedAt"]);
    assert_rfc3339(&task["finishedAt"]);

    let (status, again) = harness.post(session_id, &body).await;
    assert_eq!(status, StatusCode::OK, "{again}");

    let responses = [created, task, again].map(|body| body.to_string()).join("\n");
    let logs = logs.text();
    let database = String::from_utf8_lossy(&harness.database_bytes()).into_owned();
    assert!(!database.is_empty(), "gateway.db is read");
    assert!(logs.contains("Task succeeded"), "logs are captured");

    for secret in [API_KEY, base_url.as_str()] {
        assert!(!responses.contains(secret), "{secret} in a response");
        assert!(!logs.contains(secret), "{secret} in the logs");
        assert!(!database.contains(secret), "{secret} in gateway.db");
    }
}

#[tokio::test]
async fn provider_refusing_the_key_fails_the_task() {
    let mut harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = Uuid::new_v4();
    let base_url = spawn_ai_provider(401).await;

    let body = json!({
        "taskId": task_id,
        "provider": "openai-compatible",
        "model": "gpt-test",
        "baseUrl": base_url,
        "apiKey": API_KEY,
    });
    let (status, _) = harness.post(session_id, &body).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    harness.run_queued_job().await;

    let (status, task) = harness
        .get_analysis(session_id, task_id, "gateway.tasks.recording-ai-analysis.read")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(task["state"], "failed", "{task}");
    assert_eq!(task["payload"]["reason"], "permanent error");
    assert_eq!(task["payload"]["attempts"], 1);

    let (status, _) = harness.post(session_id, &request(Uuid::new_v4(), "gpt-test")).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "a failed analysis no longer blocks the session"
    );
}
