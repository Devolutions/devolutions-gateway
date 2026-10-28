//! `/jet/tasks/recording-ai-analysis/{taskId}` tests, against a running Gateway and a mock AI provider.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine as _;
use reqwest::StatusCode;
use serde_json::{Value, json};
use testsuite::cli::start_dgw;
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle, ProxyMode, VerbosityProfile};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;
use uuid::Uuid;

const API_KEY: &str = "sk-ai-analysis-endpoint-test-secret";
const START_SCOPE: &str = "gateway.tasks.recording-ai-analysis.start";
const READ_SCOPE: &str = "gateway.tasks.recording-ai-analysis.read";

/// An unsigned scope token; the Gateway under test runs with token validation disabled.
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

struct Gateway {
    config: DgwConfigHandle,
    process: tokio::process::Child,
    client: reqwest::Client,
}

impl Drop for Gateway {
    // The config folder is deleted right after, and Windows can't delete the files Gateway still holds open.
    fn drop(&mut self) {
        let _ = self.process.start_kill();
        let deadline = Instant::now() + Duration::from_secs(10);
        while matches!(self.process.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Gateway {
    async fn start() -> Self {
        let config = DgwConfig::builder()
            .disable_token_validation(true)
            .verbosity_profile(VerbosityProfile::ALL)
            .proxy_mode(ProxyMode::Off)
            .build()
            .init()
            .unwrap();
        let process = start_dgw(&config).await.unwrap();

        Self {
            config,
            process,
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.config.http_port())
    }

    /// Writes a finished session with one terminal recording in the default recording folder.
    fn write_session(&self) -> Uuid {
        let session_id = Uuid::new_v4();
        let dir = self.config.config_dir().join("recordings").join(session_id.to_string());
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

    async fn put_raw(&self, task_id: Uuid, scope: &str, body: String) -> reqwest::Response {
        self.client
            .put(self.url(&format!("/jet/tasks/recording-ai-analysis/{task_id}")))
            .header("content-type", "application/json")
            .bearer_auth(scope_token(scope))
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn put(&self, task_id: Uuid, body: &Value) -> (StatusCode, Value) {
        read(self.put_raw(task_id, START_SCOPE, body.to_string()).await).await
    }

    async fn get_analysis(&self, task_id: Uuid, scope: &str) -> (StatusCode, Value) {
        let response = self
            .client
            .get(self.url(&format!("/jet/tasks/recording-ai-analysis/{task_id}")))
            .bearer_auth(scope_token(scope))
            .send()
            .await
            .unwrap();
        read(response).await
    }

    /// Asks for the analysis until it has succeeded or failed.
    async fn finished_analysis(&self, task_id: Uuid) -> Value {
        let deadline = Instant::now() + Duration::from_secs(60);

        loop {
            let (status, task) = self.get_analysis(task_id, READ_SCOPE).await;
            assert_eq!(status, StatusCode::OK, "{task}");

            if task["state"] == "succeeded" || task["state"] == "failed" {
                return task;
            }

            assert!(Instant::now() < deadline, "the analysis did not finish: {task}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Reads the log files until they contain `text`, as the Gateway writes them in the background.
    async fn logs_containing(&self, text: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);

        loop {
            let logs = self
                .files(|name| name.starts_with("gateway") && name.ends_with(".log"))
                .map(|path| std::fs::read_to_string(path).unwrap())
                .collect::<String>();

            if logs.contains(text) {
                return logs;
            }

            assert!(Instant::now() < deadline, "no {text:?} in the logs");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// `gateway.db` and its write-ahead log, where the Tasks are recorded.
    fn database_bytes(&self) -> Vec<u8> {
        self.files(|name| name == "gateway.db" || name == "gateway.db-wal")
            .flat_map(|path| std::fs::read(path).unwrap())
            .collect()
    }

    fn files(&self, keep: impl Fn(&str) -> bool) -> impl Iterator<Item = PathBuf> {
        std::fs::read_dir(self.config.config_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(move |path| path.file_name().and_then(|name| name.to_str()).is_some_and(&keep))
    }
}

async fn read(response: reqwest::Response) -> (StatusCode, Value) {
    let status = response.status();
    let body = response.bytes().await.unwrap();
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, body)
}

fn request(session_id: Uuid, model: &str, base_url: &str) -> Value {
    json!({
        "sessionId": session_id,
        "provider": "openai-compatible",
        "model": model,
        "baseUrl": base_url,
        "apiKey": API_KEY,
    })
}

/// A mock AI provider that never answers, so an analysis started against it stays in progress.
async fn spawn_silent_ai_provider() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await;
            });
        }
    });

    format!("http://{addr}/v1/")
}

/// A mock OpenAI-compatible provider answering every request with one action, or with `status` when it is not 200.
async fn spawn_ai_provider(status: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();

            tokio::spawn(async move {
                let mut stream = BufReader::new(stream);
                let mut content_length = 0;

                loop {
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    let line = line.trim_end();

                    if line.is_empty() {
                        break;
                    }

                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap();
                    }
                }

                let mut body = vec![0; content_length];
                stream.read_exact(&mut body).await.unwrap();

                let answer = if status == 200 {
                    json!({
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
                    })
                } else {
                    json!({ "error": { "message": "scripted failure" } })
                }
                .to_string();

                let response = format!(
                    "HTTP/1.1 {status} Scripted\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                stream.get_mut().write_all(response.as_bytes()).await.unwrap();
            });
        }
    });

    format!("http://{addr}/v1/")
}

fn assert_rfc3339(value: &Value) {
    let text = value.as_str().unwrap_or_else(|| panic!("not a string: {value}"));
    OffsetDateTime::parse(text, &Rfc3339).unwrap_or_else(|error| panic!("{text}: {error}"));
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn start_returns_202_then_200_for_the_same_request() {
    let gateway = Gateway::start().await;
    let session_id = gateway.write_session();
    let task_id = Uuid::new_v4();
    let base_url = spawn_silent_ai_provider().await;

    let (status, created) = gateway.put(task_id, &request(session_id, "gpt-test", &base_url)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    assert_eq!(created["id"], task_id.to_string());
    assert_eq!(created["sessionId"], session_id.to_string());
    assert_eq!(
        created["params"],
        json!({ "provider": "openai-compatible", "model": "gpt-test", "maxOutputTokens": null })
    );
    assert_eq!(created["state"], "queued");
    assert_eq!(created["payload"], Value::Null);
    assert_rfc3339(&created["createdAt"]);
    assert_rfc3339(&created["deadlineAt"]);
    assert_eq!(created["startedAt"], Value::Null);
    assert_eq!(created["finishedAt"], Value::Null);
    for internal in ["kind", "target", "attempts"] {
        assert!(created.get(internal).is_none(), "{internal} is not returned");
    }

    let (status, again) = gateway.put(task_id, &request(session_id, "gpt-test", &base_url)).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    // The job may have started meanwhile, so only the fields a run leaves alone are compared.
    for field in ["id", "sessionId", "params", "createdAt"] {
        assert_eq!(again[field], created[field], "{field}");
    }
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn start_conflicts_return_409_with_a_code() {
    let gateway = Gateway::start().await;
    let session_id = gateway.write_session();
    let task_id = Uuid::new_v4();
    let base_url = spawn_silent_ai_provider().await;
    gateway.put(task_id, &request(session_id, "gpt-test", &base_url)).await;

    let (status, body) = gateway.put(task_id, &request(session_id, "gpt-other", &base_url)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({ "code": "task_id_conflict" }));

    let (status, body) = gateway
        .put(task_id, &request(gateway.write_session(), "gpt-test", &base_url))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "the same Task ID for another session");
    assert_eq!(body, json!({ "code": "task_id_conflict" }));

    let (status, body) = gateway
        .put(Uuid::new_v4(), &request(session_id, "gpt-test", &base_url))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({ "code": "analysis_in_progress", "taskId": task_id }));
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn start_without_recording_returns_404() {
    let gateway = Gateway::start().await;
    let base_url = spawn_silent_ai_provider().await;

    let (status, _) = gateway
        .put(Uuid::new_v4(), &request(Uuid::new_v4(), "gpt-test", &base_url))
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn start_ignores_unknown_fields() {
    let gateway = Gateway::start().await;
    let session_id = gateway.write_session();
    let base_url = spawn_silent_ai_provider().await;
    let mut body = request(session_id, "gpt-test", &base_url);
    body["temperature"] = json!(0.5);

    let (status, created) = gateway.put(Uuid::new_v4(), &body).await;

    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn invalid_bodies_and_settings_return_400() {
    let gateway = Gateway::start().await;
    let session_id = gateway.write_session();
    let task_id = Uuid::new_v4();
    let base_url = spawn_silent_ai_provider().await;
    let valid = request(session_id, "gpt-test", &base_url);

    let mut no_session = valid.clone();
    no_session.as_object_mut().unwrap().remove("sessionId");

    let mut no_key = valid.clone();
    no_key.as_object_mut().unwrap().remove("apiKey");

    let mut empty_key = valid.clone();
    empty_key["apiKey"] = json!("");

    let mut no_base_url = valid.clone();
    no_base_url.as_object_mut().unwrap().remove("baseUrl");

    let mut bad_base_url = valid.clone();
    bad_base_url["baseUrl"] = json!("ftp://ai.example/v1/");

    let mut unknown_provider = valid.clone();
    unknown_provider["provider"] = json!("skynet");

    let mut long_language = valid.clone();
    long_language["language"] = json!("zh-Hant-TW-x");

    let mut empty_language = valid.clone();
    empty_language["language"] = json!("");

    for (case, body) in [
        ("missing session ID", no_session.to_string()),
        ("missing API key", no_key.to_string()),
        ("empty API key", empty_key.to_string()),
        ("empty model", request(session_id, " ", &base_url).to_string()),
        ("missing base URL", no_base_url.to_string()),
        ("unsupported base URL", bad_base_url.to_string()),
        ("unknown provider", unknown_provider.to_string()),
        ("language longer than 10 characters", long_language.to_string()),
        ("empty language", empty_language.to_string()),
        ("not JSON", "{".to_owned()),
    ] {
        let response = gateway.put_raw(task_id, START_SCOPE, body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
    }

    let (status, _) = gateway.get_analysis(task_id, READ_SCOPE).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no Task is recorded");
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn endpoints_require_their_scope() {
    let gateway = Gateway::start().await;
    let session_id = gateway.write_session();
    let base_url = spawn_silent_ai_provider().await;
    let body = request(session_id, "gpt-test", &base_url).to_string();

    for scope in [READ_SCOPE, "gateway.recording.delete", "gateway.recordings.read"] {
        let response = gateway.put_raw(Uuid::new_v4(), scope, body.clone()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{scope}");
    }

    for scope in [START_SCOPE, "gateway.sessions.read", "gateway.recordings.read"] {
        let (status, _) = gateway.get_analysis(Uuid::new_v4(), scope).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{scope}");
    }

    let response = gateway.put_raw(Uuid::new_v4(), "*", body).await;
    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "the wildcard scope is accepted"
    );

    let (status, _) = gateway.get_analysis(Uuid::new_v4(), "*").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the wildcard scope is accepted");
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn an_analysis_is_found_at_its_location() {
    let gateway = Gateway::start().await;
    let session_id = gateway.write_session();
    let task_id = Uuid::new_v4();
    let base_url = spawn_silent_ai_provider().await;

    let response = gateway
        .put_raw(
            task_id,
            START_SCOPE,
            request(session_id, "gpt-test", &base_url).to_string(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(location, format!("/jet/tasks/recording-ai-analysis/{task_id}"));

    let (status, task) = gateway.get_analysis(task_id, READ_SCOPE).await;
    assert_eq!(status, StatusCode::OK, "{task}");
    assert_eq!(task["id"], task_id.to_string());
    assert_eq!(task["sessionId"], session_id.to_string());
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn get_analysis_returns_404_for_an_unknown_id() {
    let gateway = Gateway::start().await;

    let (status, _) = gateway.get_analysis(Uuid::new_v4(), READ_SCOPE).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Secrets
#[tokio::test]
async fn analysis_succeeds_without_leaking_the_key_or_the_base_url() {
    let gateway = Gateway::start().await;
    let session_id = gateway.write_session();
    let task_id = Uuid::new_v4();
    let base_url = spawn_ai_provider(200).await;
    let mut body = request(session_id, "gpt-test", &base_url);
    body["maxOutputTokens"] = json!(1000);

    let (status, created) = gateway.put(task_id, &body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");

    let task = gateway.finished_analysis(task_id).await;
    assert_eq!(task["state"], "succeeded", "{task}");
    assert_eq!(task["payload"]["fileName"], "ai-analysis-0.slog");
    assert_eq!(task["payload"]["model"], "gpt-test-2026-09-30");
    // oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
    assert_eq!(
        task["payload"]["usage"],
        json!({ "inputTokens": 20, "outputTokens": 40, "unreportedRequests": 0 }),
        "one request for the actions, one for the summary"
    );
    assert_rfc3339(&task["startedAt"]);
    assert_rfc3339(&task["finishedAt"]);

    let (status, again) = gateway.put(task_id, &body).await;
    assert_eq!(status, StatusCode::OK, "{again}");

    let responses = [created, task, again].map(|body| body.to_string()).join("\n");
    let logs = gateway.logs_containing("Task succeeded").await;
    let database = String::from_utf8_lossy(&gateway.database_bytes()).into_owned();
    assert!(!database.is_empty(), "gateway.db is read");

    for secret in [API_KEY, base_url.as_str()] {
        assert!(!responses.contains(secret), "{secret} in a response");
        assert!(!logs.contains(secret), "{secret} in the logs");
        assert!(!database.contains(secret), "{secret} in gateway.db");
    }
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn provider_refusing_the_key_fails_the_task() {
    let gateway = Gateway::start().await;
    let session_id = gateway.write_session();
    let task_id = Uuid::new_v4();
    let base_url = spawn_ai_provider(401).await;

    let (status, _) = gateway.put(task_id, &request(session_id, "gpt-test", &base_url)).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let task = gateway.finished_analysis(task_id).await;
    assert_eq!(task["state"], "failed", "{task}");
    assert_eq!(
        task["payload"],
        json!({
            "error": { "kind": "aiRejected", "status": 401 },
            "usage": { "inputTokens": 0, "outputTokens": 0, "unreportedRequests": 0 },
        })
    );

    let (status, _) = gateway
        .put(Uuid::new_v4(), &request(session_id, "gpt-test", &base_url))
        .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "a failed analysis no longer blocks the session"
    );
}
