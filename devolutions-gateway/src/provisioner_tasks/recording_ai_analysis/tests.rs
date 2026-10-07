use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use camino::Utf8Path;
use devolutions_gateway_ai::session_actions::PROMPT_VERSION;
use devolutions_gateway_task::ShutdownHandle;
use job_queue::Job as _;
use parking_lot::Mutex;
use provisioner_task::{NewProvisionerTaskRecord, ProvisionerTaskState};

use super::*;
use crate::job_queue::{JobMessage, JobQueueReceiver, MAX_ATTEMPTS};
use crate::provisioner_tasks::runner::{ProvisionerTaskJob, ProvisionerTaskRunner};
use crate::recording::RecordingManagerTask;
use crate::{DgwState, MockHandles};

const API_KEY: &str = "sk-recording-ai-analysis-test-secret";

fn config(recording_path: &Utf8Path) -> String {
    json!({
        "ProvisionerPublicKeyData": {
            "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
        },
        "Listeners": [{ "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" }],
        "Proxy": { "Mode": "Off" },
        "RecordingPath": recording_path,
    })
    .to_string()
}

fn openai(model: &str) -> AiSettings {
    AiSettings {
        provider: AiProvider::OpenAi,
        model: model.to_owned(),
        base_url: None,
        max_output_tokens: None,
    }
}

struct Harness {
    state: DgwState,
    job_queue_rx: JobQueueReceiver,
    recording_path: Utf8PathBuf,
    _keep: Box<dyn Send>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let recording_path = Utf8PathBuf::from_path_buf(dir.path().join("recordings")).expect("UTF-8");

        let (state, handles) = DgwState::mock(&config(&recording_path)).await.expect("mock state");
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

        Self {
            state,
            job_queue_rx,
            recording_path,
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

    async fn start(&self, task_id: Uuid, session_id: Uuid, settings: AiSettings) -> Result<StartOutcome, StartError> {
        start(
            &self.state,
            StartRequest {
                task_id,
                session_id,
                settings,
                api_key: SecretString::from(API_KEY),
            },
        )
        .await
    }

    /// Starts an AI analysis of `session_id` and returns its Task ID.
    async fn start_created(&self, session_id: Uuid, settings: AiSettings) -> Uuid {
        let task_id = Uuid::new_v4();
        let outcome = self.start(task_id, session_id, settings).await.expect("started");
        assert!(matches!(outcome, StartOutcome::Created(_)), "{outcome:?}");
        task_id
    }

    /// The job holding the current token of the Task, as the job queue would run it.
    async fn job(&self, task_id: Uuid) -> ProvisionerTaskJob {
        // Read as of long ago, so reading never fails the Task in place of the job.
        let job_token = self
            .state
            .provisioner_tasks
            .store()
            .get(task_id, OffsetDateTime::UNIX_EPOCH)
            .await
            .expect("read task")
            .expect("task exists")
            .job_token
            .expect("job token");
        let json = json!({ "taskId": task_id, "jobToken": job_token }).to_string();

        ProvisionerTaskJob::read_json(&json, self.state.provisioner_tasks.clone()).expect("valid job")
    }

    async fn run(&self, task_id: Uuid) -> anyhow::Result<()> {
        self.job(task_id).await.run().await
    }

    /// Records a Task directly, as if it was created at `created_at`.
    async fn create_task(
        &self,
        task_id: Uuid,
        session_id: Uuid,
        provider: &str,
        created_at: OffsetDateTime,
        deadline_at: OffsetDateTime,
    ) {
        self.state
            .provisioner_tasks
            .store()
            .create(
                NewProvisionerTaskRecord {
                    id: task_id,
                    kind: KIND.to_owned(),
                    target: session_id.to_string(),
                    params: json!({ "provider": provider, "model": "gpt-test", "maxOutputTokens": null }),
                    deadline_at,
                    job_token: Uuid::new_v4(),
                },
                created_at,
            )
            .await
            .expect("create");
    }

    async fn task(&self, task_id: Uuid) -> ProvisionerTaskRecord {
        self.state
            .provisioner_tasks
            .get(task_id, OffsetDateTime::now_utc())
            .await
            .expect("read task")
            .expect("task exists")
    }

    /// Working files of the AI analyses of session_id.
    fn workspace(&self, session_id: Uuid) -> Utf8PathBuf {
        self.recording_path.join(session_id.to_string()).join(".ai-analysis")
    }

    fn access(&self, task_id: Uuid) -> Option<AiAccess> {
        self.state
            .provisioning
            .task_secret(task_id)
            .expect("read the task secret")
            .map(|secret| AiAccess::from_secret(&secret).expect("AI access"))
    }

    fn has_key(&self, task_id: Uuid) -> bool {
        self.access(task_id).is_some()
    }

    /// Hands `task_id` an API key directly, as `start` does.
    fn insert_key(&self, task_id: Uuid, base_url: Option<url::Url>, expires_at: OffsetDateTime) {
        let access = AiAccess {
            api_key: SecretString::from(API_KEY),
            base_url,
        };
        self.state
            .provisioning
            .insert_task_secret(task_id, &access.to_secret().expect("secret"), expires_at)
            .expect("insert the task secret");
    }

    /// Writes a finished session with a short terminal recording.
    fn write_session(&self) -> Uuid {
        self.write_long_session(10)
    }

    /// Writes a finished session whose terminal output is `lines` lines of about 100 bytes each.
    fn write_long_session(&self, lines: usize) -> Uuid {
        let session_id = Uuid::new_v4();
        let dir = self.recording_path.join(session_id.to_string());
        std::fs::create_dir_all(&dir).expect("session dir");

        let manifest = json!({
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
}

/// A mock OpenAI-compatible provider: `status` picks the answer of the n-th request, 0 being a valid answer.
async fn spawn_ai_provider(
    status: impl Fn(usize) -> u16 + Send + Sync + 'static,
) -> (AiSettings, Arc<Mutex<Vec<String>>>) {
    spawn_ai_provider_after(Duration::ZERO, status).await
}

/// Like [`spawn_ai_provider`], answering each request after `delay`.
async fn spawn_ai_provider_after(
    delay: Duration,
    status: impl Fn(usize) -> u16 + Send + Sync + 'static,
) -> (AiSettings, Arc<Mutex<Vec<String>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let status = Arc::new(status);

    let app = axum::Router::new().fallback(axum::routing::post({
        let requests = Arc::clone(&requests);
        move |body: String| {
            let requests = Arc::clone(&requests);
            let status = Arc::clone(&status);
            async move {
                tokio::time::sleep(delay).await;

                let index = {
                    let mut requests = requests.lock();
                    requests.push(body);
                    requests.len() - 1
                };

                let answer = json!({
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "gpt-test-2026-09-30",
                    "choices": [{
                        "index": 0,
                        "message": { "role": "assistant", "content": format!("{{\"line\":\"L1\",\"description\":\"Step {index}\"}}") },
                        "finish_reason": "stop"
                    }],
                    "usage": { "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30 }
                });

                match status(index) {
                    0 => (StatusCode::OK, axum::Json(answer)),
                    code => (
                        StatusCode::from_u16(code).expect("valid status"),
                        axum::Json(json!({ "error": { "message": "scripted failure" } })),
                    ),
                }
            }
        }
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let settings = AiSettings {
        provider: AiProvider::OpenAiCompatible,
        model: "gpt-test".to_owned(),
        base_url: Some(format!("http://{addr}/v1/").parse().expect("URL")),
        max_output_tokens: None,
    };

    (settings, requests)
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
async fn start_records_the_task_keeps_the_key_and_queues_a_job() {
    let mut harness = Harness::new().await;
    let task_id = Uuid::new_v4();
    let session_id = harness.write_session();
    let mut settings = openai("gpt-test");
    settings.base_url = Some("https://ai.example/v1/".parse().expect("URL"));

    let StartOutcome::Created(task) = harness.start(task_id, session_id, settings).await.expect("started") else {
        panic!("task must be created");
    };

    assert_eq!(task.id, task_id);
    assert_eq!(task.kind, KIND);
    assert_eq!(task.target, session_id.to_string());
    assert_eq!(task.state, ProvisionerTaskState::Queued);
    assert_eq!(
        task.params,
        json!({ "provider": "openai", "model": "gpt-test", "maxOutputTokens": null }),
        "neither the key nor the base URL is recorded"
    );
    assert_eq!(task.deadline_at - task.created_at, TASK_DEADLINE);

    let access = harness.access(task_id).expect("key is kept");
    assert_eq!(access.base_url.expect("base URL").as_str(), "https://ai.example/v1/");

    let JobMessage { job, schedule_for } = harness.job_queue_rx.try_recv().expect("job queued");
    assert_eq!(job.name(), ProvisionerTaskJob::NAME);
    assert_eq!(
        job.write_json().expect("job JSON"),
        format!(
            r#"{{"taskId":"{task_id}","jobToken":"{}"}}"#,
            task.job_token.expect("job token")
        )
    );
    assert!(schedule_for.is_none());
}

#[tokio::test]
async fn asking_again_creates_nothing_new() {
    let mut harness = Harness::new().await;
    let task_id = Uuid::new_v4();
    let session_id = harness.write_session();
    harness
        .start(task_id, session_id, openai("gpt-test"))
        .await
        .expect("started");
    harness.job_queue_rx.try_recv().expect("first job");

    let same = harness
        .start(task_id, session_id, openai("gpt-test"))
        .await
        .expect("same request");
    assert!(
        matches!(same, StartOutcome::Existing(ref task) if task.id == task_id),
        "{same:?}"
    );

    let other_params = harness
        .start(task_id, session_id, openai("gpt-other"))
        .await
        .expect("other parameters");
    assert!(matches!(other_params, StartOutcome::IdConflict(_)), "{other_params:?}");

    let busy = harness
        .start(Uuid::new_v4(), session_id, openai("gpt-test"))
        .await
        .expect("other task");
    assert_eq!(
        busy,
        StartOutcome::TargetBusy {
            active_task_id: task_id
        }
    );

    assert!(harness.job_queue_rx.try_recv().is_err(), "no other job is queued");
    assert!(harness.has_key(task_id), "the first key stays");
}

#[tokio::test]
async fn asking_again_returns_the_task_even_while_the_session_records_again() {
    let mut harness = Harness::new().await;
    let task_id = Uuid::new_v4();
    let session_id = harness.write_session();
    harness
        .start(task_id, session_id, openai("gpt-test"))
        .await
        .expect("started");
    harness.job_queue_rx.try_recv().expect("first job");
    harness.state.recordings.active_recordings.insert(session_id);

    let same = harness
        .start(task_id, session_id, openai("gpt-test"))
        .await
        .expect("same request");
    assert!(matches!(same, StartOutcome::Existing(_)), "{same:?}");

    let other_params = harness
        .start(task_id, session_id, openai("gpt-other"))
        .await
        .expect("other parameters");
    assert!(matches!(other_params, StartOutcome::IdConflict(_)), "{other_params:?}");

    let new_task = harness.start(Uuid::new_v4(), session_id, openai("gpt-test")).await;
    assert!(matches!(new_task, Err(StartError::RecordingActive)), "{new_task:?}");
}

#[tokio::test]
async fn refuses_a_session_without_recording() {
    let harness = Harness::new().await;
    let task_id = Uuid::new_v4();

    let error = harness
        .start(task_id, Uuid::new_v4(), openai("gpt-test"))
        .await
        .expect_err("no recording");

    assert!(matches!(error, StartError::RecordingNotFound), "{error:?}");
    assert!(
        harness
            .state
            .provisioner_tasks
            .get(task_id, OffsetDateTime::now_utc())
            .await
            .expect("read")
            .is_none()
    );
    assert!(!harness.has_key(task_id));
}

#[tokio::test]
async fn refuses_a_session_that_is_still_recording() {
    let harness = Harness::new().await;
    let task_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    harness.state.recordings.active_recordings.insert(session_id);

    let error = harness
        .start(task_id, session_id, openai("gpt-test"))
        .await
        .expect_err("still recording");

    assert!(matches!(error, StartError::RecordingActive), "{error:?}");
    assert!(
        harness
            .state
            .provisioner_tasks
            .get(task_id, OffsetDateTime::now_utc())
            .await
            .expect("read")
            .is_none()
    );
}

#[tokio::test]
async fn refuses_invalid_ai_settings() {
    let harness = Harness::new().await;
    let task_id = Uuid::new_v4();

    let error = harness
        .start(task_id, Uuid::new_v4(), openai(" "))
        .await
        .expect_err("empty model");
    assert!(
        matches!(error, StartError::InvalidSettings(AiSettingsError::MissingModel)),
        "{error:?}"
    );

    let mut no_base_url = openai("gpt-test");
    no_base_url.provider = AiProvider::OpenAiCompatible;
    let error = harness
        .start(task_id, Uuid::new_v4(), no_base_url)
        .await
        .expect_err("no base URL");
    assert!(
        matches!(error, StartError::InvalidSettings(AiSettingsError::MissingBaseUrl)),
        "{error:?}"
    );

    assert!(!harness.has_key(task_id));
}

#[tokio::test]
async fn retry_resumes_at_the_first_chunk_without_a_checkpoint() {
    let harness = Harness::new().await;
    // About 1 MB of transcript: three chunks.
    let session_id = harness.write_long_session(10_000);
    let (settings, requests) = spawn_ai_provider(|index| if index == 1 { 503 } else { 0 }).await;
    let task_id = harness.start_created(session_id, settings).await;
    let workspace = harness.workspace(session_id);

    assert!(harness.run(task_id).await.is_err(), "a provider outage is retried");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Running);
    assert_eq!(
        task.payload,
        json!({
            "step": "describing",
            "done": 1,
            "total": 3,
            "percent": 33,
            "message": "asking the AI: 1 of 3 chunks described",
        })
    );
    assert!(harness.has_key(task_id), "the key is kept for the retry");
    let plan: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(workspace.join("plan.json")).expect("plan")).expect("plan JSON");
    assert_eq!(plan.len(), 3, "three transcript chunks");
    assert!(workspace.join("chunk-0000.json").exists());
    assert!(!workspace.join("chunk-0001.json").exists());
    let chunk_starts = (0..3)
        .map(|index| first_line(&workspace.join(format!("transcript-{index:04}.txt"))))
        .collect::<Vec<_>>();
    assert_eq!(requests.lock().len(), 2);

    harness.run(task_id).await.expect("second attempt succeeds");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded, "{:?}", task.payload);
    assert_eq!(task.attempts, 2);
    assert_eq!(
        task.payload,
        json!({
            "fileName": "ai-analysis-0.slog",
            "model": "gpt-test-2026-09-30",
            "usage": { "inputTokens": 30, "outputTokens": 60 },
            "promptVersion": PROMPT_VERSION,
        }),
        "chunk 0 counts from its checkpoint, the failed request not at all"
    );

    let requests = requests.lock().clone();
    assert_eq!(requests.len(), 4, "only chunks 1 and 2 are sent again");
    for (request, chunk) in requests.iter().zip([0, 1, 1, 2]) {
        assert!(request.contains(&chunk_starts[chunk]), "request for chunk {chunk}");
    }
    assert!(requests.iter().all(|request| !request.contains(API_KEY)));

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
    assert!(!harness.has_key(task_id), "the key is dropped on success");
}

#[tokio::test]
async fn permanent_error_fails_without_retry() {
    let harness = Harness::new().await;
    let session_id = harness.write_long_session(10);
    let (settings, requests) = spawn_ai_provider(|_| 401).await;
    let task_id = harness.start_created(session_id, settings).await;

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["reason"], "permanent error");
    assert!(
        task.payload["details"].as_str().expect("details").contains("401"),
        "{}",
        task.payload
    );
    assert_eq!(task.payload["attempts"], 1);
    assert_eq!(requests.lock().len(), 1);
    assert!(!harness.workspace(session_id).exists());
    assert!(!harness.has_key(task_id));
}

#[tokio::test]
async fn a_session_mixing_terminal_and_video_fails() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let manifest_path = harness
        .recording_path
        .join(session_id.to_string())
        .join("recording.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest")).expect("manifest JSON");
    manifest["files"]
        .as_array_mut()
        .expect("files")
        .push(json!({ "fileName": "recording-1.webm", "startTime": 1_787_255_035, "duration": 1 }));
    std::fs::write(&manifest_path, manifest.to_string()).expect("manifest");
    let task_id = harness.start_created(session_id, openai("gpt-test")).await;

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["reason"], "permanent error");
    assert_eq!(task.payload["details"], "session mixes terminal and video recordings");
}
#[tokio::test]
async fn recording_deleted_after_start_fails() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = harness.start_created(session_id, openai("gpt-test")).await;
    std::fs::remove_dir_all(harness.recording_path.join(session_id.to_string())).expect("delete the recording");

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["details"], "session has no recording");
}

#[tokio::test]
async fn transient_errors_fail_the_task_once_attempts_are_exhausted() {
    let harness = Harness::new().await;
    let session_id = harness.write_long_session(10);
    let (settings, requests) = spawn_ai_provider(|_| 503).await;
    let task_id = harness.start_created(session_id, settings).await;

    for attempt in 1..MAX_ATTEMPTS {
        assert!(harness.run(task_id).await.is_err(), "attempt {attempt} is retried");
        assert_eq!(harness.task(task_id).await.state, ProvisionerTaskState::Running);
    }

    harness.run(task_id).await.expect("the last attempt is not retried");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.attempts, MAX_ATTEMPTS);
    assert_eq!(task.payload["reason"], "attempts exhausted");
    assert!(
        task.payload["details"].as_str().expect("details").contains("503"),
        "{}",
        task.payload
    );
    assert_eq!(requests.lock().len(), 5);
    assert!(!harness.workspace(session_id).exists());
    assert!(!harness.has_key(task_id));
}

#[tokio::test]
async fn slow_attempt_is_retried() {
    let mut harness = Harness::new().await;
    let session_id = harness.write_long_session(10);

    // A provider that never answers makes the attempt outlast its timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        while let Ok((connection, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _connection = connection;
                std::future::pending::<()>().await;
            });
        }
    });
    let settings = AiSettings {
        provider: AiProvider::OpenAiCompatible,
        model: "gpt-test".to_owned(),
        base_url: Some(format!("http://{addr}/v1/").parse().expect("URL")),
        max_output_tokens: None,
    };
    let task_id = harness.start_created(session_id, settings).await;

    let mut task = RecordingAiAnalysis::new(
        harness.state.conf_handle.clone(),
        harness.state.recordings.clone(),
        harness.state.provisioning.clone(),
    );
    task.attempt_timeout = Duration::from_millis(500);
    harness.state.provisioner_tasks = ProvisionerTaskRunner::builder(
        Arc::clone(harness.state.provisioner_tasks.store()),
        harness.state.job_queue_handle.clone(),
    )
    .register(task)
    .build();

    let error = harness.run(task_id).await.expect_err("timeout is retried");

    assert!(error.to_string().contains("took longer than"), "{error:#}");
    assert_eq!(harness.task(task_id).await.state, ProvisionerTaskState::Running);
    assert!(harness.has_key(task_id));
    assert!(
        harness.workspace(session_id).join("plan.json").exists(),
        "the chunks are kept for the retry"
    );
}

#[tokio::test]
async fn log_added_after_the_deadline_leaves_the_task_failed() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, _requests) = spawn_ai_provider_after(Duration::from_secs(4), |_| 0).await;
    let task_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    harness
        .create_task(
            task_id,
            session_id,
            "openai-compatible",
            now,
            now + time::Duration::seconds(2),
        )
        .await;
    harness.insert_key(task_id, settings.base_url, now + time::Duration::hours(1));

    let mut job = harness.job(task_id).await;
    let job = tokio::spawn(async move { job.run().await });

    // Reading the Task past its deadline, as a status request does, ends it while the AI is still answering.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(harness.task(task_id).await.state, ProvisionerTaskState::Failed);

    job.await.expect("job task").expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["reason"], "timed out");
    assert!(
        harness
            .recording_path
            .join(session_id.to_string())
            .join("ai-analysis-0.slog")
            .exists(),
        "the log stays in the session"
    );
    assert!(!harness.workspace(session_id).exists());
    assert!(!harness.has_key(task_id));
}

#[tokio::test]
async fn lost_key_fails_the_task() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = harness.start_created(session_id, openai("gpt-test")).await;
    std::fs::create_dir_all(harness.workspace(session_id)).expect("workspace");

    // A restart keeps `gateway.db` and the job queue, but not the keys held in memory.
    harness.state.provisioning.remove_task_secret(task_id);

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(
        task.payload,
        json!({ "reason": "key lost", "details": KEY_LOST, "attempts": 1 })
    );
    assert!(!harness.workspace(session_id).exists());
}

#[tokio::test]
async fn overdue_task_does_not_run() {
    let harness = Harness::new().await;
    let task_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    harness
        .create_task(
            task_id,
            session_id,
            "openai",
            now - time::Duration::hours(2),
            now - time::Duration::seconds(1),
        )
        .await;
    harness.insert_key(task_id, None, now + time::Duration::hours(1));
    std::fs::create_dir_all(harness.workspace(session_id)).expect("workspace");

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["reason"], "timed out");
    assert_eq!(task.attempts, 0);
    assert!(!harness.has_key(task_id));
    assert!(!harness.workspace(session_id).exists());
}

#[tokio::test]
async fn finished_task_does_not_run_again() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, _requests) = spawn_ai_provider(|_| 401).await;
    let task_id = harness.start_created(session_id, settings).await;

    harness.run(task_id).await.expect("first run");
    std::fs::create_dir_all(harness.workspace(session_id)).expect("workspace left behind");
    harness.run(task_id).await.expect("second run");

    assert_eq!(harness.task(task_id).await.attempts, 1);
    assert!(
        !harness.workspace(session_id).exists(),
        "a job that finds its Task finished deletes the workspace"
    );
}

#[tokio::test]
async fn analyses_of_one_session_run_one_at_a_time() {
    let session_id = Uuid::new_v4();
    let first = lock_session(session_id).await;

    let other_session = tokio::time::timeout(Duration::from_secs(1), lock_session(Uuid::new_v4())).await;
    assert!(other_session.is_ok(), "another session is not blocked");

    let second = tokio::spawn(lock_session(session_id));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!second.is_finished(), "the second analysis waits");

    drop(first);
    tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("the second analysis goes on")
        .expect("lock task");
}

#[tokio::test]
async fn working_files_left_by_an_earlier_task_go_with_the_task_that_ends() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, _requests) = spawn_ai_provider(|_| 401).await;
    let task_id = harness.start_created(session_id, settings).await;
    std::fs::create_dir_all(harness.workspace(session_id)).expect("working files of a crashed analysis");
    let log = harness
        .recording_path
        .join(session_id.to_string())
        .join(".ai-analysis.slog");
    std::fs::write(&log, "never moved").expect("log of a crashed analysis");

    harness.run(task_id).await.expect("no retry");

    assert_eq!(harness.task(task_id).await.state, ProvisionerTaskState::Failed);
    assert!(!harness.workspace(session_id).exists());
    assert!(!log.exists());
}
#[test]
fn unknown_usage_is_left_out_of_the_result() {
    let analysis = Analysis {
        file_name: "ai-analysis-0.slog".to_owned(),
        model: "gpt-test-2026-09-30".to_owned(),
        usage: None,
        prompt_version: PROMPT_VERSION.to_owned(),
    };

    assert_eq!(
        json!(analysis),
        json!({
            "fileName": "ai-analysis-0.slog",
            "model": "gpt-test-2026-09-30",
            "promptVersion": PROMPT_VERSION,
        })
    );
}
