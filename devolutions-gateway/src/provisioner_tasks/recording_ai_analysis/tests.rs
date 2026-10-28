use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use camino::Utf8Path;
use devolutions_gateway_ai::session_actions::PROMPT_VERSION;
use devolutions_gateway_ai::{Language, session_summary};
use devolutions_gateway_task::ShutdownHandle;
use job_queue::Job as _;
use parking_lot::Mutex;
use provisioner_task::{AttemptStart, NewProvisionerTaskRecord, ProvisionerTaskState};

use super::*;
use crate::job_queue::{JobMessage, JobQueueReceiver};
use crate::provisioner_tasks::runner::{MAX_ATTEMPTS, ProvisionerTaskJob, ProvisionerTaskRunner};
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
        self.start_in(task_id, session_id, settings, None).await
    }

    /// Same as [`Harness::start`], asking for the analysis in `language`.
    async fn start_in(
        &self,
        task_id: Uuid,
        session_id: Uuid,
        settings: AiSettings,
        language: Option<Language>,
    ) -> Result<StartOutcome, StartError> {
        start(
            &self.state,
            StartRequest {
                task_id,
                session_id,
                settings,
                language,
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

    /// The job holding the current token of the Task, for its next attempt, as the job queue would run it.
    async fn job(&self, task_id: Uuid) -> ProvisionerTaskJob {
        // Read as of long ago, so reading never fails the Task in place of the job.
        let record = self
            .state
            .provisioner_tasks
            .store()
            .get(task_id, OffsetDateTime::UNIX_EPOCH)
            .await
            .expect("read task")
            .expect("task exists");
        let json = json!({
            "taskId": task_id,
            "jobToken": record.job_token,
            "step": { "attempt": record.attempts + 1 },
        })
        .to_string();

        ProvisionerTaskJob::read_json(&json, self.state.provisioner_tasks.clone()).expect("valid job")
    }

    /// Records the success of the first attempt of the Task without ending it, as if Gateway stopped right after.
    async fn record_success(&self, task_id: Uuid) {
        let store = self.state.provisioner_tasks.store();
        let now = OffsetDateTime::now_utc();
        let job_token = store
            .get(task_id, now)
            .await
            .expect("read task")
            .expect("task exists")
            .job_token;

        let started = store
            .start_attempt(task_id, job_token, 1, json!({}), now + time::Duration::hours(1), now)
            .await
            .expect("start the attempt");
        assert!(matches!(started, AttemptStart::Started(_)), "{started:?}");
        assert!(
            store
                .succeed(task_id, json!({}), now)
                .await
                .expect("record the success")
        );
    }

    async fn run(&self, task_id: Uuid) -> anyhow::Result<()> {
        self.job(task_id).await.run().await
    }

    /// Takes every queued job.
    fn queued_jobs(&mut self) -> Vec<JobMessage> {
        std::iter::from_fn(|| self.job_queue_rx.try_recv().ok()).collect()
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

    /// Runs the Tasks with an AI analysis that fails after `progress_timeout` without progress.
    fn with_progress_timeout(&mut self, progress_timeout: time::Duration) {
        let mut task = RecordingAiAnalysis::new(
            self.state.conf_handle.clone(),
            self.state.recordings.clone(),
            self.state.secrets.clone(),
        );
        task.progress_timeout = progress_timeout;
        self.state.provisioner_tasks = ProvisionerTaskRunner::builder(
            Arc::clone(self.state.provisioner_tasks.store()),
            Arc::new(self.state.job_queue_handle.clone()),
        )
        .register(task)
        .build();
    }

    /// Working files of the AI analyses of session_id.
    fn workspace(&self, session_id: Uuid) -> Utf8PathBuf {
        self.recording_path.join(session_id.to_string()).join(".ai-analysis")
    }

    fn access(&self, task_id: Uuid) -> Option<AiAccess> {
        self.state
            .secrets
            .get(SecretId(task_id))
            .expect("read the secret")
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
            .secrets
            .insert(SecretId(task_id), &access.to_secret().expect("secret"), expires_at)
            .expect("insert the secret");
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

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Secrets
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
    assert_eq!(task.deadline_at - task.created_at, START_WINDOW);

    let access = harness.access(task_id).expect("key is kept");
    assert_eq!(access.base_url.expect("base URL").as_str(), "https://ai.example/v1/");

    let JobMessage { job, schedule_for } = harness.job_queue_rx.try_recv().expect("job queued");
    assert_eq!(job.name(), ProvisionerTaskJob::NAME);
    assert_eq!(
        job.write_json().expect("job JSON"),
        format!(
            r#"{{"taskId":"{task_id}","jobToken":"{}","step":{{"attempt":1}}}}"#,
            task.job_token
        )
    );
    assert!(schedule_for.is_none());
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
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

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
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

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
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

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
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

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
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

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn retry_resumes_at_the_first_chunk_without_a_checkpoint() {
    let mut harness = Harness::new().await;
    // About 1 MB of transcript: three chunks.
    let session_id = harness.write_long_session(10_000);
    let (settings, requests) = spawn_ai_provider(|index| if index == 1 { 503 } else { 0 }).await;
    let task_id = harness.start_created(session_id, settings).await;
    let workspace = harness.workspace(session_id);

    harness
        .run(task_id)
        .await
        .expect("the job queues the next attempt itself");
    // oracle: mutant a recoverable failure is retried at once, without the delay a busy provider asks for
    assert!(
        harness.queued_jobs().iter().any(|job| job.schedule_for.is_some()),
        "a provider outage is retried"
    );

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Running);
    assert_eq!(
        task.payload,
        json!({
            "step": "describing",
            "done": 1,
            "total": 3,
            "usage": { "inputTokens": 10, "outputTokens": 20, "unreportedRequests": 0 },
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
            "usage": { "inputTokens": 40, "outputTokens": 80, "unreportedRequests": 0 },
            "promptVersion": format!("{PROMPT_VERSION}+{}", session_summary::PROMPT_VERSION),
        }),
        "every attempt counts, and the refused request costs nothing"
    );

    let requests = requests.lock().clone();
    assert_eq!(
        requests.len(),
        5,
        "only chunks 1 and 2 are sent again, then the summary"
    );
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

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn permanent_error_fails_without_retry() {
    let harness = Harness::new().await;
    let session_id = harness.write_long_session(10);
    let (settings, requests) = spawn_ai_provider(|_| 401).await;
    let task_id = harness.start_created(session_id, settings).await;

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(
        task.payload,
        json!({
            "error": { "kind": "aiRejected", "status": 401 },
            "usage": { "inputTokens": 0, "outputTokens": 0, "unreportedRequests": 0 },
        })
    );
    assert_eq!(task.attempts, 1);
    assert_eq!(requests.lock().len(), 1);
    assert!(!harness.workspace(session_id).exists());
    assert!(!harness.has_key(task_id));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
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
    assert_eq!(task.payload["error"], json!({ "kind": "mixedRecording" }));
}

// oracle: mutant a recording deleted after the Task starts fails it as internal instead of noRecording
#[tokio::test]
async fn recording_deleted_after_start_fails() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = harness.start_created(session_id, openai("gpt-test")).await;
    std::fs::remove_dir_all(harness.recording_path.join(session_id.to_string())).expect("delete the recording");

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "noRecording" }));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn transient_errors_fail_the_task_once_attempts_are_exhausted() {
    let mut harness = Harness::new().await;
    let session_id = harness.write_long_session(10);
    let (settings, requests) = spawn_ai_provider(|_| 503).await;
    let task_id = harness.start_created(session_id, settings).await;

    for attempt in 1..MAX_ATTEMPTS {
        harness
            .run(task_id)
            .await
            .expect("the job queues the next attempt itself");
        // oracle: mutant a recoverable failure is retried at once, without the delay a busy provider asks for
        assert!(
            harness.queued_jobs().iter().any(|job| job.schedule_for.is_some()),
            "attempt {attempt} is retried"
        );
        assert_eq!(harness.task(task_id).await.state, ProvisionerTaskState::Running);
    }

    harness.run(task_id).await.expect("the last attempt is not retried");
    assert!(harness.queued_jobs().is_empty(), "no attempt after the last");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.attempts, MAX_ATTEMPTS);
    assert_eq!(
        task.payload["error"],
        json!({ "kind": "attemptsExhausted", "last": { "kind": "aiBusy", "status": 503 } })
    );
    assert_eq!(requests.lock().len(), 5);
    assert!(!harness.workspace(session_id).exists());
    assert!(!harness.has_key(task_id));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn an_analysis_without_progress_fails_at_its_deadline() {
    let mut harness = Harness::new().await;
    let session_id = harness.write_long_session(10);

    // A provider that never answers stops the progress of the analysis.
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
    harness.with_progress_timeout(time::Duration::seconds(2));

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    // oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
    assert_eq!(
        task.payload,
        json!({
            "error": { "kind": "deadlinePassed" },
            "usage": { "inputTokens": 0, "outputTokens": 0, "unreportedRequests": 1 },
        }),
        "the request cut off at the deadline may have cost tokens"
    );
    assert!(!harness.workspace(session_id).exists());
    assert!(!harness.has_key(task_id));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn lost_key_fails_the_task() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = harness.start_created(session_id, openai("gpt-test")).await;
    std::fs::create_dir_all(harness.workspace(session_id)).expect("workspace");

    // A restart keeps `gateway.db` and the job queue, but not the keys held in memory.
    harness.state.secrets.remove(SecretId(task_id));

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(
        task.payload,
        json!({
            "error": { "kind": "keyLost" },
            "usage": { "inputTokens": 0, "outputTokens": 0, "unreportedRequests": 0 },
        })
    );
    assert!(!harness.workspace(session_id).exists());
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
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
    assert_eq!(
        task.payload,
        json!({ "error": { "kind": "deadlinePassed" } }),
        "a Task that never ran spent nothing"
    );
    assert_eq!(task.attempts, 0);
    assert!(!harness.has_key(task_id));
    assert!(!harness.workspace(session_id).exists());
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §Management
#[tokio::test]
async fn finished_task_does_not_run_again() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, requests) = spawn_ai_provider(|_| 401).await;
    let task_id = harness.start_created(session_id, settings).await;

    harness.run(task_id).await.expect("first run");
    let asked = requests.lock().len();
    harness.run(task_id).await.expect("second run");

    assert_eq!(harness.task(task_id).await.attempts, 1);
    assert_eq!(requests.lock().len(), asked, "the AI is not asked again");
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
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

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
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
// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_new_task_replaces_the_result_of_the_earlier_one() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, _requests) = spawn_ai_provider(|_| 0).await;
    let first = harness.start_created(session_id, settings.clone()).await;
    harness.run(first).await.expect("first analysis");

    let second = harness.start_created(session_id, settings).await;
    harness.run(second).await.expect("second analysis");

    let task = harness.task(second).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded, "{:?}", task.payload);
    assert_eq!(task.payload["fileName"], "ai-analysis-0.slog");
    let dir = harness.recording_path.join(session_id.to_string());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("recording.json")).expect("manifest")).expect("manifest JSON");
    assert_eq!(
        manifest["artifacts"]["ai-analysis"],
        json!([{ "fileName": "ai-analysis-0.slog" }]),
        "one analysis per recording"
    );
    assert!(!dir.join("ai-analysis-1.slog").exists());
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_new_task_that_fails_keeps_the_earlier_analysis() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, _requests) = spawn_ai_provider(|_| 0).await;
    let first = harness.start_created(session_id, settings.clone()).await;
    harness.run(first).await.expect("first analysis");

    let second = harness.start_created(session_id, settings).await;
    harness.state.secrets.remove(SecretId(second));
    harness.run(second).await.expect("no retry");

    let task = harness.task(second).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(task.payload["error"], json!({ "kind": "keyLost" }));
    let dir = harness.recording_path.join(session_id.to_string());
    assert_eq!(ai_analyses(&dir), json!([{ "fileName": "ai-analysis-0.slog" }]));
    assert!(dir.join("ai-analysis-0.slog").exists());
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_restart_fails_an_unfinished_analysis_at_once_and_ends_it() {
    let harness = Harness::new().await;
    // About 1 MB of transcript: three chunks, so the first attempt stops with the tokens of one.
    let session_id = harness.write_long_session(10_000);
    let (settings, requests) = spawn_ai_provider(|index| if index == 1 { 503 } else { 0 }).await;
    let task_id = harness.start_created(session_id, settings).await;
    harness
        .run(task_id)
        .await
        .expect("the job queues the next attempt itself");
    // As if Gateway stopped after an attempt wrote its log, before its success was recorded.
    let dir = harness.recording_path.join(session_id.to_string());
    let log = dir.join(format!(".ai-analysis-{task_id}.slog"));
    std::fs::write(&log, "an analysis whose success was never recorded").expect("unlisted log");

    harness.state.provisioner_tasks.resume().await.expect("resume");

    let task = harness.task(task_id).await;
    // oracle: mutant an AI analysis that cannot run after a restart stays unfinished until its next attempt
    assert_eq!(task.state, ProvisionerTaskState::Failed, "no job ran yet");
    assert_eq!(task.payload["error"], json!({ "kind": "keyLost" }));
    // oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
    assert_eq!(
        task.payload["usage"],
        json!({ "inputTokens": 10, "outputTokens": 20, "unreportedRequests": 0 })
    );

    harness.run(task_id).await.expect("the new job only ends the Task");
    assert_eq!(requests.lock().len(), 2, "the AI is not asked again");
    assert!(!harness.workspace(session_id).exists(), "the working files are removed");
    assert!(!log.exists(), "the unlisted log is removed");
    assert_eq!(ai_analyses(&dir), json!([]));
    assert!(!harness.has_key(task_id));
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn a_failed_task_reports_the_tokens_it_spent() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    // The chunk is answered, then the provider refuses the summary request for good.
    let (settings, _requests) = spawn_ai_provider(|index| if index == 1 { 401 } else { 0 }).await;
    let task_id = harness.start_created(session_id, settings).await;

    harness.run(task_id).await.expect("no retry");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Failed);
    assert_eq!(
        task.payload["usage"],
        json!({ "inputTokens": 10, "outputTokens": 20, "unreportedRequests": 0 })
    );
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_task_that_fails_removes_its_unlisted_log() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = harness.start_created(session_id, openai("gpt-test")).await;
    let dir = harness.recording_path.join(session_id.to_string());
    let log = dir.join(format!(".ai-analysis-{task_id}.slog"));
    std::fs::write(&log, "an analysis whose success was never recorded").expect("unlisted log");
    harness
        .state
        .provisioner_tasks
        .store()
        .fail(task_id, json!({}), OffsetDateTime::now_utc())
        .await
        .expect("fail the Task");

    harness.run(task_id).await.expect("the job ends the Task");

    assert!(!log.exists());
    assert_eq!(ai_analyses(&dir), json!([]));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_success_cut_short_before_the_log_is_listed_is_finished_at_startup() {
    let mut harness = Harness::new().await;
    let session_id = harness.write_session();
    let task_id = harness.start_created(session_id, openai("gpt-test")).await;
    harness.queued_jobs();

    // As if Gateway stopped right after recording the success, before the manifest listed the log.
    let dir = harness.recording_path.join(session_id.to_string());
    let log = dir.join(format!(".ai-analysis-{task_id}.slog"));
    std::fs::write(&log, "an analysis whose log was never listed").expect("unlisted log");
    harness.record_success(task_id).await;

    harness.state.provisioner_tasks.resume().await.expect("resume");
    for JobMessage { mut job, .. } in harness.queued_jobs() {
        job.run().await.expect("the job ends the Task");
    }

    assert_eq!(ai_analyses(&dir), json!([{ "fileName": "ai-analysis-0.slog" }]));
    assert!(dir.join("ai-analysis-0.slog").exists());
    assert!(!log.exists());
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_late_end_of_an_earlier_task_never_lists_its_log_over_a_newer_analysis() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, _requests) = spawn_ai_provider(|_| 0).await;
    let first = harness.start_created(session_id, settings.clone()).await;

    // As if the end of the first Task failed before the manifest listed its log, so it is done again later.
    let dir = harness.recording_path.join(session_id.to_string());
    let first_log = dir.join(format!(".ai-analysis-{first}.slog"));
    std::fs::write(&first_log, "the analysis of the first Task").expect("unlisted log");
    harness.record_success(first).await;

    let second = harness.start_created(session_id, settings).await;
    harness.run(second).await.expect("second analysis");
    let newer = std::fs::read_to_string(dir.join("ai-analysis-0.slog")).expect("newer analysis");

    harness.run(first).await.expect("the late end of the first Task");

    assert_eq!(ai_analyses(&dir), json!([{ "fileName": "ai-analysis-0.slog" }]));
    assert_eq!(
        std::fs::read_to_string(dir.join("ai-analysis-0.slog")).expect("analysis"),
        newer
    );
    assert!(!first_log.exists());
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_new_task_that_fails_keeps_an_earlier_success_whose_log_was_not_listed_yet() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, _requests) = spawn_ai_provider(|_| 0).await;
    let first = harness.start_created(session_id, settings.clone()).await;
    harness.run(first).await.expect("first analysis");

    // As if the end of the first Task failed before the manifest listed its log, so it is done again later.
    let dir = harness.recording_path.join(session_id.to_string());
    std::fs::remove_file(dir.join("ai-analysis-0.slog")).expect("unlist the log");
    std::fs::write(
        dir.join(format!(".ai-analysis-{first}.slog")),
        "the analysis of the first Task",
    )
    .expect("unlisted log");
    let manifest_path = dir.join("recording.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest")).expect("manifest JSON");
    manifest["artifacts"] = json!({});
    std::fs::write(&manifest_path, manifest.to_string()).expect("manifest");

    let second = harness.start_created(session_id, settings).await;
    harness.state.secrets.remove(SecretId(second));
    harness.run(second).await.expect("no retry");
    assert_eq!(harness.task(second).await.state, ProvisionerTaskState::Failed);

    harness.run(first).await.expect("the late end of the first Task");

    assert_eq!(ai_analyses(&dir), json!([{ "fileName": "ai-analysis-0.slog" }]));
    assert_eq!(
        std::fs::read_to_string(dir.join("ai-analysis-0.slog")).expect("analysis"),
        "the analysis of the first Task"
    );
}

// oracle: mutant the log left unlisted by a Task that has no record is kept
#[tokio::test]
async fn a_new_task_removes_a_log_left_unlisted_by_an_unknown_task() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let dir = harness.recording_path.join(session_id.to_string());
    let unknown_log = dir.join(format!(".ai-analysis-{}.slog", Uuid::new_v4()));
    std::fs::write(&unknown_log, "an analysis whose success was never recorded").expect("unlisted log");
    let (settings, _requests) = spawn_ai_provider(|_| 401).await;
    let task_id = harness.start_created(session_id, settings).await;

    harness.run(task_id).await.expect("no retry");

    assert!(!unknown_log.exists());
    assert_eq!(ai_analyses(&dir), json!([]));
}

/// The AI analyses the manifest in `dir` lists.
fn ai_analyses(dir: &Utf8Path) -> serde_json::Value {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("recording.json")).expect("manifest")).expect("manifest JSON");
    manifest["artifacts"]
        .get("ai-analysis")
        .cloned()
        .unwrap_or_else(|| json!([]))
}

// oracle: intent devolutions-gateway/src/api/jrec.intent.md §AI analysis
#[tokio::test]
async fn the_analysis_is_in_the_language_of_the_request() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, requests) = spawn_ai_provider(|_| 0).await;
    let task_id = Uuid::new_v4();
    let language = Language::new("fr-CA").expect("language");

    let outcome = harness
        .start_in(task_id, session_id, settings.clone(), Some(language.clone()))
        .await
        .expect("started");
    assert!(matches!(outcome, StartOutcome::Created(_)), "{outcome:?}");
    harness.run(task_id).await.expect("analysis");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded, "{:?}", task.payload);
    assert_eq!(task.params["language"], "fr-CA");
    assert!(requests.lock().iter().all(|request| request.contains("`fr-CA`")));

    let other = harness
        .start_in(
            task_id,
            session_id,
            settings,
            Some(Language::new("de-DE").expect("language")),
        )
        .await
        .expect("started");
    assert!(
        matches!(other, StartOutcome::IdConflict(_)),
        "the same Task ID with another language is another request: {other:?}"
    );
}

// oracle: intent crates/devolutions-gateway-ai/INTENT.md §Analyze Recording
#[tokio::test]
async fn the_analysis_is_in_english_without_a_language() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, requests) = spawn_ai_provider(|_| 0).await;
    let task_id = harness.start_created(session_id, settings).await;

    harness.run(task_id).await.expect("analysis");

    let task = harness.task(task_id).await;
    assert_eq!(task.state, ProvisionerTaskState::Succeeded, "{:?}", task.payload);
    assert!(task.params.get("language").is_none(), "{}", task.params);
    assert!(requests.lock().iter().all(|request| request.contains("`English`")));
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn a_new_task_never_resumes_from_an_earlier_task() {
    let harness = Harness::new().await;
    // About 1 MB of transcript: three chunks.
    let session_id = harness.write_long_session(10_000);
    let (settings, requests) = spawn_ai_provider(|index| if index == 1 { 503 } else { 0 }).await;
    let first = harness.start_created(session_id, settings.clone()).await;
    harness
        .run(first)
        .await
        .expect("the job queues the next attempt itself");
    assert!(harness.workspace(session_id).join("chunk-0000.json").exists());
    harness
        .state
        .provisioner_tasks
        .store()
        .fail(first, json!({}), OffsetDateTime::now_utc())
        .await
        .expect("end the first Task");

    let second = harness.start_created(session_id, settings).await;
    harness.run(second).await.expect("second analysis");

    assert_eq!(harness.task(second).await.state, ProvisionerTaskState::Succeeded);
    assert_eq!(
        requests.lock().len(),
        2 + 3 + 1,
        "the new Task asks about every chunk again, then for the summary"
    );
}

// oracle: intent devolutions-gateway/src/provisioner_tasks/INTENT.md §AI analysis
#[tokio::test]
async fn an_ended_task_leaves_the_working_files_of_another_task() {
    let harness = Harness::new().await;
    let session_id = harness.write_session();
    let (settings, _requests) = spawn_ai_provider(|_| 0).await;
    let task_id = harness.start_created(session_id, settings).await;
    let workspace = harness.workspace(session_id);
    std::fs::create_dir_all(&workspace).expect("working files of a newer Task");
    std::fs::write(
        workspace.join("analysis.json"),
        json!({
            "owner": Uuid::new_v4().to_string(),
            "promptVersion": "p",
            "model": "m",
            "language": "English",
            "chunkLen": 1,
        })
        .to_string(),
    )
    .expect("settings of a newer Task");
    let record = harness.task(task_id).await;
    let task = RecordingAiAnalysis::new(
        harness.state.conf_handle.clone(),
        harness.state.recordings.clone(),
        harness.state.secrets.clone(),
    );

    task.on_end(&record).await.expect("end");

    assert!(workspace.exists(), "the newer Task still resumes from them");
    assert!(!harness.has_key(task_id));
}
