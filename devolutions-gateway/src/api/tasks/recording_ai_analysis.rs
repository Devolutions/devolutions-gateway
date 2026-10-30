//! `/jet/tasks/recording-ai-analysis/{task_id}`: start and read the AI analysis of a recorded session.

use anyhow::Context as _;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{self, State};
use axum::http::header::{HeaderValue, LOCATION};
use axum::response::{IntoResponse as _, Response};
use devolutions_gateway_ai::Language;
use hyper::StatusCode;
use provisioner_task::ProvisionerTaskRecord;
use secrecy::SecretString;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::TaskState;
use crate::DgwState;
use crate::extract::{RecordingAiAnalysisReadScope, RecordingAiAnalysisStartScope};
use crate::http::HttpError;
use crate::provisioner_tasks::ai::{AiProvider, AiSettings};
use crate::provisioner_tasks::recording_ai_analysis::{self as analysis, StartError, StartOutcome, StartRequest};

/// Settings of an AI analysis
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisRequest {
    /// Recorded session to analyze.
    session_id: Uuid,
    provider: AiProvider,
    /// Model identifier, passed to the provider as is.
    model: String,
    /// Endpoint of the provider API, kept in memory only; required for `openai-compatible`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(default)]
    base_url: Option<Url>,
    /// Upper bound of tokens in each AI answer.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, minimum = 0, maximum = 4_294_967_295_u64))]
    #[serde(default)]
    max_output_tokens: Option<u32>,
    /// Language the AI writes in, any text of 1 to 10 characters such as `fr-CA` or `français`; English when absent.
    #[cfg_attr(feature = "openapi", schema(min_length = 1, max_length = 10))]
    #[serde(default)]
    language: Option<String>,
    /// API key of the provider, kept in memory only until the Task ends.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = Password))]
    api_key: SecretString,
}

/// Why an AI analysis cannot start now
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisConflict {
    code: AiAnalysisConflictCode,
    /// The AI analysis of this session that is not finished yet; set for `analysis_in_progress`.
    #[serde(skip_serializing_if = "Option::is_none")]
    task_id: Option<Uuid>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AiAnalysisConflictCode {
    /// The Task ID is already used by a Task with other parameters.
    TaskIdConflict,
    /// The session is still recording.
    RecordingActive,
    /// Another AI analysis of this session is not finished yet.
    AnalysisInProgress,
}

/// An AI analysis Task: the permanent record of one analysis the provisioner asked for
///
/// The work runs in the background; `state` and `payload` tell how it goes.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisTask {
    /// Task ID, chosen by the provisioner.
    id: Uuid,
    /// Recorded session the analysis is about.
    session_id: Uuid,
    /// What was asked, without the API key and the base URL.
    params: AiAnalysisParams,
    state: TaskState,
    /// Details of the state: progress while `running`, the log once `succeeded`, the reason once `failed`; null while
    /// `queued`.
    payload: Option<AiAnalysisPayload>,
    /// When the Task was created.
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// When its first attempt started.
    #[serde(with = "time::serde::rfc3339::option")]
    started_at: Option<OffsetDateTime>,
    /// When it succeeded or failed.
    #[serde(with = "time::serde::rfc3339::option")]
    finished_at: Option<OffsetDateTime>,
    /// Time at which a Task still unfinished fails; while the Task runs, it moves ahead each time an attempt starts or
    /// the Task makes progress.
    #[serde(with = "time::serde::rfc3339")]
    deadline_at: OffsetDateTime,
}

/// Params of an AI analysis Task: what was asked, without the API key and the base URL
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisParams {
    provider: AiProvider,
    /// Model identifier, passed to the provider as is.
    model: String,
    /// Upper bound of tokens in each AI answer; null when not asked.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, minimum = 0, maximum = 4_294_967_295_u64))]
    max_output_tokens: Option<u32>,
    /// Language the AI writes in; absent when not asked, so the AI writes in English.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    language: Option<String>,
}

/// Details of the state of an AI analysis Task: `running`, `succeeded` and `failed` each have their own
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum AiAnalysisPayload {
    Running(AiAnalysisRunningPayload),
    Succeeded(AiAnalysisSucceededPayload),
    Failed(AiAnalysisFailedPayload),
}

/// Payload of a `running` AI analysis Task: its progress, and the tokens it used so far
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisRunningPayload {
    /// Current step: `preparing` (the attempt starts), `reading` (the recordings are read), `describing` (the AI is
    /// asked about the recording, part by part), then `writing` (the log is written).
    step: String,
    /// Work done in the step: bytes read while `reading`, parts described while `describing`; absent in the other steps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    done: Option<u64>,
    /// Work the step has in all, in the same unit as `done`; absent in the other steps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total: Option<u64>,
    usage: AiAnalysisUsage,
}

/// Payload of a `succeeded` AI analysis Task: the log it put in the session
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisSucceededPayload {
    /// Name of the log in the session manifest, such as `ai-analysis-0.slog`.
    file_name: String,
    /// Model that wrote the log, as reported by the AI provider; the requested model when it reports none.
    model: String,
    usage: AiAnalysisUsage,
    /// Versions of the prompts that wrote the log, such as
    /// `session-actions-3f9a1c2b7e4d0a51+session-summary-8b20e9a4c1f70d36`.
    prompt_version: String,
}

/// Tokens the AI provider counted for an AI analysis Task, over all its attempts
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisUsage {
    input_tokens: u64,
    output_tokens: u64,
    /// Requests that may have cost tokens the provider did not report, such as a request that got no answer, or one
    /// still waiting for it; while it is not 0, `inputTokens` and `outputTokens` are short of what the provider billed.
    unreported_requests: u64,
}

/// Payload of a `failed` AI analysis Task: why it failed, and the tokens it used
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisFailedPayload {
    error: AiAnalysisError,
    /// Absent only for a Task that never ran before its deadline passed, since it used no token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    usage: Option<AiAnalysisUsage>,
}

/// Why an AI analysis Task failed: a kind, with the fields of that kind; there is no text for people, so the caller
/// words it
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisError {
    kind: AiAnalysisErrorKind,
    /// HTTP status the AI provider answered, for `aiRejected`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    /// What was wrong with the answer, for `aiBadAnswer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    why: Option<AiAnalysisBadAnswer>,
    /// Recording file that cannot be read, for `unreadableRecording`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    /// Failure of the last attempt, for `attemptsExhausted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last: Option<AiAnalysisRecoverableError>,
}

/// Kind of failure of an AI analysis Task
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AiAnalysisErrorKind {
    /// The AI provider refused the request for good, such as for a wrong API key (401) or a spent quota.
    AiRejected,
    /// The AI provider answered, but not with something usable.
    AiBadAnswer,
    /// The API key is gone, such as after a Gateway restart.
    KeyLost,
    /// The session has no recording, or it was deleted.
    NoRecording,
    /// The session mixes terminal and video recordings.
    MixedRecording,
    /// A recording file of the session cannot be read.
    UnreadableRecording,
    /// The Task itself is not valid, such as with parameters this Gateway cannot read.
    InvalidTask,
    /// The attempt panicked.
    Panicked,
    /// Something went wrong inside Gateway, such as a file it could not write, or a restart that cut the last attempt
    /// short.
    Internal,
    /// Every attempt failed with a failure worth another attempt.
    AttemptsExhausted,
    /// The Task did not start in time, or went too long without progress.
    DeadlinePassed,
}

/// What was wrong with an answer of the AI provider
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AiAnalysisBadAnswer {
    /// The answer is not in the format of the provider API.
    Invalid,
    /// The answer was cut short by the output token limit or the context window.
    Truncated,
    /// The provider refused to answer, such as when its content filter blocked the request.
    Refused,
    /// The model did not answer in the format it was asked for.
    NotExpectedJson,
}

/// A failure of an attempt that was worth another attempt
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AiAnalysisRecoverableError {
    kind: AiAnalysisRecoverableErrorKind,
    /// HTTP status the AI provider answered, for `aiBusy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
}

/// Kind of a failure worth another attempt
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum AiAnalysisRecoverableErrorKind {
    /// The AI provider could not be reached, or did not answer in time.
    AiUnreachable,
    /// The AI provider is busy or failing for now, such as with a rate limit (429) or a server error (5xx).
    AiBusy,
}

impl TryFrom<ProvisionerTaskRecord> for AiAnalysisTask {
    type Error = anyhow::Error;

    /// The record as the API shows it; a record whose params or payload are not of this shape is an error, so a
    /// Gateway that stored something else never passes it on.
    fn try_from(task: ProvisionerTaskRecord) -> Result<Self, Self::Error> {
        let state = TaskState::from(task.state);
        let payload = match state {
            TaskState::Queued => None,
            TaskState::Running => Some(AiAnalysisPayload::Running(
                serde_json::from_value(task.payload).context("running payload")?,
            )),
            TaskState::Succeeded => Some(AiAnalysisPayload::Succeeded(
                serde_json::from_value(task.payload).context("succeeded payload")?,
            )),
            TaskState::Failed => Some(AiAnalysisPayload::Failed(
                serde_json::from_value(task.payload).context("failed payload")?,
            )),
        };

        Ok(Self {
            id: task.id,
            session_id: Uuid::parse_str(&task.target).context("session ID")?,
            params: serde_json::from_value(task.params).context("params")?,
            state,
            payload,
            created_at: task.created_at,
            started_at: task.started_at,
            finished_at: task.finished_at,
            deadline_at: task.deadline_at,
        })
    }
}

fn task_json(task: ProvisionerTaskRecord) -> Result<Json<AiAnalysisTask>, HttpError> {
    AiAnalysisTask::try_from(task).map(Json).map_err(
        HttpError::internal()
            .with_msg("the AI analysis Task is not of the expected shape")
            .err(),
    )
}

fn ai_analysis_conflict(code: AiAnalysisConflictCode, task_id: Option<Uuid>) -> Response {
    debug!(?code, task.id = ?task_id, "AI analysis refused");
    (StatusCode::CONFLICT, Json(AiAnalysisConflict { code, task_id })).into_response()
}

/// Starts an AI analysis of a recorded session
///
/// Gateway asks the AI provider what the user did in the session recording, and puts the answer in the session as its
/// log, listed under `artifacts.ai-analysis` in its manifest.
/// The answer is in the `language` of the request, English without one.
/// The work runs in the background as a Task; follow it with `GET /jet/tasks/recording-ai-analysis/{task_id}`.
///
/// Sending the same request again returns the same Task and starts nothing new.
/// A new Task for the session starts from scratch, and replaces the earlier AI analysis of the session once its success
/// is recorded, so a session holds at most one; a Task that fails leaves the earlier analysis in place and removes
/// everything it made.
/// A Task fails if it does not start within 2 hours, or, once it runs, after 30 minutes without progress.
/// The API key and the base URL are kept in memory only, until the Task ends; a Gateway restart fails the unfinished
/// Tasks.
#[cfg_attr(feature = "openapi", utoipa::path(
    put,
    operation_id = "StartAiAnalysis",
    tag = "Tasks",
    path = "/jet/tasks/recording-ai-analysis/{task_id}",
    params(
        ("task_id" = Uuid, Path, description = "Task ID, chosen by the caller so it can send the same request again safely"),
    ),
    request_body(content = AiAnalysisRequest, description = "AI analysis settings", content_type = "application/json"),
    responses(
        (status = 200, description = "The same request came in before; nothing new starts", body = AiAnalysisTask),
        (status = 202, description = "The AI analysis Task is created and runs in the background", body = AiAnalysisTask, headers(
            ("Location" = String, description = "Path of the new Task, `/jet/tasks/recording-ai-analysis/{task_id}`"),
        )),
        (status = 400, description = "Invalid request body, AI settings or language", body = ApiError, content_type = "application/problem+json"),
        (status = 401, description = "Invalid or missing authorization token", body = ApiError, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient permissions", body = ApiError, content_type = "application/problem+json"),
        (status = 404, description = "The session has no recording", body = ApiError, content_type = "application/problem+json"),
        (status = 409, description = "The AI analysis cannot start now", body = AiAnalysisConflict),
        (status = 500, description = "Unexpected server error", body = ApiError, content_type = "application/problem+json"),
    ),
    security(("scope_token" = ["gateway.tasks.recording-ai-analysis.start"])),
))]
pub(crate) async fn start_ai_analysis(
    State(state): State<DgwState>,
    _scope: RecordingAiAnalysisStartScope,
    extract::Path(task_id): extract::Path<Uuid>,
    body: Bytes,
) -> Result<Response, HttpError> {
    let request: AiAnalysisRequest = serde_json::from_slice(&body).map_err(|error| {
        // The serde message may quote a value of the body, such as a misplaced API key, so only its place is logged.
        debug!(
            category = ?error.classify(),
            line = error.line(),
            column = error.column(),
            "Invalid AI analysis request body"
        );
        HttpError::bad_request().msg("invalid AI analysis request body")
    })?;

    let AiAnalysisRequest {
        session_id,
        provider,
        model,
        base_url,
        max_output_tokens,
        language,
        api_key,
    } = request;

    let language = language
        .map(Language::new)
        .transpose()
        .map_err(HttpError::bad_request().with_msg("invalid language").err())?;

    let outcome = analysis::start(
        &state,
        StartRequest {
            task_id,
            session_id,
            settings: AiSettings {
                provider,
                model,
                base_url,
                max_output_tokens,
            },
            language,
            api_key,
        },
    )
    .await;

    match outcome {
        Ok(StartOutcome::Created(task)) => {
            let location = HeaderValue::try_from(format!("/jet/tasks/recording-ai-analysis/{}", task.id))
                .map_err(HttpError::internal().with_msg("invalid Location header").err())?;
            Ok((StatusCode::ACCEPTED, [(LOCATION, location)], task_json(task)?).into_response())
        }
        Ok(StartOutcome::Existing(task)) => Ok((StatusCode::OK, task_json(task)?).into_response()),
        Ok(StartOutcome::IdConflict(_)) => Ok(ai_analysis_conflict(AiAnalysisConflictCode::TaskIdConflict, None)),
        Ok(StartOutcome::TargetBusy { active_task_id }) => Ok(ai_analysis_conflict(
            AiAnalysisConflictCode::AnalysisInProgress,
            Some(active_task_id),
        )),
        Err(StartError::RecordingActive) => Ok(ai_analysis_conflict(AiAnalysisConflictCode::RecordingActive, None)),
        Err(StartError::InvalidSettings(error)) => {
            Err(HttpError::bad_request().with_msg("invalid AI settings").build(error))
        }
        Err(StartError::RecordingNotFound) => Err(HttpError::not_found().msg("session has no recording")),
        Err(StartError::Internal(error)) => Err(HttpError::internal()
            .with_msg("failed to start the AI analysis")
            .build(error)),
    }
}

/// Gets an AI analysis of a recorded session
///
/// Returns the Task of the analysis: its state, its progress while it runs, its result once it is over, and the tokens
/// it used in every state but `queued`.
/// Tasks are kept forever, across Gateway restarts; an unfinished Task past its deadline is reported as failed.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetAiAnalysis",
    tag = "Tasks",
    path = "/jet/tasks/recording-ai-analysis/{task_id}",
    params(
        ("task_id" = Uuid, Path, description = "Task ID of the AI analysis"),
    ),
    responses(
        (status = 200, description = "The AI analysis Task", body = AiAnalysisTask),
        (status = 400, description = "Bad request", body = ApiError, content_type = "application/problem+json"),
        (status = 401, description = "Invalid or missing authorization token", body = ApiError, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient permissions", body = ApiError, content_type = "application/problem+json"),
        (status = 404, description = "No AI analysis has this Task ID", body = ApiError, content_type = "application/problem+json"),
        (status = 500, description = "Unexpected server error", body = ApiError, content_type = "application/problem+json"),
    ),
    security(("scope_token" = ["gateway.tasks.recording-ai-analysis.read"])),
))]
pub(crate) async fn get_ai_analysis(
    State(state): State<DgwState>,
    _scope: RecordingAiAnalysisReadScope,
    extract::Path(task_id): extract::Path<Uuid>,
) -> Result<Json<AiAnalysisTask>, HttpError> {
    let task = analysis::get(&state, task_id)
        .await
        .map_err(HttpError::internal().with_msg("failed to read the AI analysis").err())?
        // A Task of another kind is not found under this path.
        .filter(|task| task.kind == analysis::KIND)
        .ok_or_else(|| HttpError::not_found().msg("AI analysis not found"))?;

    task_json(task)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::Body;
    use http_body_util::BodyExt as _;

    use super::*;

    fn record(state: provisioner_task::ProvisionerTaskState, payload: serde_json::Value) -> ProvisionerTaskRecord {
        let now = OffsetDateTime::now_utc();
        ProvisionerTaskRecord {
            id: Uuid::new_v4(),
            kind: analysis::KIND.to_owned(),
            target: Uuid::new_v4().to_string(),
            params: serde_json::json!({ "provider": "openai", "model": "gpt-test", "maxOutputTokens": null }),
            state,
            payload,
            attempts: 0,
            created_at: now,
            started_at: None,
            finished_at: None,
            deadline_at: now,
            job_token: Uuid::new_v4(),
        }
    }

    // oracle: intent devolutions-gateway/src/api/tasks/recording_ai_analysis.intent.md §AI analysis
    #[test]
    fn a_task_failed_before_it_ran_is_shown_without_usage() {
        let record = record(
            provisioner_task::ProvisionerTaskState::Failed,
            serde_json::json!({ "error": { "kind": "deadlinePassed" } }),
        );

        let task = AiAnalysisTask::try_from(record).expect("a failed Task without usage");

        let payload = serde_json::to_value(task.payload).expect("JSON");
        assert_eq!(payload, serde_json::json!({ "error": { "kind": "deadlinePassed" } }));
    }

    // oracle: mutant a payload of another shape is passed on to the caller as it is
    #[test]
    fn a_task_of_another_shape_is_refused() {
        let record = record(
            provisioner_task::ProvisionerTaskState::Succeeded,
            serde_json::json!({ "error": { "kind": "internal" } }),
        );

        let error = AiAnalysisTask::try_from(record).expect_err("a succeeded Task with a failed payload");

        assert!(error.to_string().contains("succeeded payload"), "{error:#}");
    }

    // oracle: intent devolutions-gateway/src/api/tasks/recording_ai_analysis.intent.md §AI analysis
    #[tokio::test]
    async fn ai_analysis_of_a_session_still_recording_is_a_conflict() {
        use axum::extract::connect_info::MockConnectInfo;
        use base64::Engine as _;
        use tower::ServiceExt as _;

        let dir = tempfile::tempdir().expect("temp dir");
        let config = serde_json::json!({
            "ProvisionerPublicKeyData": {
                "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
            },
            "Listeners": [{ "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" }],
            "RecordingPath": dir.path().to_str().expect("UTF-8"),
            "__debug__": { "disable_token_validation": true },
        });
        let (state, handles) = DgwState::mock(&config.to_string()).await.expect("mock state");
        // `start` asks the provisioner task service whether it knows the Task before it looks at the session.
        let conn = gateway_db::GatewayDb::open_path(":memory:")
            .await
            .expect("open gateway database")
            .connect()
            .await
            .expect("connect");
        let store = provisioner_task_libsql::LibSqlProvisionerTaskStore::open(conn)
            .await
            .expect("open task store");
        let service = crate::provisioner_tasks::ProvisionerTaskService::new(
            std::sync::Arc::new(store),
            crate::job_queue::TestJobQueue::new().await,
            handles.provisioner_task_rx,
        );
        let (_service_shutdown, service_shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
        tokio::spawn(devolutions_gateway_task::Task::run(service, service_shutdown_signal));
        let session_id = Uuid::new_v4();
        state.recordings.active_recordings.insert(session_id);
        let app = crate::make_http_service(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 3000))));

        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let claims = serde_json::json!({ "jti": Uuid::new_v4(), "exp": i64::from(u32::MAX), "scope": "gateway.tasks.recording-ai-analysis.start" });
        let token = format!(
            "{}.{}.{}",
            engine.encode(r#"{"alg":"RS256","cty":"SCOPE"}"#),
            engine.encode(claims.to_string()),
            engine.encode(b"signature"),
        );
        let body = serde_json::json!({ "sessionId": session_id, "provider": "openai", "model": "gpt-test", "apiKey": "sk-test" });
        let request = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/jet/tasks/recording-ai-analysis/{}", Uuid::new_v4()))
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .expect("request");

        let response = app.oneshot(request).await.expect("response");

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("JSON"),
            serde_json::json!({ "code": "recording_active" })
        );
    }
}
