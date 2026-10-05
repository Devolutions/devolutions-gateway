use axum::body::Bytes;
use axum::extract::{self, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{TaskToken, TasksReadScope};
use crate::tasks::recording_ai_analysis::RecordingAiAnalysisTask;
use crate::tasks::{TaskErrorCode, TaskService, TaskSnapshot, TaskStatus};
use crate::token::TaskSpec;

#[derive(Clone)]
pub(crate) struct TasksState {
    gateway: DgwState,
    tasks: TaskService,
}

pub fn make_router<S>(state: DgwState, tasks: TaskService) -> Router<S> {
    Router::new()
        .route("/", routing::post(start_task))
        .route("/{id}", routing::get(get_task))
        .with_state(TasksState { gateway: state, tasks })
}

/// Starts a background task.
///
/// The TASK token holds the whole task: its kind, and the payload of that kind.
/// The token is not encrypted, so the request body carries the secrets of the kind: `RecordingAiAnalysisCredentials` for `recording.ai-analysis`.
///
/// This endpoint is unstable: it is only available when `__debug__.enable_unstable` is set.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "StartTask",
    tag = "Tasks",
    path = "/jet/tasks",
    request_body(content = Object, description = "Secrets of the task kind, such as `RecordingAiAnalysisCredentials` for `recording.ai-analysis`", content_type = "application/json"),
    responses(
        (status = 202, description = "Task was accepted and runs in the background", body = TaskInfo),
        (status = 400, description = "Invalid task or request body", body = TaskErrorResponse),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 409, description = "The task target is busy, such as a session that is still recording", body = TaskErrorResponse),
        (status = 500, description = "Unexpected server error", body = TaskErrorResponse),
    ),
    security(("task_token" = [])),
))]
pub(crate) async fn start_task(
    State(state): State<TasksState>,
    TaskToken(claims): TaskToken,
    body: Bytes,
) -> Result<(StatusCode, Json<TaskInfo>), TaskErrorCode> {
    let snapshot = match claims.jet_task {
        TaskSpec::RecordingAiAnalysis(payload) => {
            state
                .tasks
                .start_ephemeral::<RecordingAiAnalysisTask>(&state.gateway, payload, &body, claims.jti)
                .await?
        }
    };

    Ok((StatusCode::ACCEPTED, Json(TaskInfo::from(snapshot))))
}

/// Gets the status of a background task.
///
/// Task records are kept forever, including across Gateway restarts.
///
/// This endpoint is unstable: it is only available when `__debug__.enable_unstable` is set.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetTask",
    tag = "Tasks",
    path = "/jet/tasks/{id}",
    params(
        ("id" = Uuid, Path, description = "Task ID"),
    ),
    responses(
        (status = 200, description = "Task status", body = TaskInfo),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "No task with this ID", body = TaskErrorResponse),
        (status = 500, description = "Unexpected server error", body = TaskErrorResponse),
    ),
    security(("scope_token" = ["gateway.tasks.read"])),
))]
pub(crate) async fn get_task(
    State(state): State<TasksState>,
    _scope: TasksReadScope,
    extract::Path(id): extract::Path<Uuid>,
) -> Result<Json<TaskInfo>, TaskErrorCode> {
    let snapshot = state.tasks.get(id).await.map_err(|error| {
        error!(task.id = %id, error = format!("{error:#}"), "Failed to read the task");
        TaskErrorCode::Internal
    })?;

    snapshot
        .map(|snapshot| Json(TaskInfo::from(snapshot)))
        .ok_or(TaskErrorCode::TaskNotFound)
}

/// A background task and its status.
///
/// `substate` is set only when `state` is `running`, `result` only when it is `success`, and `error` only when it is `failed`.
/// Both `substate` and `result` are kind-specific: for `recording.ai-analysis`, `substate` is an `RecordingAiAnalysisSubstate`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaskInfo {
    /// Task ID.
    id: Uuid,
    /// Task kind, as in `jet_task.kind` in the TASK token.
    kind: String,
    state: TaskState,
    /// Progress of a running task.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<Object>))]
    #[serde(skip_serializing_if = "Option::is_none")]
    substate: Option<serde_json::Value>,
    /// Result of a successful task.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<Object>))]
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    /// Why the task failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TaskState {
    /// The task waits for a free slot or for its next attempt.
    NotStarted,
    Running,
    Success,
    Failed,
}

impl From<TaskSnapshot> for TaskInfo {
    fn from(snapshot: TaskSnapshot) -> Self {
        let (state, substate, result, error) = match snapshot.status {
            TaskStatus::NotStarted => (TaskState::NotStarted, None, None, None),
            TaskStatus::Running { substate } => (TaskState::Running, Some(substate), None, None),
            TaskStatus::Success { result } => (TaskState::Success, None, Some(result), None),
            TaskStatus::Failed { error } => (TaskState::Failed, None, None, Some(error)),
        };

        Self {
            id: snapshot.id,
            kind: snapshot.kind,
            state,
            substate,
            result,
            error,
        }
    }
}

/// Why a task request failed.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct TaskErrorResponse {
    error: TaskErrorCode,
}

impl IntoResponse for TaskErrorCode {
    fn into_response(self) -> Response {
        let status = match self {
            TaskErrorCode::InvalidRequest
            | TaskErrorCode::MissingModel
            | TaskErrorCode::MissingApiKey
            | TaskErrorCode::MissingBaseUrl
            | TaskErrorCode::InvalidAiSettings => StatusCode::BAD_REQUEST,
            TaskErrorCode::RecordingActive => StatusCode::CONFLICT,
            TaskErrorCode::TaskNotFound => StatusCode::NOT_FOUND,
            TaskErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Server errors are logged where they happen.
        if status.is_client_error() {
            debug!(%status, error = ?self, "Task request rejected");
        }

        (status, Json(TaskErrorResponse { error: self })).into_response()
    }
}
