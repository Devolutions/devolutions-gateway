use axum::body::Bytes;
use axum::extract::{self, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{TaskToken, TasksReadScope};
use crate::http::HttpError;
#[cfg(feature = "openapi")]
#[expect(unused_imports, reason = "utoipa refers to the request body schema by its name only")]
use crate::tasks::ai_log::AiLogParams;
use crate::tasks::ai_log::{AiLogTarget, AiLogTask};
use crate::tasks::{StartError, TaskSnapshot, TaskStatus};
use crate::token::TaskKind;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/", routing::post(start_task))
        .route("/{id}", routing::get(get_task))
        .with_state(state)
}

/// Starts a background task.
///
/// The task kind and its target come from the TASK token.
/// The request body holds the kind-specific parameters: `AiLogParams` for `ai-log`.
///
/// This endpoint is unstable: it is only available when `__debug__.enable_unstable` is set.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "StartTask",
    tag = "Tasks",
    path = "/jet/tasks",
    request_body(content = AiLogParams, description = "Kind-specific task parameters", content_type = "application/json"),
    responses(
        (status = 202, description = "Task was accepted and runs in the background", body = TaskInfo),
        (status = 400, description = "Invalid task parameters", body = TaskErrorResponse),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 409, description = "The task target is busy, such as a session that is still recording", body = TaskErrorResponse),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("task_token" = [])),
))]
pub(crate) async fn start_task(
    State(state): State<DgwState>,
    TaskToken(claims): TaskToken,
    body: Bytes,
) -> Result<(StatusCode, Json<TaskInfo>), StartTaskError> {
    let snapshot = match claims.kind {
        TaskKind::AiLog { jet_aid } => {
            state
                .tasks
                .start_ephemeral::<AiLogTask>(AiLogTarget { session_id: jet_aid }, &body, claims.jti, &state)
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
        (status = 404, description = "No task with this ID"),
    ),
    security(("scope_token" = ["gateway.tasks.read"])),
))]
pub(crate) async fn get_task(
    State(state): State<DgwState>,
    _scope: TasksReadScope,
    extract::Path(id): extract::Path<Uuid>,
) -> Result<Json<TaskInfo>, HttpError> {
    state
        .tasks
        .get(id)
        .await
        .map_err(HttpError::internal().with_msg("failed to read the task").err())?
        .map(|snapshot| Json(TaskInfo::from(snapshot)))
        .ok_or_else(|| HttpError::not_found().msg("task not found"))
}

/// A background task and its status.
///
/// `substate` is set only when `state` is `running`, `result` only when it is `success`, and `error` only when it is `failed`.
/// Both `substate` and `result` are kind-specific: for `ai-log`, `substate` is an `AiLogSubstate`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaskInfo {
    /// Task ID.
    id: Uuid,
    /// Task kind, as in the `jet_tk` claim of the TASK token.
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

/// Why a task was not started.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct TaskErrorResponse {
    /// Stable error code, such as `invalid_params`, `missing_model`, `missing_api_key`, `missing_base_url`,
    /// `invalid_ai_settings` or `recording_active`.
    error: &'static str,
}

pub(crate) struct StartTaskError(StartError);

impl From<StartError> for StartTaskError {
    fn from(error: StartError) -> Self {
        Self(error)
    }
}

impl IntoResponse for StartTaskError {
    fn into_response(self) -> Response {
        let (status, error) = match self.0 {
            StartError::InvalidParams(code) => (StatusCode::BAD_REQUEST, code),
            StartError::TargetBusy(code) => (StatusCode::CONFLICT, code),
            StartError::Internal => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        warn!(%status, error, "Task rejected");

        (status, Json(TaskErrorResponse { error })).into_response()
    }
}
