use axum::extract::{self, State};
use axum::routing::get;
use axum::{Json, Router};
use provisioner_task::{ProvisionerTask, ProvisionerTaskState};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::DgwState;
use crate::extract::TasksReadScope;
use crate::http::HttpError;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new().route("/{id}", get(get_task)).with_state(state)
}

/// Gets a Task, the record of one piece of work the provisioner asked Gateway to do
///
/// Tasks are kept forever, across Gateway restarts.
/// An unfinished Task past its deadline is reported as failed.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetTask",
    tag = "Tasks",
    path = "/jet/tasks/{id}",
    params(
        ("id" = Uuid, Path, description = "Task ID"),
    ),
    responses(
        (status = 200, description = "The Task", body = TaskInfo),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "No Task has this ID"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.tasks.read"])),
))]
pub(crate) async fn get_task(
    State(DgwState { provisioner_tasks, .. }): State<DgwState>,
    _scope: TasksReadScope,
    extract::Path(id): extract::Path<Uuid>,
) -> Result<Json<TaskInfo>, HttpError> {
    let task = provisioner_tasks
        .get(id, OffsetDateTime::now_utc())
        .await
        .map_err(HttpError::internal().with_msg("failed to read the task").err())?
        .ok_or_else(|| HttpError::not_found().msg("task not found"))?;

    Ok(Json(TaskInfo::from(task)))
}

/// A Task: the permanent record of one piece of work the provisioner asked Gateway to do
///
/// The work runs in the background; `state` and `payload` tell how it goes.
/// The shape of `params` and `payload` belongs to the kind.
/// For `recording.ai-analysis`, `payload` is an `AiAnalysisRunningPayload` while `running`, an
/// `AiAnalysisSucceededPayload` once `succeeded`, and an `AiAnalysisFailedPayload` once `failed`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaskInfo {
    /// Task ID, chosen by the provisioner.
    id: Uuid,
    /// Kind of work, such as `recording.ai-analysis`.
    kind: String,
    /// What the work is about, such as a session ID.
    target: String,
    /// What was asked, without secrets.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    params: serde_json::Value,
    state: TaskState,
    /// Details of the current state; null while `queued`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<Object>))]
    payload: serde_json::Value,
    /// Number of attempts started so far.
    attempts: u32,
    /// When the Task was created.
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// When its first attempt started.
    #[serde(with = "time::serde::rfc3339::option")]
    started_at: Option<OffsetDateTime>,
    /// When it succeeded or failed.
    #[serde(with = "time::serde::rfc3339::option")]
    finished_at: Option<OffsetDateTime>,
    /// When an unfinished Task becomes failed, waiting and retries included.
    #[serde(with = "time::serde::rfc3339")]
    deadline_at: OffsetDateTime,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TaskState {
    /// Waiting for its first attempt.
    Queued,
    /// An attempt runs, or the next one waits for a retry.
    Running,
    Succeeded,
    Failed,
}

impl From<ProvisionerTaskState> for TaskState {
    fn from(state: ProvisionerTaskState) -> Self {
        match state {
            ProvisionerTaskState::Queued => Self::Queued,
            ProvisionerTaskState::Running => Self::Running,
            ProvisionerTaskState::Succeeded => Self::Succeeded,
            ProvisionerTaskState::Failed => Self::Failed,
        }
    }
}

impl From<ProvisionerTask> for TaskInfo {
    fn from(task: ProvisionerTask) -> Self {
        Self {
            id: task.id,
            kind: task.kind,
            target: task.target,
            params: task.params,
            state: TaskState::from(task.state),
            payload: task.payload,
            attempts: task.attempts,
            created_at: task.created_at,
            started_at: task.started_at,
            finished_at: task.finished_at,
            deadline_at: task.deadline_at,
        }
    }
}
