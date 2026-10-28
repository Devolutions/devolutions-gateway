//! Endpoints of provisioner tasks: each kind of Task is started and read under `/jet/tasks/{kind}/{task_id}`.

pub(crate) mod recording_ai_analysis;

use axum::Router;
use axum::routing::put;
use provisioner_task::ProvisionerTaskState;

use crate::DgwState;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route(
            "/recording-ai-analysis/{task_id}",
            put(recording_ai_analysis::start_ai_analysis).get(recording_ai_analysis::get_ai_analysis),
        )
        .with_state(state)
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
