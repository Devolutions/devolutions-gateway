use axum::Router;
use axum::extract::State;
use axum::routing::post;
use uuid::Uuid;

use crate::DgwState;
use crate::extract::SessionTerminateScope;
use crate::http::HttpError;
use crate::session::KillResult;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/{id}/terminate", post(terminate_session))
        .with_state(state)
}

/// Terminate forcefully a running session
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "TerminateSession",
    tag = "Sessions",
    path = "/jet/session/{id}/terminate",
    params(
        ("id" = Uuid, Path, description = "Session / association ID of the session to terminate")
    ),
    responses(
        (status = 200, description = "Session terminated successfully"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "No running session found with provided ID"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.session.terminate"])),
))]
pub(crate) async fn terminate_session(
    State(DgwState { sessions, .. }): State<DgwState>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    _scope: SessionTerminateScope,
) -> Result<(), HttpError> {
    match sessions
        .kill_session(session_id)
        .await
        .map_err(HttpError::internal().err())?
    {
        KillResult::Success => Ok(()),
        KillResult::NotFound => Err(HttpError::not_found().msg("session not found")),
    }
}
