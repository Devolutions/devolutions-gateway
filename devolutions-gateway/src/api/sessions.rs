use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::DgwState;
use crate::extract::SessionsReadScope;
use crate::http::HttpError;
use crate::session::SessionInfo;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new().route("/", get(get_sessions)).with_state(state)
}

/// Lists running sessions
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetSessions",
    tag = "Sessions",
    path = "/jet/sessions",
    responses(
        (status = 200, description = "Running sessions", body = [SessionInfo]),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.sessions.read"])),
))]
pub(crate) async fn get_sessions(
    State(DgwState { sessions, .. }): State<DgwState>,
    _scope: SessionsReadScope,
) -> Result<Json<Vec<SessionInfo>>, HttpError> {
    let sessions_in_progress: Vec<SessionInfo> = sessions
        .get_running_sessions()
        .await
        .map_err(HttpError::internal().err())?
        .into_values()
        .collect();

    Ok(Json(sessions_in_progress))
}
