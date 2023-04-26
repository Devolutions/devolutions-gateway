use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpError;
use crate::session::{KillResult, SessionManagerHandle};
use crate::token::AccessScope;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use uuid::Uuid;

pub struct SessionController {
    pub sessions: SessionManagerHandle,
}

#[controller(name = "jet/session")]
impl SessionController {
    #[post("/{id}/terminate")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::SessionTerminate)"#)]
    async fn terminate_session(&self, id: Uuid) -> Result<(), HttpError> {
        terminate_session(&self.sessions, id).await
    }
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
pub(crate) async fn terminate_session(sessions: &SessionManagerHandle, session_id: Uuid) -> Result<(), HttpError> {
    match sessions
        .kill_session(session_id)
        .await
        .map_err(HttpError::internal().err())?
    {
        KillResult::Success => Ok(()),
        KillResult::NotFound => Err(HttpError::not_found().msg("session not found")),
    }
}
