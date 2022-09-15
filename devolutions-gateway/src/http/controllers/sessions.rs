use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpErrorStatus;
use crate::session::{SessionInfo, SessionManagerHandle};
use crate::token::AccessScope;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::prelude::Json;

pub struct SessionsController {
    pub sessions: SessionManagerHandle,
}

#[controller(name = "jet/sessions")]
impl SessionsController {
    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::SessionsRead)"#)]
    async fn get_sessions(&self) -> Result<Json<Vec<SessionInfo>>, HttpErrorStatus> {
        get_sessions(&self.sessions).await
    }
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
pub(crate) async fn get_sessions(sessions: &SessionManagerHandle) -> Result<Json<Vec<SessionInfo>>, HttpErrorStatus> {
    let sessions_in_progress: Vec<SessionInfo> = sessions
        .get_running_sessions()
        .await
        .map_err(HttpErrorStatus::internal)?
        .into_values()
        .collect();

    Ok(Json(sessions_in_progress))
}

// NOTE: legacy controller starting 2021/11/25

pub struct LegacySessionsController {
    pub sessions: SessionManagerHandle,
}

#[controller(name = "sessions")]
impl LegacySessionsController {
    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::SessionsRead)"#)]
    async fn get_sessions(&self) -> Result<Json<Vec<SessionInfo>>, HttpErrorStatus> {
        get_sessions(&self.sessions).await
    }
}
