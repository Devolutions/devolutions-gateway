use crate::http::guards::access::{AccessGuard, TokenType};
use crate::token::JetAccessScope;
use crate::{GatewaySessionInfo, SESSIONS_IN_PROGRESS};
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::prelude::Json;

pub struct SessionsController;

#[controller(name = "jet/sessions")]
impl SessionsController {
    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(JetAccessScope::GatewaySessionsRead)"#)]
    async fn get_sessions(&self) -> Json<Vec<GatewaySessionInfo>> {
        get_sessions().await
    }
}

/// Lists running sessions
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetSessions",
    path = "/jet/sessions",
    responses(
        (status = 200, description = "Running sessions", body = [SessionInfo]),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.sessions.read"])),
))]
pub(crate) async fn get_sessions() -> Json<Vec<GatewaySessionInfo>> {
    let sessions = SESSIONS_IN_PROGRESS.read().await;
    let sessions_in_progress: Vec<GatewaySessionInfo> = sessions.values().cloned().collect();
    Json(sessions_in_progress)
}

// NOTE: legacy controller starting 2021/11/25

pub struct LegacySessionsController;

#[controller(name = "sessions")]
impl LegacySessionsController {
    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(JetAccessScope::GatewaySessionsRead)"#)]
    async fn get_sessions(&self) -> Json<Vec<GatewaySessionInfo>> {
        get_sessions().await
    }
}
