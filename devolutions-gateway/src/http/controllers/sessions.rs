use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpErrorStatus;
use crate::token::JetAccessScope;
use crate::{GatewaySessionInfo, SESSIONS_IN_PROGRESS};
use saphir::controller::Controller;
use saphir::http::{Method, StatusCode};
use saphir::macros::controller;
use saphir::prelude::Json;

pub struct SessionsController;

#[controller(name = "jet/sessions")]
impl SessionsController {
    #[get("/count")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(JetAccessScope::GatewaySessionsRead)"#)]
    async fn get_count(&self) -> (StatusCode, String) {
        get_count_stub().await
    }

    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(JetAccessScope::GatewaySessionsRead)"#)]
    async fn get_sessions(&self) -> Result<Json<Vec<GatewaySessionInfo>>, HttpErrorStatus> {
        get_sessions_stub().await
    }
}

async fn get_count_stub() -> (StatusCode, String) {
    let sessions = SESSIONS_IN_PROGRESS.read().await;
    (StatusCode::OK, sessions.len().to_string())
}

async fn get_sessions_stub() -> Result<Json<Vec<GatewaySessionInfo>>, HttpErrorStatus> {
    let sessions = SESSIONS_IN_PROGRESS.read().await;

    let sessions_in_progress: Vec<GatewaySessionInfo> = sessions.values().cloned().collect();

    Ok(Json(sessions_in_progress))
}

// NOTE: legacy controller starting 2021/11/25

pub struct LegacySessionsController;

#[controller(name = "sessions")]
impl LegacySessionsController {
    #[get("/count")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(JetAccessScope::GatewaySessionsRead)"#)]
    async fn get_count(&self) -> (StatusCode, String) {
        get_count_stub().await
    }

    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(JetAccessScope::GatewaySessionsRead)"#)]
    async fn get_sessions(&self) -> Result<Json<Vec<GatewaySessionInfo>>, HttpErrorStatus> {
        get_sessions_stub().await
    }
}
