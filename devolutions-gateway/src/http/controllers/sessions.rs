use crate::http::guards::access::{AccessGuard, JetTokenType};
use crate::http::HttpErrorStatus;
use crate::token::JetAccessScope;
use crate::{GatewaySessionInfo, SESSIONS_IN_PROGRESS};
use saphir::controller::Controller;
use saphir::http::{Method, StatusCode};
use saphir::macros::controller;
use saphir::prelude::Json;

pub struct SessionsController;

#[controller(name = "sessions")]
impl SessionsController {
    #[get("/count")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewaySessionsRead)"#
    )]
    async fn get_count(&self) -> (StatusCode, String) {
        let sessions = SESSIONS_IN_PROGRESS.read().await;
        (StatusCode::OK, sessions.len().to_string())
    }

    #[get("/")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewaySessionsRead)"#
    )]
    async fn get_sessions(&self) -> Result<Json<Vec<GatewaySessionInfo>>, HttpErrorStatus> {
        let sessions = SESSIONS_IN_PROGRESS.read().await;

        let sessions_in_progress: Vec<GatewaySessionInfo> = sessions.values().cloned().collect();

        Ok(Json(sessions_in_progress))
    }
}
