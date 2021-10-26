use crate::config::{Config, ListenerConfig};
use crate::http::guards::access::{AccessGuard, JetTokenType};
use crate::http::HttpErrorStatus;
use crate::token::JetAccessScope;
use saphir::prelude::*;
use std::sync::Arc;

pub struct DiagnosticsController {
    config: Arc<Config>,
}

#[derive(Serialize)]
struct GatewayConfigurationResponse {
    hostname: String,
    listeners: Vec<ListenerConfig>,
}

impl From<Arc<Config>> for GatewayConfigurationResponse {
    fn from(config: Arc<Config>) -> Self {
        GatewayConfigurationResponse {
            listeners: config.listeners.clone(),
            hostname: config.hostname.clone(),
        }
    }
}

impl DiagnosticsController {
    pub fn new(config: Arc<Config>) -> Self {
        DiagnosticsController { config }
    }
}

#[controller(name = "diagnostics")]
impl DiagnosticsController {
    #[get("/logs")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_logs(&self) -> Result<File, HttpErrorStatus> {
        let log_file_path = self
            .config
            .log_file
            .as_ref()
            .ok_or_else(|| HttpErrorStatus::not_found("Log file is not configured"))?;
        File::open(log_file_path).await.map_err(HttpErrorStatus::internal)
    }

    #[get("/configuration")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_configuration(&self) -> Json<GatewayConfigurationResponse> {
        Json(self.config.clone().into())
    }
}
