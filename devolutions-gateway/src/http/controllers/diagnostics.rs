use crate::config::{Config, ListenerConfig};
use crate::http::guards::access::{AccessGuard, JetTokenType};
use crate::http::HttpErrorStatus;
use crate::token::JetAccessScope;
use saphir::prelude::*;
use std::sync::Arc;

#[derive(Serialize)]
struct GatewayConfigurationResponse {
    hostname: String,
    version: &'static str,
    listeners: Vec<ListenerConfig>,
}

impl From<Arc<Config>> for GatewayConfigurationResponse {
    fn from(config: Arc<Config>) -> Self {
        GatewayConfigurationResponse {
            listeners: config.listeners.clone(),
            version: env!("CARGO_PKG_VERSION"),
            hostname: config.hostname.clone(),
        }
    }
}

#[derive(Serialize)]
struct GatewayClockResponse {
    timestamp_secs: i64,
    timestamp_millis: i64,
    timestamp_nanos: i64,
}

impl GatewayClockResponse {
    pub fn now() -> Self {
        use chrono::prelude::*;
        let utc = Utc::now();
        Self {
            timestamp_secs: utc.timestamp(),
            timestamp_millis: utc.timestamp_millis(),
            timestamp_nanos: utc.timestamp_nanos(),
        }
    }
}

pub struct DiagnosticsController {
    config: Arc<Config>,
}

impl DiagnosticsController {
    pub fn new(config: Arc<Config>) -> (Self, LegacyDiagnosticsController) {
        (
            DiagnosticsController { config: config.clone() },
            LegacyDiagnosticsController {
                inner: DiagnosticsController { config },
            },
        )
    }
}

#[controller(name = "jet/diagnostics")]
impl DiagnosticsController {
    #[get("/logs")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_logs(&self) -> Result<File, HttpErrorStatus> {
        get_logs_stub(self).await
    }

    #[get("/clock")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_clock(&self) -> Json<GatewayClockResponse> {
        Json(GatewayClockResponse::now())
    }

    #[get("/configuration")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_configuration(&self) -> Json<GatewayConfigurationResponse> {
        get_configuration_stub(self).await
    }
}

async fn get_logs_stub(controller: &DiagnosticsController) -> Result<File, HttpErrorStatus> {
    let log_file_path = controller
        .config
        .log_file
        .as_ref()
        .ok_or_else(|| HttpErrorStatus::not_found("Log file is not configured"))?;
    File::open(log_file_path.as_str())
        .await
        .map_err(HttpErrorStatus::internal)
}

async fn get_configuration_stub(controller: &DiagnosticsController) -> Json<GatewayConfigurationResponse> {
    Json(controller.config.clone().into())
}

// NOTE: legacy controller starting 2021/11/25

pub struct LegacyDiagnosticsController {
    inner: DiagnosticsController,
}

#[controller(name = "diagnostics")]
impl LegacyDiagnosticsController {
    #[get("/logs")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_logs(&self) -> Result<File, HttpErrorStatus> {
        get_logs_stub(&self.inner).await
    }

    #[get("/configuration")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_configuration(&self) -> Json<GatewayConfigurationResponse> {
        get_configuration_stub(&self.inner).await
    }
}
