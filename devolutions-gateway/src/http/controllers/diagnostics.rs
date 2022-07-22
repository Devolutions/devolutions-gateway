use crate::config::{Config, ListenerConfig};
use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpErrorStatus;
use crate::token::JetAccessScope;
use saphir::prelude::*;
use std::sync::Arc;

#[derive(Serialize, utoipa::Component)]
pub(crate) struct GatewayConfiguration {
    hostname: String,
    version: &'static str,
    #[component(inline)]
    listeners: Vec<ListenerConfig>,
}

impl From<Arc<Config>> for GatewayConfiguration {
    fn from(config: Arc<Config>) -> Self {
        GatewayConfiguration {
            listeners: config.listeners.clone(),
            version: env!("CARGO_PKG_VERSION"),
            hostname: config.hostname.clone(),
        }
    }
}

#[derive(Serialize, utoipa::Component)]
pub(crate) struct GatewayClock {
    timestamp_secs: i64,
    timestamp_millis: i64,
}

impl GatewayClock {
    pub fn now() -> Self {
        use chrono::prelude::*;
        let utc = Utc::now();
        Self {
            timestamp_secs: utc.timestamp(),
            timestamp_millis: utc.timestamp_millis(),
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
        init_expr = r#"TokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_logs(&self) -> Result<File, HttpErrorStatus> {
        get_logs(self).await
    }

    // NOTE: this route is not secured by access token.
    // Indeed, this route is used to retrieve server's clock when diagnosing clock drifting.
    // If there is clock drift, token validation will fail because claims such as `nbf` will then
    // be invalid, and thus prevent the clock drift diagnosis.
    #[get("/clock")]
    async fn get_clock(&self) -> Json<GatewayClock> {
        get_clock()
    }

    #[get("/configuration")]
    #[guard(
        AccessGuard,
        init_expr = r#"TokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_configuration(&self) -> Json<GatewayConfiguration> {
        get_configuration(self).await
    }
}

/// Retrieve latest logs of this service.
#[utoipa::path(
    get,
    path = "/jet/diagnostics/logs",
    responses(
        (status = 200, description = "Latest logs", body = String),
        (status = 500, description = "Couldn't retrieve logs")
    ),
    security(("scope_token" = ["gateway.diagnostics.read"])),
)]
async fn get_logs(controller: &DiagnosticsController) -> Result<File, HttpErrorStatus> {
    let log_file_path = controller
        .config
        .log_file
        .as_ref()
        .ok_or_else(|| HttpErrorStatus::internal("log file is not configured"))?;

    let latest_log_file_path = crate::log::find_latest_log_file(log_file_path.as_path())
        .await
        .map_err(|e| HttpErrorStatus::internal(format!("latest log file not found: {e:#}")))?;

    let latest_log_file_path = latest_log_file_path
        .to_str()
        .ok_or_else(|| HttpErrorStatus::internal("invalid file path"))?;

    File::open(latest_log_file_path)
        .await
        .map_err(HttpErrorStatus::internal)
}

/// Retrieve this Gateway's configuration.
#[utoipa::path(
    get,
    path = "/jet/diagnostics/configuration",
    responses(
        (status = 200, description = "Gateway's configuration", body = inline(GatewayConfiguration)),
    ),
    security(("scope_token" = ["gateway.diagnostics.read"])),
)]
async fn get_configuration(controller: &DiagnosticsController) -> Json<GatewayConfiguration> {
    Json(controller.config.clone().into())
}

/// This route is used to retrieve server's clock when diagnosing clock drifting.
/// Clock drift is an issue for token validation because of claims such as `nbf` and `exp`.
#[utoipa::path(
    get,
    path = "/jet/diagnostics/clock",
    responses(
        (status = 200, description = "Server's clock", body = inline(GatewayClock)),
    ),
)]
fn get_clock() -> Json<GatewayClock> {
    Json(GatewayClock::now())
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
        init_expr = r#"TokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_logs(&self) -> Result<File, HttpErrorStatus> {
        get_logs(&self.inner).await
    }

    #[get("/configuration")]
    #[guard(
        AccessGuard,
        init_expr = r#"TokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_configuration(&self) -> Json<GatewayConfiguration> {
        get_configuration(&self.inner).await
    }
}
