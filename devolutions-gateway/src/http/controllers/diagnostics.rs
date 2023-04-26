use crate::config::{Conf, ConfHandle};
use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpError;
use crate::listener::ListenerUrls;
use crate::token::AccessScope;
use saphir::prelude::*;
use uuid::Uuid;

/// Service configuration diagnostic
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub struct ConfigDiagnostic {
    /// This Gateway's unique ID
    id: Option<Uuid>,
    /// This Gateway's hostname
    hostname: String,
    /// Gateway service version
    version: &'static str,
    /// Listeners configured on this instance
    listeners: Vec<ListenerUrls>,
}

impl From<&Conf> for ConfigDiagnostic {
    fn from(conf: &Conf) -> Self {
        ConfigDiagnostic {
            id: conf.id,
            listeners: conf.listeners.clone(),
            version: env!("CARGO_PKG_VERSION"),
            hostname: conf.hostname.clone(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub struct ClockDiagnostic {
    /// Current time in seconds
    timestamp_secs: i64,
    /// Current time in milliseconds
    timestamp_millis: i64,
}

impl ClockDiagnostic {
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
    conf_handle: ConfHandle,
}

impl DiagnosticsController {
    pub fn new(conf_handle: ConfHandle) -> (Self, LegacyDiagnosticsController) {
        (
            DiagnosticsController {
                conf_handle: conf_handle.clone(),
            },
            LegacyDiagnosticsController {
                inner: DiagnosticsController { conf_handle },
            },
        )
    }
}

#[controller(name = "jet/diagnostics")]
impl DiagnosticsController {
    #[get("/logs")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::DiagnosticsRead)"#)]
    async fn get_logs(&self) -> Result<File, HttpError> {
        get_logs(self).await
    }

    // NOTE: this route is not secured by access token.
    // Indeed, this route is used to retrieve server's clock when diagnosing clock drifting.
    // If there is clock drift, token validation will fail because claims such as `nbf` will then
    // be invalid, and thus prevent the clock drift diagnosis.
    #[get("/clock")]
    async fn get_clock(&self) -> Json<ClockDiagnostic> {
        get_clock()
    }

    #[get("/configuration")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::DiagnosticsRead)"#)]
    async fn get_configuration(&self) -> Json<ConfigDiagnostic> {
        get_configuration(self).await
    }
}

/// Retrieves latest logs.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetLogs",
    tag = "Diagnostics",
    path = "/jet/diagnostics/logs",
    responses(
        (status = 200, description = "Latest logs", body = String),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to retrieve logs"),
    ),
    security(("scope_token" = ["gateway.diagnostics.read"])),
))]
async fn get_logs(controller: &DiagnosticsController) -> Result<File, HttpError> {
    let conf = controller.conf_handle.get_conf();

    let latest_log_file_path = crate::log::find_latest_log_file(conf.log_file.as_path())
        .await
        .map_err(HttpError::internal().with_msg("latest log file not found").err())?;

    let latest_log_file_path = latest_log_file_path
        .to_str()
        .ok_or_else(|| HttpError::internal().msg("invalid file path"))?;

    File::open(latest_log_file_path)
        .await
        .map_err(HttpError::internal().err())
}

/// Retrieves configuration.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetConfigurationDiagnostic",
    tag = "Diagnostics",
    path = "/jet/diagnostics/configuration",
    responses(
        (status = 200, description = "Service configuration diagnostic (including version)", body = ConfigDiagnostic),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.diagnostics.read"])),
))]
async fn get_configuration(controller: &DiagnosticsController) -> Json<ConfigDiagnostic> {
    Json(ConfigDiagnostic::from(controller.conf_handle.get_conf().as_ref()))
}

/// Retrieves server's clock in order to diagnose clock drifting.
///
/// Clock drift is an issue for token validation because of claims such as `nbf` and `exp`.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetClockDiagnostic",
    tag = "Diagnostics",
    path = "/jet/diagnostics/clock",
    responses(
        (status = 200, description = "Server's clock", body = ClockDiagnostic),
    ),
))]
fn get_clock() -> Json<ClockDiagnostic> {
    Json(ClockDiagnostic::now())
}

// NOTE: legacy controller starting 2021/11/25

pub struct LegacyDiagnosticsController {
    inner: DiagnosticsController,
}

#[controller(name = "diagnostics")]
impl LegacyDiagnosticsController {
    #[get("/logs")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::DiagnosticsRead)"#)]
    async fn get_logs(&self) -> Result<File, HttpError> {
        get_logs(&self.inner).await
    }

    #[get("/configuration")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(AccessScope::DiagnosticsRead)"#)]
    async fn get_configuration(&self) -> Json<ConfigDiagnostic> {
        get_configuration(&self.inner).await
    }
}
