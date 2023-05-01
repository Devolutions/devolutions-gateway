use axum::extract::State;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::fs::File;
use uuid::Uuid;

use crate::config::Conf;
use crate::extract::DiagnosticsReadScope;
use crate::http::HttpError;
use crate::listener::ListenerUrls;
use crate::DgwState;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/logs", get(get_logs))
        .route("/clock", get(get_clock))
        .route("/configuration", get(get_configuration))
        .with_state(state)
}

/// Service configuration diagnostic
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct ConfigDiagnostic {
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
pub(crate) struct ClockDiagnostic {
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
async fn get_logs(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    _token: DiagnosticsReadScope,
) -> Result<Response, HttpError> {
    let conf = conf_handle.get_conf();

    let latest_log_file_path = crate::log::find_latest_log_file(conf.log_file.as_path())
        .await
        .map_err(HttpError::internal().with_msg("latest log file not found").err())?;

    let file = File::open(&latest_log_file_path)
        .await
        .map_err(HttpError::internal().err())?;

    Ok(axum_extra::body::AsyncReadBody::new(file).into_response())
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
async fn get_configuration(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    _scope: DiagnosticsReadScope,
) -> Json<ConfigDiagnostic> {
    Json(ConfigDiagnostic::from(conf_handle.get_conf().as_ref()))
}

/// Retrieves server's clock in order to diagnose clock drifting.
///
/// This route is not secured by access token.
/// Indeed, this route is used to retrieve server's clock when diagnosing clock drifting.
/// If there is clock drift, token validation will fail because claims such as `nbf` will then
/// be invalid, and thus prevent the clock drift diagnosis.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetClockDiagnostic",
    tag = "Diagnostics",
    path = "/jet/diagnostics/clock",
    responses(
        (status = 200, description = "Server's clock", body = ClockDiagnostic),
    ),
))]
async fn get_clock() -> Json<ClockDiagnostic> {
    Json(ClockDiagnostic::now())
}
