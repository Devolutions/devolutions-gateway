use axum::extract::State;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::fs::File;
use uuid::Uuid;

use crate::DgwState;
use crate::config::Conf;
use crate::extract::DiagnosticsReadScope;
use crate::http::HttpError;
use crate::listener::ListenerUrls;
use crate::log::GatewayLog;

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
        use url::Url;

        use crate::config::dto::NgrokTunnelConf;

        let mut listeners = conf.listeners.clone();

        if let Some(ngrok) = &conf.ngrok {
            for tunnel in ngrok.tunnels.values() {
                match tunnel {
                    NgrokTunnelConf::Tcp(tcp_tunnel) => {
                        let url = format!("tcp://{}", tcp_tunnel.remote_addr);

                        match Url::parse(&url) {
                            Ok(url) => listeners.push(ListenerUrls {
                                internal_url: url.clone(),
                                external_url: url.clone(),
                            }),
                            Err(error) => {
                                warn!(?tcp_tunnel, %error, "invalid URL for Ngrok TCP tunnel");
                            }
                        }
                    }
                    NgrokTunnelConf::Http(http_tunnel) => {
                        let url = format!("https://{}", http_tunnel.domain);

                        match Url::parse(&url) {
                            Ok(url) => listeners.push(ListenerUrls {
                                internal_url: url.clone(),
                                external_url: url.clone(),
                            }),
                            Err(error) => {
                                warn!(?http_tunnel, %error, "invalid URL for Ngrok HTTP tunnel");
                            }
                        }
                    }
                }
            }
        }

        ConfigDiagnostic {
            id: conf.id,
            listeners,
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
    pub(crate) fn now() -> Self {
        let now = time::OffsetDateTime::now_utc();
        Self {
            timestamp_secs: now.unix_timestamp(),
            timestamp_millis: i64::try_from(now.unix_timestamp_nanos() / 1_000_000).expect("never truncated"),
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

    let latest_log_file_path = devolutions_log::find_latest_log_file::<GatewayLog>(conf.log_file.as_path())
        .await
        .map_err(HttpError::internal().with_msg("latest log file not found").err())?;

    let file = File::open(&latest_log_file_path)
        .await
        .map_err(HttpError::internal().err())?;

    Ok(axum_extra::body::AsyncReadBody::new(file).into_response())
}

/// Retrieves a subset of the configuration, for diagnosis purposes.
///
/// This route primary function is to help with configuration diagnosis (e.g.: ID mismatch, hostname mismatch,
/// outdated version). In addition, it may be used to retrieve the listener URLs. This information can be used to
/// provide configuration auto-filling, in order to assist the end user.
///
/// It must be noted that this route will never return the whole configuration file as-is, for security reasons.
/// For an exhaustive list of returned keys, refer to the `ConfigDiagnostic` component definition.
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
