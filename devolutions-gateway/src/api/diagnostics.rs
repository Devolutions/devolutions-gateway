use std::io;
use std::path::Path as FsPath;
use std::time::UNIX_EPOCH;

use axum::extract::{Path, State};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::fs::{File, OpenOptions};
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
        .route("/logs/files", get(list_log_files))
        .route("/logs/files/{name}", get(get_log_file))
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

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogFileInfo {
    name: String,
    size: u64,
    modified_unix_millis: u64,
}

/// Lists the log files retained by this Gateway.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "ListLogFiles",
    tag = "Diagnostics",
    path = "/jet/diagnostics/logs/files",
    responses(
        (status = 200, description = "Retained log files", body = [LogFileInfo]),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Failed to list log files"),
    ),
    security(("scope_token" = ["gateway.diagnostics.read"])),
))]
async fn list_log_files(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    _scope: DiagnosticsReadScope,
) -> Result<Json<Vec<LogFileInfo>>, HttpError> {
    let conf = conf_handle.get_conf();
    let files = devolutions_log::list_log_files::<GatewayLog>(conf.log_file.as_path())
        .await
        .map_err(HttpError::internal().err())?;

    Ok(Json(
        files
            .into_iter()
            .map(|file| LogFileInfo {
                name: file.name,
                size: file.size,
                modified_unix_millis: file
                    .modified
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            })
            .collect(),
    ))
}

/// Retrieves one retained log file by its listed name.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetLogFile",
    tag = "Diagnostics",
    path = "/jet/diagnostics/logs/files/{name}",
    params(("name" = String, Path, description = "Name returned by ListLogFiles")),
    responses(
        (status = 200, description = "Log file contents", body = String, content_type = "text/plain"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Log file no longer exists"),
        (status = 500, description = "Failed to read log file"),
    ),
    security(("scope_token" = ["gateway.diagnostics.read"])),
))]
async fn get_log_file(
    State(DgwState { conf_handle, .. }): State<DgwState>,
    Path(name): Path<String>,
    _scope: DiagnosticsReadScope,
) -> Result<Response, HttpError> {
    let conf = conf_handle.get_conf();
    let files = devolutions_log::list_log_files::<GatewayLog>(conf.log_file.as_path())
        .await
        .map_err(HttpError::internal().err())?;
    let file = files
        .into_iter()
        .find(|file| file.name == name)
        .ok_or_else(|| HttpError::not_found().msg("log file not found"))?;
    let file = open_regular_log_file(&file.path).await.map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            HttpError::not_found().build(error)
        } else {
            HttpError::internal().build(error)
        }
    })?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        axum_extra::body::AsyncReadBody::new(file),
    )
        .into_response())
}

async fn open_regular_log_file(path: &FsPath) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);

    #[cfg(windows)]
    options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);

    let file = options.open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "log path is not a regular file",
        ));
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "log path is a reparse point",
            ));
        }
    }

    Ok(file)
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

#[cfg(test)]
mod tests {
    use super::open_regular_log_file;

    // oracle: regression Devolutions/devolutions-gateway#2185 review comment 4473309953.
    #[tokio::test]
    async fn replaced_log_file_symlink_is_rejected() {
        let dir = tempfile::tempdir().expect("create temporary directory");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir(&log_dir).expect("create log directory");
        let outside = dir.path().join("outside.txt");
        let selected_log = log_dir.join("gateway.log");
        std::fs::write(&outside, b"private data").expect("create outside file");
        std::fs::write(&selected_log, b"log data").expect("create selected log");
        std::fs::remove_file(&selected_log).expect("replace selected log");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &selected_log).expect("replace log with symlink");
        #[cfg(windows)]
        if let Err(error) = std::os::windows::fs::symlink_file(&outside, &selected_log) {
            if error.raw_os_error() == Some(1314) {
                eprintln!("Windows symlink privilege is unavailable; skipping symlink check");
                return;
            }
            panic!("replace log with symlink: {error}");
        }

        assert!(open_regular_log_file(&selected_log).await.is_err());
    }

    // oracle: regression Devolutions/devolutions-gateway#2185 review comment 4473309953.
    #[tokio::test]
    async fn opened_log_handle_must_be_a_regular_file() {
        let dir = tempfile::tempdir().expect("create temporary directory");
        let regular_file = dir.path().join("gateway.log");
        std::fs::write(&regular_file, b"log data").expect("create regular file");

        assert!(open_regular_log_file(&regular_file).await.is_ok());
        assert!(open_regular_log_file(dir.path()).await.is_err());
    }
}
