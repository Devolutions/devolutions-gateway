use std::net::IpAddr;

use axum::extract::State;
use axum::Json;
use devolutions_agent_shared::get_installed_agent_version;
use uuid::Uuid;

use crate::credendials::Password;
use crate::extract::PreflightScope;
use crate::http::HttpError;
use crate::DgwState;

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
pub(crate) struct PreflightOperation {
    id: Uuid,
    #[serde(flatten)]
    kind: PreflightOperationKind,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum PreflightOperationKind {
    #[serde(rename = "get-version")]
    GetVersion,
    #[serde(rename = "get-agent-version")]
    GetAgentVersion,
    #[serde(rename = "get-running-session-count")]
    GetRunningSessionCount,
    #[serde(rename = "get-recording-storage-health")]
    GetRecordingStorageHealth,
    #[serde(rename = "push-token")]
    PushToken { token_id: Uuid, token: String },
    #[serde(rename = "push-credentials")]
    PushCredentials {
        credentials_id: Uuid,
        credentials: Credentials,
    },
    #[serde(rename = "lookup-host")]
    LookupHost {
        #[serde(rename = "host_to_lookup")]
        host: String,
    },
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum Credentials {
    #[serde(rename = "username-password")]
    UsernamePassword { username: String, password: Password },
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) struct PreflightResult {
    operation_id: Uuid,
    #[serde(flatten)]
    kind: PreflightResultKind,
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
#[serde(tag = "kind")]
pub(crate) enum PreflightResultKind {
    #[serde(rename = "version")]
    Version {
        /// Gateway service version
        version: &'static str,
    },
    #[serde(rename = "agent-version")]
    AgentVersion {
        /// Agent service version, if installed
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "agent_version")]
        version: Option<String>,
    },
    #[serde(rename = "running-session-count")]
    RunningSessionCount {
        /// Number of running sessions
        #[serde(rename = "running_session_count")]
        count: usize,
    },
    #[serde(rename = "recording-storage-health")]
    RecordingStorageHealth {
        /// Whether the recording storage is writeable or not
        recording_storage_is_writeable: bool,
        /// The total space of the disk used to store recordings, in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        recording_storage_total_space: Option<u64>,
        /// The remaining available space to store recordings, in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        recording_storage_available_space: Option<u64>,
    },
    #[serde(rename = "resolved-host")]
    ResolvedHost {
        /// Hostname that was resolved.
        #[serde(rename = "resolved_host")]
        host: String,
        /// Resolved IP addresses.
        #[serde(rename = "resolved_addresses")]
        addresses: Vec<IpAddr>,
    },
    #[serde(rename = "alert")]
    Alert {
        /// Alert status
        #[serde(rename = "alert_status")]
        status: PreflightAlertStatus,
        /// Message describing the problem
        #[serde(rename = "alert_message")]
        message: String,
    },
}

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) enum PreflightAlertStatus {
    #[serde(rename = "general-failure")]
    GeneralFailure,
    #[serde(rename = "internal-server-error")]
    InternalServerError,
    #[serde(rename = "host-lookup-failure")]
    HostLookupFailure,
    #[serde(rename = "agent-version-lookup-failure")]
    AgentVersionLookupFailure,
}

/// Performs a heartbeat check
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "PostPreflight",
    tag = "Preflight",
    path = "/jet/preflight",
    request_body = [PreflightOperation],
    responses(
        (status = 200, description = "Preflight results", body = [PreflightResult]),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("scope_token" = ["gateway.preflight"])),
))]
pub(super) async fn post_preflight(
    State(DgwState {
        conf_handle, sessions, ..
    }): State<DgwState>,
    _scope: PreflightScope,
    Json(operations): Json<Vec<PreflightOperation>>,
) -> Result<Json<Vec<PreflightResult>>, HttpError> {
    debug!(?operations, "Preflight operations");

    // TODO: parallelize the work here, using tasks.
    // Especially important for DNS resolution.

    let conf = conf_handle.get_conf();

    let mut results = Vec::with_capacity(operations.len());

    for operation in operations {
        match operation.kind {
            PreflightOperationKind::GetVersion => results.push(PreflightResult {
                operation_id: operation.id,
                kind: PreflightResultKind::Version {
                    version: env!("CARGO_PKG_VERSION"),
                },
            }),
            PreflightOperationKind::GetAgentVersion => match get_installed_agent_version() {
                Ok(version) => results.push(PreflightResult {
                    operation_id: operation.id,
                    kind: PreflightResultKind::AgentVersion {
                        version: version.map(|x| x.fmt_without_revision()),
                    },
                }),
                Err(error) => {
                    warn!(error = %error, "Failed to get Agent version");
                    results.push(PreflightResult {
                        operation_id: operation.id,
                        kind: PreflightResultKind::Alert {
                            status: PreflightAlertStatus::AgentVersionLookupFailure,
                            message: "failed to get Agent version".to_owned(),
                        },
                    })
                }
            },
            PreflightOperationKind::GetRunningSessionCount => match sessions.get_running_session_count().await {
                Ok(count) => results.push(PreflightResult {
                    operation_id: operation.id,
                    kind: PreflightResultKind::RunningSessionCount { count },
                }),
                Err(error) => {
                    warn!(%operation.id, error = format!("{error:#}"), "Failed to count running sessions");
                    results.push(PreflightResult {
                        operation_id: operation.id,
                        kind: PreflightResultKind::Alert {
                            status: PreflightAlertStatus::InternalServerError,
                            message: "failed to count running sessions".to_owned(),
                        },
                    })
                }
            },
            PreflightOperationKind::GetRecordingStorageHealth => {
                let recording_storage_result =
                    crate::api::heartbeat::recording_storage_health(conf.recording_path.as_std_path());

                results.push(PreflightResult {
                    operation_id: operation.id,
                    kind: PreflightResultKind::RecordingStorageHealth {
                        recording_storage_is_writeable: recording_storage_result.recording_storage_is_writeable,
                        recording_storage_total_space: recording_storage_result.recording_storage_total_space,
                        recording_storage_available_space: recording_storage_result.recording_storage_available_space,
                    },
                });
            }
            PreflightOperationKind::PushToken { token_id, token } => {
                results.push(PreflightResult {
                    operation_id: operation.id,
                    kind: PreflightResultKind::Alert {
                        status: PreflightAlertStatus::GeneralFailure,
                        message: "unimplemented".to_owned(),
                    },
                });
            }
            PreflightOperationKind::PushCredentials {
                credentials_id,
                credentials,
            } => {
                results.push(PreflightResult {
                    operation_id: operation.id,
                    kind: PreflightResultKind::Alert {
                        status: PreflightAlertStatus::GeneralFailure,
                        message: "unimplemented".to_owned(),
                    },
                });
            }
            PreflightOperationKind::LookupHost { host } => match tokio::net::lookup_host((host.as_str(), 0)).await {
                Ok(addresses) => {
                    results.push(PreflightResult {
                        operation_id: operation.id,
                        kind: PreflightResultKind::ResolvedHost {
                            host: host.clone(),
                            addresses: addresses.map(|addr| addr.ip()).collect(),
                        },
                    });
                }
                Err(error) => {
                    warn!(%operation.id, error = format!("{error:#}"), %host, "Failed to lookup host");
                    results.push(PreflightResult {
                        operation_id: operation.id,
                        kind: PreflightResultKind::Alert {
                            status: PreflightAlertStatus::HostLookupFailure,
                            message: format!("failed to lookup host {host}"),
                        },
                    });
                }
            },
        }
    }

    Ok(Json(results))
}
