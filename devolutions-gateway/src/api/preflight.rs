use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use devolutions_agent_shared::get_installed_agent_version;
use serde::de;
use tracing::{Instrument as _, Span};
use uuid::Uuid;

use crate::config::Conf;
use crate::credendials::Credentials;
use crate::extract::PreflightScope;
use crate::http::HttpError;
use crate::session::SessionMessageSender;
use crate::DgwState;

const OP_GET_VERSION: &str = "get-version";
const OP_GET_AGENT_VERSION: &str = "get-agent-version";
const OP_GET_RUNNING_SESSION_COUNT: &str = "get-running-session-count";
const OP_GET_RECORDING_STORAGE_HEALTH: &str = "get-recording-storage-health";
const OP_PUSH_TOKEN: &str = "push-token";
const OP_PUSH_CREDENTIALS: &str = "push-credentials";
const OP_LOOKUP_HOST: &str = "lookup-host";

#[derive(Debug, Deserialize)]
pub(crate) struct PreflightOperation {
    id: Uuid,
    kind: String,
    #[serde(flatten)]
    params: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct PushTokenParams {
    token: String,
}

#[derive(Debug, Deserialize)]
struct PushCredentialsParams {
    association_id: Uuid,
    proxy_credentials: Credentials,
    target_credentials: Credentials,
}

#[derive(Debug, Deserialize)]
struct LookupHostParams {
    #[serde(rename = "host_to_lookup")]
    host: String,
}

#[derive(Serialize)]
pub(crate) struct PreflightOutput {
    operation_id: Uuid,
    #[serde(flatten)]
    kind: PreflightOutputKind,
}

#[derive(Serialize)]
#[serde(tag = "kind")]
pub(crate) enum PreflightOutputKind {
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
    #[serde(rename = "unsupported-operation")]
    UnsupportedOperation,
    #[serde(rename = "invalid-parameters")]
    InvalidParams,
    #[serde(rename = "internal-server-error")]
    InternalServerError,
    #[serde(rename = "host-lookup-failure")]
    HostLookupFailure,
    #[serde(rename = "agent-version-lookup-failure")]
    AgentVersionLookupFailure,
}

struct PreflightError {
    status: PreflightAlertStatus,
    message: String,
}

impl PreflightError {
    fn new(status: PreflightAlertStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn invalid_params(error: impl std::error::Error) -> Self {
        Self::new(PreflightAlertStatus::InvalidParams, format!("{error:#}"))
    }
}

#[derive(Clone)]
struct Outputs(Arc<parking_lot::Mutex<Vec<PreflightOutput>>>);

impl Outputs {
    fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(parking_lot::Mutex::new(Vec::with_capacity(capacity))))
    }

    fn push(&self, output: PreflightOutput) {
        self.0.lock().push(output);
    }

    fn take(&self) -> Vec<PreflightOutput> {
        std::mem::take(&mut self.0.lock())
    }
}

/// Performs a batch of preflight operations
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "PostPreflight",
    tag = "Preflight",
    path = "/jet/preflight",
    request_body = [PreflightOperation],
    responses(
        (status = 200, description = "Preflight outputs", body = [PreflightOutput]),
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
) -> Result<Json<Vec<PreflightOutput>>, HttpError> {
    debug!(?operations, "Preflight operations");

    let outputs = Outputs::with_capacity(operations.len());

    let handles = operations
        .into_iter()
        .map(|operation| {
            tokio::spawn({
                let span = Span::current();
                let outputs = outputs.clone();
                let conf = conf_handle.get_conf();
                let sessions = sessions.clone();

                async move {
                    let operation_id = operation.id;
                    trace!(%operation.id, "Process preflight operation");

                    if let Err(error) = handle_operation(operation, &outputs, &conf, &sessions).await {
                        outputs.push(PreflightOutput {
                            operation_id,
                            kind: PreflightOutputKind::Alert {
                                status: error.status,
                                message: error.message,
                            },
                        });
                    }
                }
                .instrument(span)
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        let _ = handle.await;
    }

    Ok(Json(outputs.take()))
}

async fn handle_operation(
    operation: PreflightOperation,
    outputs: &Outputs,
    conf: &Conf,
    sessions: &SessionMessageSender,
) -> Result<(), PreflightError> {
    match operation.kind.as_str() {
        OP_GET_VERSION => outputs.push(PreflightOutput {
            operation_id: operation.id,
            kind: PreflightOutputKind::Version {
                version: env!("CARGO_PKG_VERSION"),
            },
        }),
        OP_GET_AGENT_VERSION => {
            let version = get_installed_agent_version()
                .inspect_err(|error| warn!(%operation.id, %error, "Failed to get Agent version"))
                .map_err(|e| PreflightError::new(PreflightAlertStatus::AgentVersionLookupFailure, e.to_string()))?;

            outputs.push(PreflightOutput {
                operation_id: operation.id,
                kind: PreflightOutputKind::AgentVersion {
                    version: version.map(|x| x.fmt_without_revision()),
                },
            });
        }
        OP_GET_RUNNING_SESSION_COUNT => {
            let count = sessions
                .get_running_session_count()
                .await
                .inspect_err(
                    |error| warn!(%operation.id, error = format!("{error:#}"), "Failed to count running sessions"),
                )
                .map_err(|_| {
                    PreflightError::new(
                        PreflightAlertStatus::InternalServerError,
                        "failed to count running sessions",
                    )
                })?;

            outputs.push(PreflightOutput {
                operation_id: operation.id,
                kind: PreflightOutputKind::RunningSessionCount { count },
            });
        }
        OP_GET_RECORDING_STORAGE_HEALTH => {
            let recording_storage_result =
                crate::api::heartbeat::recording_storage_health(conf.recording_path.as_std_path());

            outputs.push(PreflightOutput {
                operation_id: operation.id,
                kind: PreflightOutputKind::RecordingStorageHealth {
                    recording_storage_is_writeable: recording_storage_result.recording_storage_is_writeable,
                    recording_storage_total_space: recording_storage_result.recording_storage_total_space,
                    recording_storage_available_space: recording_storage_result.recording_storage_available_space,
                },
            });
        }
        OP_PUSH_TOKEN => {
            let PushTokenParams { .. } = from_params(operation.params).map_err(PreflightError::invalid_params)?;

            return Err(PreflightError::new(
                PreflightAlertStatus::GeneralFailure,
                "unimplemented",
            ));
        }
        OP_PUSH_CREDENTIALS => {
            let PushCredentialsParams { .. } = from_params(operation.params).map_err(PreflightError::invalid_params)?;

            return Err(PreflightError::new(
                PreflightAlertStatus::GeneralFailure,
                "unimplemented",
            ));
        }
        OP_LOOKUP_HOST => {
            let LookupHostParams { host } = from_params(operation.params).map_err(PreflightError::invalid_params)?;

            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .inspect_err(|error| warn!(%operation.id, error = format!("{error:#}"), %host, "Failed to lookup host"))
                .map_err(|_| {
                    PreflightError::new(
                        PreflightAlertStatus::HostLookupFailure,
                        format!("failed to lookup host {host}"),
                    )
                })?;

            outputs.push(PreflightOutput {
                operation_id: operation.id,
                kind: PreflightOutputKind::ResolvedHost {
                    host: host.clone(),
                    addresses: addresses.map(|addr| addr.ip()).collect(),
                },
            });
        }
        unsupported_op => {
            return Err(PreflightError::new(
                PreflightAlertStatus::UnsupportedOperation,
                format!("unsupported operation: {unsupported_op}"),
            ))
        }
    }

    Ok(())
}

fn from_params<T: de::DeserializeOwned>(params: serde_json::Map<String, serde_json::Value>) -> serde_json::Result<T> {
    serde_json::from_value(serde_json::Value::Object(params))
}
