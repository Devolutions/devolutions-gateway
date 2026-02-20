use std::net::IpAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use devolutions_agent_shared::get_installed_agent_version;
use serde::de;
use time::Duration;
use tracing::{Instrument as _, Span};
use uuid::Uuid;

use crate::DgwState;
use crate::config::Conf;
use crate::credential::{AppCredentialMapping, CredentialStoreHandle};
use crate::extract::PreflightScope;
use crate::http::HttpError;
use crate::session::SessionMessageSender;

const OP_GET_VERSION: &str = "get-version";
const OP_GET_AGENT_VERSION: &str = "get-agent-version";
const OP_GET_RUNNING_SESSION_COUNT: &str = "get-running-session-count";
const OP_GET_RECORDING_STORAGE_HEALTH: &str = "get-recording-storage-health";
const OP_PROVISION_TOKEN: &str = "provision-token";
const OP_PROVISION_CREDENTIALS: &str = "provision-credentials";
const OP_RESOLVE_HOST: &str = "resolve-host";

const DEFAULT_TTL: Duration = Duration::minutes(15);
const MAX_TTL: Duration = Duration::hours(2);

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PreflightOperation {
    id: Uuid,
    kind: String,
    #[serde(flatten)]
    params: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ProvisionTokenParams {
    token: String,
    time_to_live: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ProvisionCredentialsParams {
    token: String,
    #[serde(flatten)]
    mapping: AppCredentialMapping,
    time_to_live: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ResolveHostParams {
    #[serde(rename = "host_to_resolve")]
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
    #[serde(rename = "ack")]
    Ack,
}

#[allow(
    unused,
    reason = "all values are still part of the public HTTP API even if we stop emitting them later"
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub(crate) enum PreflightAlertStatus {
    #[serde(rename = "general-failure")]
    GeneralFailure,
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "unsupported-operation")]
    UnsupportedOperation,
    #[serde(rename = "invalid-parameters")]
    InvalidParams,
    #[serde(rename = "internal-server-error")]
    InternalServerError,
    #[serde(rename = "host-resolution-failure")]
    HostResolutionFailure,
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
        conf_handle,
        sessions,
        credential_store,
        ..
    }): State<DgwState>,
    _scope: PreflightScope,
    Json(operations): Json<Vec<PreflightOperation>>,
) -> Result<Json<Vec<PreflightOutput>>, HttpError> {
    // Log operations with sensitive fields redacted.
    if tracing::enabled!(tracing::Level::DEBUG) {
        let mut redacted_operations = operations.clone();
        for operation in &mut redacted_operations {
            for value in operation.params.values_mut() {
                redact_sensitive_fields(value);
            }
        }
        debug!(operations = ?redacted_operations, "Preflight operations");
    }

    let outputs = Outputs::with_capacity(operations.len());

    let handles = operations
        .into_iter()
        .map(|operation| {
            tokio::spawn({
                let span = Span::current();
                let outputs = outputs.clone();
                let conf = conf_handle.get_conf();
                let sessions = sessions.clone();
                let credential_store = credential_store.clone();

                async move {
                    let operation_id = operation.id;
                    trace!(%operation.id, "Process preflight operation");

                    if let Err(error) = handle_operation(operation, &outputs, &conf, &sessions, &credential_store).await
                    {
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
    credential_store: &CredentialStoreHandle,
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
        OP_PROVISION_TOKEN | OP_PROVISION_CREDENTIALS => {
            let (token, time_to_live, mapping) = if operation.kind.as_str() == OP_PROVISION_TOKEN {
                let ProvisionTokenParams { token, time_to_live } =
                    from_params(operation.params).map_err(PreflightError::invalid_params)?;
                (token, time_to_live, None)
            } else {
                let ProvisionCredentialsParams {
                    token,
                    mapping,
                    time_to_live,
                } = from_params(operation.params).map_err(PreflightError::invalid_params)?;
                (token, time_to_live, Some(mapping))
            };

            let time_to_live = time_to_live
                .map(i64::from)
                .map(Duration::seconds)
                .unwrap_or(DEFAULT_TTL);

            if time_to_live > MAX_TTL {
                return Err(PreflightError {
                    status: PreflightAlertStatus::InvalidParams,
                    message: format!(
                        "provided time_to_live ({time_to_live}) is exceeding the maximum TTL duration ({MAX_TTL})"
                    ),
                });
            }

            let previous_entry = credential_store
                .insert(token, mapping, time_to_live)
                .inspect_err(
                    |error| warn!(%operation.id, error = format!("{error:#}"), "Failed to count running sessions"),
                )
                .map_err(|e| PreflightError::new(PreflightAlertStatus::InvalidParams, format!("{e:#}")))?;

            if previous_entry.is_some() {
                outputs.push(PreflightOutput {
                    operation_id: operation.id,
                    kind: PreflightOutputKind::Alert {
                        status: PreflightAlertStatus::Info,
                        message: "an existing credential entry was replaced".to_owned(),
                    },
                });
            }

            outputs.push(PreflightOutput {
                operation_id: operation.id,
                kind: PreflightOutputKind::Ack,
            });
        }
        OP_RESOLVE_HOST => {
            let ResolveHostParams { host } = from_params(operation.params).map_err(PreflightError::invalid_params)?;

            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .inspect_err(
                    |error| warn!(%operation.id, error = format!("{error:#}"), %host, "Failed to resolve host"),
                )
                .map_err(|_| {
                    PreflightError::new(
                        PreflightAlertStatus::HostResolutionFailure,
                        format!("failed to resolve host {host}"),
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
            ));
        }
    }

    Ok(())
}

fn from_params<T: de::DeserializeOwned>(params: serde_json::Map<String, serde_json::Value>) -> serde_json::Result<T> {
    serde_json::from_value(serde_json::Value::Object(params))
}

/// Redacts sensitive fields in JSON values.
///
/// This function recursively traverses a JSON value and replaces any field
/// with a key name of "password" with the string "***REDACTED***".
fn redact_sensitive_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if key.eq_ignore_ascii_case("password") {
                    *val = serde_json::Value::String("***REDACTED***".to_owned());
                } else {
                    // Recursively redact nested objects and arrays.
                    redact_sensitive_fields(val);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                redact_sensitive_fields(item);
            }
        }
        _ => {
            // Nothing to redact in primitives (String, Number, Bool, Null).
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case::simple_password(
        serde_json::json!({"username": "admin", "password": "secret123"}),
        serde_json::json!({"username": "admin", "password": "***REDACTED***"})
    )]
    #[case::nested_password(
        serde_json::json!({
            "credential": {
                "kind": "username-password",
                "username": "user",
                "password": "super-secret"
            }
        }),
        serde_json::json!({
            "credential": {
                "kind": "username-password",
                "username": "user",
                "password": "***REDACTED***"
            }
        })
    )]
    #[case::case_insensitive(
        serde_json::json!({"PASSWORD": "secret", "Password": "secret2"}),
        serde_json::json!({"PASSWORD": "***REDACTED***", "Password": "***REDACTED***"})
    )]
    #[case::array_with_passwords(
        serde_json::json!([
            {"username": "user1", "password": "pass1"},
            {"username": "user2", "password": "pass2"}
        ]),
        serde_json::json!([
            {"username": "user1", "password": "***REDACTED***"},
            {"username": "user2", "password": "***REDACTED***"}
        ])
    )]
    fn test_redact_sensitive_fields(#[case] mut input: serde_json::Value, #[case] expected: serde_json::Value) {
        redact_sensitive_fields(&mut input);
        assert_eq!(input, expected);
    }
}
