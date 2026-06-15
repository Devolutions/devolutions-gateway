//! Meta-endpoint models: health, capabilities, and error responses.
//!
//! These describe the bodies returned by `GET /v1/health`, `GET /v1/capabilities`,
//! and the generic error payloads so that every endpoint is fully described in the
//! generated OpenAPI document.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ProtocolVersion;
use super::enums::{ManagerName, Operation, Transport};

/// Broker readiness state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "HealthStatus")]
pub enum HealthStatus {
    /// Broker has a valid policy and is serving requests.
    Ready,
    /// Broker is paused (policy file missing or corrupted).
    Paused,
}

/// Response body for `GET /v1/health`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "HealthResponse")]
#[serde(rename_all = "PascalCase")]
pub struct HealthResponse {
    /// Whether the broker is ready or paused.
    pub status: HealthStatus,

    /// Wire protocol version implemented by the broker.
    pub protocol_version: ProtocolVersion,

    /// Whether the broker runs in elevated-simulation (development) mode.
    pub elevated_simulation: bool,

    /// Identifier of the active policy (empty when paused).
    pub policy_id: String,

    /// The set of routes exposed by the broker.
    pub endpoints: Vec<String>,
}

/// Response body for `GET /v1/capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "CapabilitiesResponse")]
#[serde(rename_all = "PascalCase")]
pub struct CapabilitiesResponse {
    /// Wire protocol version implemented by the broker.
    pub protocol_version: ProtocolVersion,

    /// Supported transports.
    pub transports: Vec<Transport>,

    /// Accepted request media types.
    pub request_media_types: Vec<String>,

    /// Produced response media types.
    pub response_media_types: Vec<String>,

    /// Package managers the broker can operate.
    pub supported_managers: Vec<ManagerName>,

    /// Operations the broker can perform.
    pub supported_operations: Vec<Operation>,

    /// Maximum accepted request body size, in bytes.
    pub max_request_body_bytes: u64,

    /// Name of the named pipe the broker listens on.
    pub pipe_name: String,
}

/// Generic error body returned for failures not described by a `BrokerResponse`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "ErrorResponse")]
#[serde(rename_all = "PascalCase")]
pub struct ErrorResponse {
    /// Short, machine-stable error label.
    pub error: String,

    /// Optional human-readable elaboration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Optional audit identifier correlating server logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_id: Option<String>,
}
