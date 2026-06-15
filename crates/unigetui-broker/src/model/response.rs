//! Response models.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::enums::{Decision, ExecutionMode, Operation, Transport};
use super::{CommandString, PackageIdentifier, ProtocolVersion, ResourceId, RuleId, SemanticVersion};

/// Canonical response returned by the broker after evaluating a request.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "BrokerResponse")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerResponse {
    /// Broker identity and capabilities.
    pub broker: BrokerInfo,

    /// Server-generated audit identifier.
    pub audit_id: ResourceId,

    /// Echoed request id.
    pub request_id: ResourceId,

    /// UTC timestamp when broker received the request (RFC 3339).
    pub received_at: DateTime<Utc>,

    /// UTC timestamp when broker completed evaluation (RFC 3339).
    pub completed_at: DateTime<Utc>,

    /// Manager name from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    pub manager: Option<String>,

    /// Source name from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    pub source: Option<String>,

    /// Package identifier from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_id: Option<PackageIdentifier>,

    /// Operation from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,

    /// The evaluation decision.
    pub decision: Decision,

    /// The rule that produced the decision.
    pub rule_id: RuleId,

    /// Human-readable reason for the decision.
    #[schemars(length(min = 1, max = 2048))]
    pub reason: String,

    /// Whether the broker would execute a command for this decision.
    pub would_execute: bool,

    /// Summary of the policy used.
    pub policy: ResponsePolicyInfo,

    /// Execution details.
    pub execution: ExecutionInfo,
}

/// Broker identity information in responses.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "BrokerInfo")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerInfo {
    /// Broker display name.
    #[schemars(length(min = 1, max = 128))]
    pub name: String,

    /// Protocol version (e.g., "1.0").
    pub protocol_version: ProtocolVersion,

    /// Transport mechanism.
    pub transport: Transport,

    /// Named pipe path (when transport is http-named-pipe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    pub pipe_name: Option<String>,

    /// Whether the broker is running in simulated elevation mode.
    pub elevated_simulation: bool,
}

/// Summary of policy used for the decision.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "ResponsePolicyInfo")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct ResponsePolicyInfo {
    /// Policy document identifier.
    pub id: ResourceId,

    /// Policy revision number.
    #[schemars(range(min = 1, max = 2147483647))]
    pub revision: u32,

    /// Policy syntax version.
    pub policy_version: SemanticVersion,
}

/// Execution outcome details.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "ExecutionInfo")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct ExecutionInfo {
    /// Execution mode.
    pub mode: ExecutionMode,

    /// Command that was or would be executed.
    #[schemars(length(max = 256))]
    pub command: Vec<CommandString>,

    /// Additional note about execution.
    #[schemars(length(min = 1, max = 2048))]
    pub note: String,
}
