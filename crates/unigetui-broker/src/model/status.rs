//! Status query request and response models.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::enums::OperationStatus;
use super::markers::{
    PackageOperationStatusResponse, PackageOperationStatusType, StatusRequestSchemaUri, StatusResponseSchemaUri,
};
use super::newtypes::{ResourceId, SemanticVersion};
use super::request::BrokerContext;
use super::response::BrokerInfo;

/// Request to query the status of a previously submitted package operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "statusRequest")]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    /// Status request schema URI constant.
    #[serde(rename = "$schema")]
    pub _schema: StatusRequestSchemaUri,

    /// Request syntax version (semver).
    pub request_version: SemanticVersion,

    /// Must be `"packageOperationStatus"`.
    pub request_type: PackageOperationStatusType,

    /// The `requestId` of the original package operation to query.
    pub request_id: ResourceId,

    /// Broker context from the client.
    pub broker: BrokerContext,
}

/// Response to a status query.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "statusResponse")]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    /// Status response schema URI constant.
    #[serde(rename = "$schema")]
    pub _schema: StatusResponseSchemaUri,

    /// Response syntax version (semver).
    pub response_version: SemanticVersion,

    /// Must be `"packageOperationStatusResponse"`.
    pub response_type: PackageOperationStatusResponse,

    /// Broker identity and capabilities.
    pub broker: BrokerInfo,

    /// The original request id being queried.
    pub request_id: ResourceId,

    /// Current status of the operation.
    pub status: OperationStatus,

    /// UTC timestamp when the process was actually launched (null if not yet started).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    /// UTC timestamp when the operation completed or failed (null if still running).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    /// Process exit code (present when status is `completed`, or `failed` due to non-zero exit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Human-readable note about the status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub note: Option<String>,
}
