//! Status query request and response models.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ResourceId;
use super::enums::OperationStatus;
use super::request::BrokerContext;
use super::response::BrokerInfo;

/// Request to query the status of a previously submitted package operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "StatusRequest")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    /// The `requestId` of the original package operation to query.
    pub request_id: ResourceId,

    /// Broker context from the client.
    pub broker: BrokerContext,
}

/// Response to a status query.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "StatusResponse")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
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

    /// Human-readable note about the status. For failures this carries the short error
    /// summary (e.g. "winget.exe exited with code 0x8A150011", or a process-launch error).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub note: Option<String>,

    /// Captured combined stdout+stderr of the operation (UTF-8, tail-truncated to ~10 KiB).
    /// Only present when the original request opted in via `CaptureOutput`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 16384))]
    pub stdout: Option<String>,
}
