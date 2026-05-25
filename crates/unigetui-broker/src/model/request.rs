//! Request models.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::enums::{Architecture, Elevation, ManagerName, Operation, Scope};
use super::markers::{PackageOperation, RequestSchemaUri};
use super::newtypes::{CustomParameterString, PackageIdentifier, ProcessName, ResourceId, SemanticVersion};

/// Canonical request sent by an unelevated UniGetUI process to the elevated broker.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "packageRequest")]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PackageRequest {
    /// Request schema URI constant.
    #[serde(rename = "$schema")]
    pub _schema: RequestSchemaUri,

    /// The request syntax version (semver).
    pub request_version: SemanticVersion,

    /// Must be `"packageOperation"`.
    pub request_type: PackageOperation,

    /// Unique client-generated request id for audit correlation.
    pub request_id: ResourceId,

    /// UTC timestamp when the client created the request (RFC 3339).
    pub created_at: DateTime<Utc>,

    /// The package operation to perform.
    pub operation: Operation,

    /// Package manager information.
    pub manager: RequestManager,

    /// Source/repository information.
    pub source: RequestSource,

    /// Package information.
    pub package: RequestPackage,

    /// Operation options.
    pub options: RequestOptions,

    /// Broker context from the client.
    pub broker: BrokerContext,
}

/// Package manager metadata from the request.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "requestManager")]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestManager {
    /// Package manager name.
    pub name: ManagerName,

    /// Human-readable display name.
    #[schemars(length(min = 1, max = 128))]
    pub display_name: String,

    /// Friendly name of the executable.
    #[schemars(length(min = 1, max = 128))]
    pub executable_friendly_name: String,
}

/// Package source/repository information.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "requestSource")]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestSource {
    /// Source name.
    #[schemars(length(min = 1, max = 128))]
    pub name: String,

    /// Optional source URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub url: Option<String>,

    /// Whether this is a virtual manager (runs without a real CLI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_virtual_manager: Option<bool>,
}

/// Package information.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "requestPackage")]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestPackage {
    /// Package identifier (e.g., "Publisher.Package" for WinGet).
    pub id: PackageIdentifier,

    /// Human-readable package name.
    #[schemars(length(min = 1, max = 256))]
    pub name: String,

    /// Target version (for update/install operations).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<SemanticVersion>,

    /// Target architecture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<Architecture>,

    /// Release channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 16))]
    pub channel: Option<String>,
}

/// Options controlling the package operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "requestOptions")]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestOptions {
    /// Installation scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,

    /// Run interactively (show installer UI).
    pub interactive: bool,

    /// Run the process as administrator.
    pub run_as_administrator: bool,

    /// Skip package hash verification.
    pub skip_hash_check: bool,

    /// Allow pre-release versions.
    pub pre_release: bool,

    /// Custom install directory path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub custom_install_location: Option<String>,

    /// Additional command-line parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub custom_parameters: Vec<CustomParameterString>,

    /// Command to execute before the package operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub pre_operation_command: Option<String>,

    /// Command to execute after the package operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub post_operation_command: Option<String>,

    /// Processes to kill before running the operation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub kill_before_operation: Vec<ProcessName>,

    /// Whether to uninstall previous version before installing update.
    #[serde(default)]
    pub uninstall_previous: bool,

    /// Whether to skip upgrade if an existing version is detected (for install operations).
    #[serde(default)]
    pub no_upgrade: bool,
}

/// Broker context provided by the client.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "brokerContext")]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerContext {
    /// Elevation level requested.
    pub requested_elevation: Elevation,

    /// Windows identity of the calling user.
    #[schemars(length(min = 1, max = 256))]
    pub effective_user: String,

    /// Version of the UniGetUI client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub client_version: Option<String>,

    /// File path of the client process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub client_process_path: Option<String>,
}
