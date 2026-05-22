//! Data models for UniGetUI package broker protocol.
//!
//! These types correspond to the schemas defined in the UniGetUI policies folder:
//! - `unigetui.package-request.schema.1.0.json`
//! - `unigetui.package-broker-response.schema.1.0.json`
//! - `unigetui.package-policy.schema.1.0.json`

use serde::{Deserialize, Serialize};

// === Request Models ===

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageRequest {
    pub request_version: String,
    pub request_type: String,
    pub request_id: String,
    pub created_at: String,
    pub operation: String,
    pub manager: RequestManager,
    pub source: RequestSource,
    pub package: RequestPackage,
    pub options: RequestOptions,
    pub broker: BrokerContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestManager {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub executable_friendly_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestSource {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub is_virtual_manager: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPackage {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub new_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub interactive: Option<bool>,
    #[serde(default)]
    pub run_as_administrator: Option<bool>,
    #[serde(default)]
    pub skip_hash_check: Option<bool>,
    #[serde(default)]
    pub pre_release: Option<bool>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub custom_parameters: Option<Vec<String>>,
    #[serde(default)]
    pub custom_install_location: Option<String>,
    #[serde(default)]
    pub kill_before_operation: Option<Vec<String>>,
    #[serde(default)]
    pub pre_operation_command: Option<String>,
    #[serde(default)]
    pub post_operation_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerContext {
    pub requested_elevation: String,
    pub effective_user: String,
    pub client_version: String,
}

// === Response Models ===

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerResponse {
    pub response_version: String,
    pub response_type: String,
    pub broker: BrokerInfo,
    pub audit_id: String,
    pub request_id: Option<String>,
    pub received_at: String,
    pub completed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    pub decision: String,
    pub rule_id: String,
    pub reason: String,
    pub would_execute: bool,
    pub policy: PolicyInfo,
    pub execution: ExecutionInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerInfo {
    pub name: String,
    pub protocol_version: String,
    pub transport: String,
    pub pipe_name: String,
    pub elevated_simulation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyInfo {
    pub id: String,
    pub revision: u32,
    pub default_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionInfo {
    pub mode: String,
    pub command: Vec<String>,
}

// === Policy Models ===

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDocument {
    #[serde(default)]
    pub policy_version: String,
    pub policy_type: String,
    pub metadata: PolicyMetadata,
    pub enforcement: PolicyEnforcement,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyMetadata {
    pub id: String,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub revision: u32,
    #[serde(default)]
    pub published_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEnforcement {
    pub default_decision: String,
    pub failure_decision: String,
    pub rule_precedence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRule {
    pub id: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub priority: i32,
    pub decision: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(rename = "match")]
    pub match_criteria: PolicyMatch,
    #[serde(default)]
    pub constraints: Option<PolicyConstraints>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyMatch {
    #[serde(default)]
    pub operations: Option<Vec<String>>,
    #[serde(default)]
    pub managers: Option<Vec<String>>,
    #[serde(default)]
    pub sources: Option<Vec<String>>,
    #[serde(default)]
    pub package_identifiers: Option<Vec<String>>,
    #[serde(default)]
    pub package_names: Option<Vec<String>>,
    #[serde(default)]
    pub versions: Option<Vec<String>>,
    #[serde(default)]
    pub version_range: Option<VersionRange>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub architectures: Option<Vec<String>>,
    #[serde(default)]
    pub elevation: Option<Vec<String>>,
    #[serde(default)]
    pub run_as_administrator: Option<Vec<bool>>,
    #[serde(default)]
    pub interactive: Option<Vec<bool>>,
    #[serde(default)]
    pub skip_hash_check: Option<Vec<bool>>,
    #[serde(default)]
    pub pre_release: Option<Vec<bool>>,
    #[serde(default)]
    pub has_custom_parameters: Option<Vec<bool>>,
    #[serde(default)]
    pub has_custom_install_location: Option<Vec<bool>>,
    #[serde(default)]
    pub has_pre_post_commands: Option<Vec<bool>>,
    #[serde(default)]
    pub has_kill_before_operation: Option<Vec<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionRange {
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub max_version: Option<String>,
    #[serde(default)]
    pub include_prerelease: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConstraints {
    #[serde(default)]
    pub allow_interactive: Option<bool>,
    #[serde(default)]
    pub allow_run_as_administrator: Option<bool>,
    #[serde(default)]
    pub allow_skip_hash_check: Option<bool>,
    #[serde(default)]
    pub allow_pre_release: Option<bool>,
    #[serde(default)]
    pub allow_custom_install_location: Option<bool>,
    #[serde(default)]
    pub allowed_install_location_patterns: Option<Vec<String>>,
    #[serde(default)]
    pub allow_custom_parameters: Option<bool>,
    #[serde(default)]
    pub allowed_custom_parameters: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_custom_parameter_patterns: Option<Vec<String>>,
    #[serde(default)]
    pub denied_custom_parameters: Option<Vec<String>>,
    #[serde(default)]
    pub allow_pre_post_commands: Option<bool>,
    #[serde(default)]
    pub allow_kill_before_operation: Option<bool>,
}

// === Helper types for evaluation ===

/// Derived boolean flags from a request, used for policy matching.
pub struct RequestFlags {
    pub has_custom_parameters: bool,
    pub has_custom_install_location: bool,
    pub has_pre_post_commands: bool,
    pub has_kill_before_operation: bool,
    pub custom_parameters: Vec<String>,
    pub custom_install_location: String,
}

impl RequestFlags {
    pub fn from_request(request: &PackageRequest) -> Self {
        let custom_params = request.options.custom_parameters.clone().unwrap_or_default();
        let custom_location = request
            .options
            .custom_install_location
            .clone()
            .unwrap_or_default();
        let has_pre_post = request.options.pre_operation_command.is_some()
            || request.options.post_operation_command.is_some();
        let kill_before = request.options.kill_before_operation.clone().unwrap_or_default();

        Self {
            has_custom_parameters: !custom_params.is_empty(),
            has_custom_install_location: !custom_location.is_empty(),
            has_pre_post_commands: has_pre_post,
            has_kill_before_operation: !kill_before.is_empty(),
            custom_parameters: custom_params,
            custom_install_location: custom_location,
        }
    }
}
