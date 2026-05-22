//! Data models for UniGetUI package broker protocol.
//!
//! These types are designed so that:
//! 1. They serialize/deserialize from/to JSON matching the wire protocol
//! 2. `schemars::JsonSchema` generates schemas close to the hand-authored ones in UniGetUI
//! 3. `jsonschema` can validate incoming JSON against these generated schemas
//!
//! Reference schemas:
//! - `unigetui.package-request.schema.1.0.json`
//! - `unigetui.package-broker-response.schema.1.0.json`
//! - `unigetui.package-policy.schema.1.0.json`

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════════
// Shared enumerations
// ═══════════════════════════════════════════════════════════════════════════════

/// Package operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Install,
    Update,
    Uninstall,
}

/// Package installation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Machine,
}

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86,
    X64,
    Arm32,
    Arm64,
    Neutral,
}

/// Supported package manager names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ManagerName {
    Winget,
    PowerShell,
}

/// Policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

/// Requested elevation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Elevation {
    Standard,
    Elevated,
}

/// Broker transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    HttpNamedPipe,
    HttpLoopbackSimulator,
}

/// Execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    SimulatedElevated,
    Elevated,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Request models
// ═══════════════════════════════════════════════════════════════════════════════

/// Canonical request sent by an unelevated UniGetUI process to the elevated broker.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PackageRequest {
    /// JSON Schema URI (ignored at runtime).
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// The request syntax version (semver).
    pub request_version: String,

    /// Must be `"packageOperation"`.
    pub request_type: String,

    /// Unique client-generated request id for audit correlation.
    pub request_id: String,

    /// UTC timestamp when the client created the request.
    pub created_at: String,

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
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestManager {
    /// Package manager name.
    pub name: ManagerName,

    /// Human-readable display name.
    pub display_name: String,

    /// Friendly name of the manager executable.
    pub executable_friendly_name: String,
}

/// Source/repository metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestSource {
    /// Source name (e.g., "winget", "msstore").
    pub name: String,

    /// Source URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Whether this is a virtual manager source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_virtual_manager: Option<bool>,
}

/// Package identification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestPackage {
    /// Package identifier (e.g., "Publisher.Package" for WinGet).
    pub id: String,

    /// Human-readable package name.
    pub name: String,

    /// Currently installed version (for update/uninstall).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Target version (for update operations).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_version: Option<String>,

    /// Release channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

/// Options controlling the package operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestOptions {
    /// Installation scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,

    /// Target architecture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<Architecture>,

    /// Requested install version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

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
    pub custom_install_location: Option<String>,

    /// Additional command-line parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_parameters: Option<Vec<String>>,

    /// Command to execute before the package operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_operation_command: Option<String>,

    /// Command to execute after the package operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_operation_command: Option<String>,

    /// Processes to kill before running the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_before_operation: Option<Vec<String>>,
}

/// Broker context provided by the client.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerContext {
    /// Elevation level requested.
    pub requested_elevation: Elevation,

    /// Windows identity of the calling user.
    pub effective_user: String,

    /// Version of the UniGetUI client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,

    /// File path of the client process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_process_path: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Response models
// ═══════════════════════════════════════════════════════════════════════════════

/// Canonical response returned by the broker after evaluating a request.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerResponse {
    /// Response syntax version (semver).
    pub response_version: String,

    /// Must be `"packageBrokerResponse"`.
    pub response_type: String,

    /// Broker identity and capabilities.
    pub broker: BrokerInfo,

    /// Server-generated audit identifier.
    pub audit_id: String,

    /// Echoed request id (null if request was invalid).
    pub request_id: Option<String>,

    /// UTC timestamp when broker received the request.
    pub received_at: String,

    /// UTC timestamp when broker completed evaluation.
    pub completed_at: String,

    /// Manager name from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,

    /// Source name from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Package identifier from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,

    /// Operation from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,

    /// The evaluation decision.
    pub decision: Decision,

    /// The rule that produced the decision.
    pub rule_id: String,

    /// Human-readable reason for the decision.
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
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerInfo {
    /// Broker display name.
    pub name: String,

    /// Protocol version (e.g., "1.0").
    pub protocol_version: String,

    /// Transport mechanism.
    pub transport: Transport,

    /// Named pipe path (when transport is http-named-pipe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipe_name: Option<String>,

    /// Whether the broker is running in simulated elevation mode.
    pub elevated_simulation: bool,
}

/// Summary of policy used for the decision.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ResponsePolicyInfo {
    /// Policy document identifier.
    pub id: String,

    /// Policy revision number.
    pub revision: u32,

    /// Policy syntax version.
    pub policy_version: String,
}

/// Execution outcome details.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ExecutionInfo {
    /// Execution mode.
    pub mode: ExecutionMode,

    /// Command that was or would be executed.
    pub command: Vec<String>,

    /// Additional note about execution.
    pub note: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Policy models
// ═══════════════════════════════════════════════════════════════════════════════

/// A policy document governing which package operations are allowed or denied.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// JSON Schema URI (ignored at runtime).
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Policy syntax version (semver).
    pub policy_version: String,

    /// Must be `"packageBrokerPolicy"`.
    pub policy_type: String,

    /// Policy metadata.
    pub metadata: PolicyMetadata,

    /// Enforcement configuration.
    pub enforcement: PolicyEnforcement,

    /// Ordered list of policy rules.
    pub rules: Vec<PolicyRule>,
}

/// Policy metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyMetadata {
    /// Unique policy identifier.
    pub id: String,

    /// Organization that published the policy.
    pub publisher: String,

    /// Monotonically increasing revision number.
    pub revision: u32,

    /// ISO 8601 publication timestamp.
    pub published_at: String,

    /// Policy becomes active at this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,

    /// Policy expires at this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// URL for support or documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_url: Option<String>,
}

/// Enforcement configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyEnforcement {
    /// Decision when no rule matches.
    pub default_decision: Decision,

    /// Decision on validation/parsing failure (must be "deny").
    pub failure_decision: FailureDecision,

    /// Rule precedence strategy (must be "priorityThenDeny").
    pub rule_precedence: RulePrecedence,

    /// When true, broker logs decisions but does not enforce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_mode: Option<bool>,
}

/// Failure decision — always deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum FailureDecision {
    #[serde(rename = "deny")]
    Deny,
}

/// Rule precedence strategy — always priorityThenDeny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum RulePrecedence {
    #[serde(rename = "priorityThenDeny")]
    PriorityThenDeny,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Unique rule identifier.
    pub id: String,

    /// Whether the rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Priority (lower = higher precedence).
    pub priority: u32,

    /// Decision if this rule matches.
    pub decision: Decision,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Reason reported to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Match criteria — request must satisfy all specified fields.
    #[serde(rename = "match")]
    pub match_criteria: PolicyMatch,

    /// Additional constraints applied after matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<PolicyConstraints>,
}

fn default_true() -> bool {
    true
}

/// Match criteria for a policy rule. All specified fields must match.
/// At least one field must be present.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyMatch {
    /// Allowed operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<Operation>>,

    /// Allowed managers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managers: Option<Vec<ManagerName>>,

    /// Source patterns (wildcard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,

    /// Package identifier patterns (wildcard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_identifiers: Option<Vec<String>>,

    /// Package name patterns (wildcard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_names: Option<Vec<String>>,

    /// Exact version list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,

    /// Semantic version range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_range: Option<VersionRange>,

    /// Allowed scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<Scope>>,

    /// Allowed architectures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<Architecture>>,

    /// Allowed elevation levels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevation: Option<Vec<Elevation>>,

    /// Allowed runAsAdministrator values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_administrator: Option<Vec<bool>>,

    /// Allowed interactive values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interactive: Option<Vec<bool>>,

    /// Allowed skipHashCheck values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_hash_check: Option<Vec<bool>>,

    /// Allowed preRelease values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_release: Option<Vec<bool>>,

    /// Whether request has custom parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_custom_parameters: Option<Vec<bool>>,

    /// Whether request has custom install location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_custom_install_location: Option<Vec<bool>>,

    /// Whether request has pre/post operation commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_pre_post_commands: Option<Vec<bool>>,

    /// Whether request has kill-before-operation entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_kill_before_operation: Option<Vec<bool>>,
}

/// Semantic version range for matching.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    /// Minimum version (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,

    /// Maximum version (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<String>,

    /// Whether to include pre-release versions.
    #[serde(default)]
    pub include_prerelease: bool,
}

/// Constraints applied after a rule matches.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyConstraints {
    /// Allow interactive mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_interactive: Option<bool>,

    /// Allow running as administrator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_run_as_administrator: Option<bool>,

    /// Allow skipping hash verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_skip_hash_check: Option<bool>,

    /// Allow pre-release versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_pre_release: Option<bool>,

    /// Allow custom install location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_custom_install_location: Option<bool>,

    /// Glob patterns for allowed install locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_install_location_patterns: Option<Vec<String>>,

    /// Allow custom parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_custom_parameters: Option<bool>,

    /// Exact allowed custom parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_custom_parameters: Option<Vec<String>>,

    /// Glob patterns for allowed custom parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_custom_parameter_patterns: Option<Vec<String>>,

    /// Denied custom parameters (deny takes precedence over allow).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_custom_parameters: Option<Vec<String>>,

    /// Allow pre/post operation commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_pre_post_commands: Option<bool>,

    /// Allow killing processes before operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_kill_before_operation: Option<bool>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper types for evaluation
// ═══════════════════════════════════════════════════════════════════════════════

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
        let custom_location = request.options.custom_install_location.clone().unwrap_or_default();
        let has_pre_post =
            request.options.pre_operation_command.is_some() || request.options.post_operation_command.is_some();
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

// ═══════════════════════════════════════════════════════════════════════════════
// Display implementations for enums (used in logging/responses)
// ═══════════════════════════════════════════════════════════════════════════════

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Install => f.write_str("install"),
            Self::Update => f.write_str("update"),
            Self::Uninstall => f.write_str("uninstall"),
        }
    }
}

impl std::fmt::Display for ManagerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Winget => f.write_str("Winget"),
            Self::PowerShell => f.write_str("PowerShell"),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => f.write_str("user"),
            Self::Machine => f.write_str("machine"),
        }
    }
}

impl std::fmt::Display for Elevation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => f.write_str("standard"),
            Self::Elevated => f.write_str("elevated"),
        }
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => f.write_str("x86"),
            Self::X64 => f.write_str("x64"),
            Self::Arm32 => f.write_str("arm32"),
            Self::Arm64 => f.write_str("arm64"),
            Self::Neutral => f.write_str("neutral"),
        }
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimulatedElevated => f.write_str("simulated-elevated"),
            Self::Elevated => f.write_str("elevated"),
        }
    }
}
