//! Policy models.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::enums::{Architecture, Decision, Elevation, ManagerName, Operation, Scope};
use super::markers::{PackageBrokerPolicy, PolicySchemaUri};
use super::newtypes::{CustomParameterString, HttpUrl, ResourceId, SemanticVersion, StringPattern, VersionString};
use super::request::PackageRequest;

/// A policy document governing which package operations are allowed or denied.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "PolicyDocument")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Policy schema URI constant.
    #[serde(rename = "$schema")]
    pub _schema: PolicySchemaUri,

    /// Policy syntax version (semver).
    pub policy_version: SemanticVersion,

    /// Must be `"packageBrokerPolicy"`.
    pub policy_type: PackageBrokerPolicy,

    /// Policy metadata.
    pub metadata: PolicyMetadata,

    /// Enforcement configuration.
    pub enforcement: PolicyEnforcement,

    /// Ordered list of policy rules (may be empty; enforcement defaults apply).
    #[schemars(length(max = 1024))]
    pub rules: Vec<PolicyRule>,
}

/// Policy metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "PolicyMetadata")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyMetadata {
    /// Unique policy identifier.
    pub id: ResourceId,

    /// Organization that published the policy.
    #[schemars(length(min = 1, max = 128))]
    pub publisher: String,

    /// Monotonically increasing revision number.
    #[schemars(range(min = 1, max = 2147483647))]
    pub revision: u32,

    /// ISO 8601 publication timestamp (RFC 3339).
    pub published_at: DateTime<Utc>,

    /// Policy becomes active at this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,

    /// Policy expires at this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 512))]
    pub description: Option<String>,

    /// URL for support or documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_url: Option<HttpUrl>,
}

/// Enforcement configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "PolicyEnforcement")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyEnforcement {
    /// Decision when no rule matches.
    pub default_decision: Decision,

    /// Rule precedence strategy (must be "PriorityThenDeny").
    pub rule_precedence: RulePrecedence,

    /// When true, broker logs decisions but does not enforce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_mode: Option<bool>,
}

/// Rule precedence strategy — always PriorityThenDeny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "RulePrecedence")]
pub enum RulePrecedence {
    PriorityThenDeny,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "PolicyRule")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Unique rule identifier.
    pub id: ResourceId,

    /// Whether the rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Priority (lower = higher precedence).
    #[schemars(range(min = 0, max = 2147483647))]
    pub priority: u32,

    /// Decision if this rule matches.
    pub decision: Decision,

    /// Reason reported to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 512))]
    pub reason: Option<String>,

    /// Match criteria — request must satisfy all specified fields.
    /// At least one criterion must be present.
    #[serde(rename = "Match", deserialize_with = "deserialize_non_empty_match")]
    pub match_criteria: PolicyMatch,

    /// Additional constraints applied after matching.
    /// When absent, no constraints are enforced beyond the match criteria.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<PolicyConstraints>,
}

fn default_true() -> bool {
    true
}

/// Custom deserializer that rejects an empty match block.
fn deserialize_non_empty_match<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<PolicyMatch, D::Error> {
    let m = PolicyMatch::deserialize(deserializer)?;
    if m.is_empty() {
        return Err(serde::de::Error::custom("match must contain at least one criterion"));
    }
    Ok(m)
}

/// Match criteria for a policy rule. All specified fields must match.
/// At least one field must be present.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "PolicyMatch")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyMatch {
    /// Allowed operations.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 3))]
    pub operations: BTreeSet<Operation>,

    /// Allowed managers.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 16))]
    pub managers: BTreeSet<ManagerName>,

    /// Source patterns (wildcard).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 128))]
    pub sources: BTreeSet<StringPattern>,

    /// Package identifier patterns (wildcard).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 1024))]
    pub package_identifiers: BTreeSet<StringPattern>,

    /// Package name patterns (wildcard).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 1024))]
    pub package_names: BTreeSet<StringPattern>,

    /// Exact version list.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 256))]
    pub versions: BTreeSet<VersionString>,

    /// Semantic version range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_range: Option<VersionRange>,

    /// Allowed scopes.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub scopes: BTreeSet<Scope>,

    /// Allowed architectures.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 5))]
    pub architectures: BTreeSet<Architecture>,

    /// Allowed elevation levels.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub elevation: BTreeSet<Elevation>,

    /// Allowed interactive values.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub interactive: BTreeSet<bool>,

    /// Allowed skipHashCheck values.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub skip_hash_check: BTreeSet<bool>,

    /// Allowed preRelease values.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub pre_release: BTreeSet<bool>,

    /// Whether request has custom parameters.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub has_custom_parameters: BTreeSet<bool>,

    /// Whether request has custom install location.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub has_custom_install_location: BTreeSet<bool>,

    /// Whether request has pre/post operation commands.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub has_pre_post_commands: BTreeSet<bool>,

    /// Whether request has kill-before-operation entries.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub has_kill_before_operation: BTreeSet<bool>,

    /// Whether request has uninstall-previous flag set.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub has_uninstall_previous: BTreeSet<bool>,
}

impl PolicyMatch {
    /// Returns true if no criteria are specified.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
            && self.managers.is_empty()
            && self.sources.is_empty()
            && self.package_identifiers.is_empty()
            && self.package_names.is_empty()
            && self.versions.is_empty()
            && self.version_range.is_none()
            && self.scopes.is_empty()
            && self.architectures.is_empty()
            && self.elevation.is_empty()
            && self.interactive.is_empty()
            && self.skip_hash_check.is_empty()
            && self.pre_release.is_empty()
            && self.has_custom_parameters.is_empty()
            && self.has_custom_install_location.is_empty()
            && self.has_pre_post_commands.is_empty()
            && self.has_kill_before_operation.is_empty()
            && self.has_uninstall_previous.is_empty()
    }
}

/// Semantic version range for matching.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "VersionRange")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    /// Minimum version (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub min_version: Option<String>,

    /// Maximum version (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub max_version: Option<String>,

    /// Whether to include pre-release versions.
    #[serde(default)]
    pub include_prerelease: bool,
}

/// Constraints applied after a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(rename = "PolicyConstraints")]
#[serde(rename_all = "PascalCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyConstraints {
    /// Allow interactive mode.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_interactive: bool,

    /// Allow skipping hash verification.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_skip_hash_check: bool,

    /// Allow pre-release versions.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_pre_release: bool,

    /// Allow custom install location.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_custom_install_location: bool,

    /// Glob patterns for allowed install locations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub allowed_install_location_patterns: Vec<StringPattern>,

    /// Allow custom parameters.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_custom_parameters: bool,

    /// Exact allowed custom parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 128))]
    pub allowed_custom_parameters: Vec<CustomParameterString>,

    /// Glob patterns for allowed custom parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 128))]
    pub allowed_custom_parameter_patterns: Vec<CustomParameterString>,

    /// Denied custom parameters (deny takes precedence over allow).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 128))]
    pub denied_custom_parameters: Vec<CustomParameterString>,

    /// Allow pre/post operation commands.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_pre_post_commands: bool,

    /// Allow killing processes before operation.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_kill_before_operation: bool,

    /// Allow uninstalling previous version before installing update.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_uninstall_previous: bool,

    /// Allow skipping upgrade on install operations if an existing version
    /// is detected (for install operations).
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_upgrade: bool,
}

impl Default for PolicyConstraints {
    fn default() -> Self {
        Self {
            allow_interactive: true,
            allow_skip_hash_check: true,
            allow_pre_release: true,
            allow_custom_install_location: true,
            allowed_install_location_patterns: Vec::new(),
            allow_custom_parameters: true,
            allowed_custom_parameters: Vec::new(),
            allowed_custom_parameter_patterns: Vec::new(),
            denied_custom_parameters: Vec::new(),
            allow_pre_post_commands: true,
            allow_kill_before_operation: true,
            allow_uninstall_previous: true,
            allow_upgrade: true,
        }
    }
}

impl PolicyConstraints {
    /// Returns true if all fields are at their defaults (fully permissive).
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

fn is_true(v: &bool) -> bool {
    *v
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
    pub custom_parameters: Vec<CustomParameterString>,
    pub custom_install_location: String,
}

impl RequestFlags {
    pub fn from_request(request: &PackageRequest) -> Self {
        let custom_params = request.options.custom_parameters.clone();
        let custom_location = request.options.custom_install_location.clone().unwrap_or_default();
        let has_pre_post =
            request.options.pre_operation_command.is_some() || request.options.post_operation_command.is_some();
        let kill_before = &request.options.kill_before_operation;

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
