//! Policy evaluation engine.
//!
//! Implements the broker flow described in the package broker policies spec:
//! 1. Deny requests whose custom install location is not a plain local drive path
//! 2. Match enabled rules against request
//! 3. Sort by priority (lowest wins), deny wins on tie
//! 4. Fall back to `enforcement.defaultDecision`
//!
//! Matching fails closed for both decisions: when a request characteristic is in doubt,
//! such as an unknown package version, scope or architecture, Deny rules match and Allow rules do not.
//! Scope and architecture are unknown only when the package manager chooses them at execution time.
//!
//! Version conditions apply to install and update requests only; a rule with a version condition never
//! matches an uninstall request.
//! An install or update without a concrete version matches Deny rules with a version condition,
//! so clients should send the resolved version to pass them.
//!
//! # Custom parameters
//!
//! WinGet and Scoop custom parameters are passed to the package manager verbatim; the other managers
//! reject them.
//! Options that the policy model also expresses (install location, scope, architecture, interactivity,
//! hash-check skipping, upgrade behavior) are read from custom parameters and matched like the typed
//! request options.
//!
//! WinGet `--override` and `--custom` pass arbitrary arguments to the package installer, which the broker
//! cannot interpret; they make the install location unknown but are otherwise allowed when a rule allows
//! custom parameters.
//! An Allow rule that permits unrestricted custom parameters for elevated WinGet operations therefore lets
//! the caller pass arbitrary arguments to an installer running with administrator privileges.
//! For elevated WinGet rules, set `AllowCustomParameters` to `false`, or list `--override*` and
//! `--custom*` in `DeniedCustomParameters` (WinGet has no short forms for these options).

use now_policy::{Decision, PolicyDocument};
use now_policy_api::{Elevation, PackageRequest, Scope};

mod constraints;
mod custom_options;
mod identifier;
mod install_location;
mod matching;
mod version;
mod wildcard;

pub(crate) use wildcard::has_powershell_wildcard_syntax;

#[cfg(test)]
mod tests;

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub rule_id: String,
    pub reason: String,
}

/// Request characteristics as the package manager will apply them, including options set
/// through custom parameters.
struct RequestFlags {
    interactive: bool,
    skip_hash_check: bool,
    has_custom_parameters: bool,
    /// Whether an install location may be selected: one is supplied (including an empty one), or
    /// opaque installer arguments may select one.
    has_custom_install_location: bool,
    /// Whether the supplied install locations are not a single plain local drive path.
    has_unacceptable_install_location: bool,
    has_pre_post_commands: bool,
    has_kill_before_operation: bool,
    has_uninstall_previous: bool,
    no_upgrade: bool,
    /// Normalized custom install location, or `None` when it is absent, unknown or unacceptable.
    custom_install_location: Option<String>,
    custom_parameters: Vec<String>,
}

impl RequestFlags {
    fn from_request(request: &PackageRequest) -> Self {
        let custom = custom_options::custom_options(request.manager, &request.options.custom_parameters);

        let mut locations = request
            .options
            .custom_install_location
            .as_deref()
            .map(Some)
            .into_iter()
            .collect::<Vec<_>>();
        locations.extend(custom.locations.iter().copied());
        let supplied_location = match locations.as_slice() {
            [] => None,
            [Some(location)] => Some(install_location::normalize_install_location(location)),
            _ => Some(None),
        };

        Self {
            interactive: request.options.interactive || custom.interactive,
            skip_hash_check: request.options.skip_hash_check || custom.skip_hash_check,
            has_custom_parameters: !request.options.custom_parameters.is_empty(),
            has_custom_install_location: supplied_location.is_some() || custom.installer_arguments,
            has_unacceptable_install_location: matches!(supplied_location, Some(None)),
            has_pre_post_commands: request.options.pre_operation_command.is_some()
                || request.options.post_operation_command.is_some(),
            has_kill_before_operation: !request.options.kill_before_operation.is_empty(),
            has_uninstall_previous: request.options.uninstall_previous || custom.uninstall_previous,
            no_upgrade: request.options.no_upgrade || custom.no_upgrade,
            // Installer arguments may override a supplied location.
            custom_install_location: supplied_location.flatten().filter(|_| !custom.installer_arguments),
            custom_parameters: request
                .options
                .custom_parameters
                .iter()
                .map(|parameter| parameter.as_ref().to_owned())
                .collect(),
        }
    }
}

/// Whether the request supplies a custom install location that is not a single plain local drive path.
///
/// The server rejects such requests before policy evaluation so audit mode cannot override the rejection;
/// [`evaluate`] also denies them for direct callers.
pub(crate) fn has_unacceptable_install_location(request: &PackageRequest) -> bool {
    RequestFlags::from_request(request).has_unacceptable_install_location
}

/// Evaluate a parsed request against a parsed policy document.
///
/// Both the policy and request should have already been deserialized into typed structs.
/// This function performs the rule-matching logic only.
pub fn evaluate(policy: &PolicyDocument, request: &PackageRequest) -> PolicyDecision {
    let flags = RequestFlags::from_request(request);

    if flags.has_unacceptable_install_location {
        return PolicyDecision {
            decision: Decision::Deny,
            rule_id: "<validation-failure>".to_owned(),
            reason: "Custom install location must be a single absolute local drive path without relative segments."
                .to_owned(),
        };
    }

    let requested_version = version::requested_version(request);

    let mut matched_rules: Vec<(&str, u32, Decision, &str)> = Vec::new();

    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }

        if matching::rule_matches(rule, request, &flags, requested_version) {
            matched_rules.push((
                &rule.id,
                rule.priority,
                rule.decision,
                rule.reason.as_deref().unwrap_or("Rule matched."),
            ));
        }
    }

    if matched_rules.is_empty() {
        return PolicyDecision {
            decision: policy.enforcement.default_decision,
            rule_id: "<default>".to_owned(),
            reason: format!(
                "No enabled rule matched; using defaultDecision '{}'.",
                policy.enforcement.default_decision
            ),
        };
    }

    // Sort: lowest priority first, deny wins on tie.
    matched_rules.sort_by(|a, b| {
        a.1.cmp(&b.1).then_with(|| {
            let a_is_deny = a.2 == Decision::Deny;
            let b_is_deny = b.2 == Decision::Deny;
            b_is_deny.cmp(&a_is_deny)
        })
    });

    let winner = matched_rules[0];
    PolicyDecision {
        decision: winner.2,
        rule_id: winner.0.to_owned(),
        reason: winner.3.to_owned(),
    }
}

/// Whether a source spelling has a stable identity across package-manager lookup and
/// policy evaluation.
pub(crate) fn source_name_is_unambiguous(source_name: &str) -> bool {
    source_name == source_name.trim() && !wildcard::has_default_ignorable_code_point(source_name)
}

/// Whether `manager` resolves a source spelling to exactly the literal repository name
/// that policy evaluation matched.
///
/// PowerShell resolves `-Repository` through `WildcardPattern`, so a spelling with
/// wildcard syntax could select repositories that policy evaluation never matched.
pub(crate) fn source_name_is_unambiguous_for_manager(manager: now_policy_api::ManagerName, source_name: &str) -> bool {
    source_name_is_unambiguous(source_name)
        && !(is_powershell_manager(manager) && has_powershell_wildcard_syntax(source_name))
}

pub(crate) fn is_powershell_manager(manager: now_policy_api::ManagerName) -> bool {
    matches!(
        manager,
        now_policy_api::ManagerName::PowerShell | now_policy_api::ManagerName::PowerShell7
    )
}

pub(crate) fn effective_execution_elevation(request: &PackageRequest) -> Elevation {
    if request.options.scope == Some(Scope::Machine) || request.client.requested_elevation == Elevation::Elevated {
        Elevation::Elevated
    } else {
        Elevation::Standard
    }
}
