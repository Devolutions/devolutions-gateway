//! Policy evaluation engine.
//!
//! Implements the broker flow described in the package broker policies spec:
//! 1. Deny requests whose custom install location is not a plain local drive path, whose
//!    kill-before-operation entries are not plain `.exe` image names, or that uninstall a protected package
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
//!
//! # Security model
//!
//! Standard operations run with the user's own filtered token, so the user could run the same
//! package manager command directly.
//! For them, the policy is governance, not a security boundary, unless App Control or AppLocker
//! also blocks running the package manager directly.
//!
//! Elevated operations run with the user's linked administrator token.
//! Each Elevated Allow rule removes the UAC prompt for the operations it matches, for any code
//! running in that administrator's session, so the broker restricts what an elevated operation
//! can select regardless of the policy:
//! - An explicit user scope, typed or passed through custom parameters, always runs with the standard
//!   token (see `effective_execution_elevation`); policy matching and execution use the same elevation.
//!   The executor refuses to run a standard plan with an elevated token, such as the full token of an
//!   administrator when UAC is disabled.
//! - Kill-before-operation entries must be plain `.exe` image names; process names without an
//!   extension get `.exe` appended.
//!   `taskkill` only targets the session of the authenticated client, and the requester's own processes
//!   when elevated.
//! - An elevated custom install location must be on a local disk, contain no reparse point, and not be
//!   writable by principals other than SYSTEM, Administrators and TrustedInstaller, including through
//!   inheritable ACEs.
//!   The executor checks the nearest existing folder before running the package manager and keeps it
//!   from being renamed until the operation completes.
//!   A supplied location is checked even with opaque installer arguments (WinGet `--override` and
//!   `--custom`), but a location selected only inside those arguments is not.
//! - The broker never uninstalls the Devolutions Agent, which hosts it.
//!   WinGet may also select installed programs by their `ARP\...` identifiers, which this protection
//!   does not cover; add Deny rules for other critical software and for such identifiers.
//! - None of these restrictions depend on the policy, so audit mode cannot override them.
//!   Audit mode allows every other request, including elevated ones the rules deny, and the policy
//!   validator warns about this whenever audit mode is enabled.

use now_policy::{Decision, PolicyDocument};
use now_policy_api::{Elevation, PackageRequest, Scope};

mod builtin_rules;
mod constraints;
mod custom_options;
mod identifier;
mod install_location;
mod matching;
mod version;
mod wildcard;

pub(crate) use builtin_rules::{is_acceptable_kill_process_name, normalize_kill_process_name};
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
    /// Normalized supplied install location, typed or passed through custom parameters, even when
    /// installer arguments may override it.
    supplied_install_location: Option<String>,
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

        let supplied_install_location = supplied_location.clone().flatten();

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
            custom_install_location: supplied_install_location
                .clone()
                .filter(|_| !custom.installer_arguments),
            supplied_install_location,
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

/// Normalized install location the request supplies, typed or passed through custom parameters,
/// or `None` when there is none.
///
/// Unlike policy matching, this keeps a supplied location even when opaque installer arguments
/// may override it, because the package manager still receives it.
pub(crate) fn custom_install_location(request: &PackageRequest) -> Option<String> {
    RequestFlags::from_request(request).supplied_install_location
}

/// Whether a kill-before-operation entry, after [`normalize_kill_process_name`], is not an
/// [`is_acceptable_kill_process_name`].
///
/// The server rejects such requests before policy evaluation so audit mode cannot override the rejection;
/// [`evaluate`] also denies them for direct callers.
pub(crate) fn has_unacceptable_kill_process_name(request: &PackageRequest) -> bool {
    request
        .options
        .kill_before_operation
        .iter()
        .any(|process| !is_acceptable_kill_process_name(&normalize_kill_process_name(&process.0)))
}

/// Whether the request uninstalls a package the broker protects, such as the Devolutions Agent.
///
/// The server rejects such requests before policy evaluation so audit mode cannot override the rejection;
/// [`evaluate`] also denies them for direct callers.
pub(crate) fn uninstalls_protected_package(request: &PackageRequest) -> bool {
    builtin_rules::uninstalls_protected_package(request, &RequestFlags::from_request(request))
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

    if has_unacceptable_kill_process_name(request) {
        return PolicyDecision {
            decision: Decision::Deny,
            rule_id: "<validation-failure>".to_owned(),
            reason: "Kill-before-operation entries must be process names without an extension or ending in .exe, without wildcards, path separators, quotes, or control characters."
                .to_owned(),
        };
    }

    if builtin_rules::uninstalls_protected_package(request, &flags) {
        return PolicyDecision {
            decision: Decision::Deny,
            rule_id: "<validation-failure>".to_owned(),
            reason: "The package broker does not uninstall the Devolutions Agent.".to_owned(),
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

/// Elevation of the token that executes `request`.
///
/// Policy matching, request validation, command building and the executor all use this value,
/// so a request is always evaluated with the elevation it runs with.
pub(crate) fn effective_execution_elevation(request: &PackageRequest) -> Elevation {
    let custom_scope = || {
        let custom = custom_options::custom_options(request.manager, &request.options.custom_parameters);
        custom_options::resolve(None, &custom.scopes).flatten()
    };
    // A user scope passed only through custom parameters lowers the elevation like a typed one;
    // a machine scope there does not raise it.
    let scope = request
        .options
        .scope
        .or_else(|| custom_scope().filter(|scope| *scope == Scope::User));
    effective_elevation(request.client.requested_elevation, scope)
}

/// Elevation of the execution token for a requested elevation and an explicitly requested scope.
///
/// Machine scope requires the elevated token.
/// User scope runs with the standard token even when elevation is requested, so the
/// administrator token never writes into the user profile.
pub(crate) fn effective_elevation(requested: Elevation, scope: Option<Scope>) -> Elevation {
    match scope {
        Some(Scope::Machine) => Elevation::Elevated,
        Some(Scope::User) => Elevation::Standard,
        None => requested,
    }
}
