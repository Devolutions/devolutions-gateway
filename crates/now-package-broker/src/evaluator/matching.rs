//! Rule matching primitives.

use std::collections::BTreeSet;

use now_policy::{Architecture, Decision, Elevation, ManagerName, Operation, PolicyRule, Scope};
use now_policy_api::PackageRequest;

use super::RequestFlags;
use super::constraints::constraints_pass;
use super::identifier::package_identifiers_match;
use super::version::version_condition_matches;
use super::wildcard::literal_case_insensitive_match;

/// Whether `rule` matches `request`.
///
/// `requested_version` is `None` when the version is unknown before execution.
///
/// A rule with a version condition never matches an uninstall request, whatever its decision:
/// removing a package cannot install a version, and the package managers do not pin the version they remove.
pub(super) fn rule_matches(
    rule: &PolicyRule,
    request: &PackageRequest,
    flags: &RequestFlags,
    requested_version: Option<&str>,
) -> bool {
    let m = &rule.match_criteria;

    operations_match(request.operation, &m.operations)
        && managers_match(request.manager, &m.managers)
        && source_names_match(request.manager, &request.source.name, &m.source_names)
        && package_identifiers_match(
            request.manager,
            &request.package.id.0,
            m.package_identifiers.as_ref(),
            rule.decision,
        )
        && m.version.as_ref().is_none_or(|condition| {
            request.operation != now_policy_api::Operation::Uninstall
                && version_condition_matches(requested_version, condition, rule.decision)
        })
        && scopes_match(effective_scope(request), &m.scopes, rule.decision)
        && architectures_match(effective_architecture(request), &m.architectures, rule.decision)
        && elevation_match(super::effective_execution_elevation(request), &m.execution_elevation)
        && optional_bool_matches(flags.interactive, m.interactive)
        && optional_bool_matches(flags.skip_hash_check, m.skip_hash_check)
        && optional_bool_matches(request.options.pre_release, m.pre_release)
        && optional_bool_matches(flags.has_custom_parameters, m.has_custom_parameters)
        && optional_bool_matches(flags.has_custom_install_location, m.has_custom_install_location)
        && optional_bool_matches(flags.has_pre_post_commands, m.has_pre_post_commands)
        && optional_bool_matches(flags.has_kill_before_operation, m.has_kill_before_operation)
        && optional_bool_matches(flags.has_uninstall_previous, m.has_uninstall_previous)
        // Constraints only narrow Allow rules; a Deny rule matches regardless of them.
        && (rule.decision == Decision::Deny || constraints_pass(&rule.constraints, request, flags))
}

fn policy_operation(operation: now_policy_api::Operation) -> Operation {
    use now_policy_api as api;

    match operation {
        api::Operation::Install => Operation::Install,
        api::Operation::Update => Operation::Update,
        api::Operation::Uninstall => Operation::Uninstall,
    }
}

fn policy_manager(manager: now_policy_api::ManagerName) -> ManagerName {
    use now_policy_api as api;

    match manager {
        api::ManagerName::Winget => ManagerName::Winget,
        api::ManagerName::PowerShell => ManagerName::PowerShell,
        api::ManagerName::PowerShell7 => ManagerName::PowerShell7,
        api::ManagerName::Apt => ManagerName::Apt,
        api::ManagerName::Bun => ManagerName::Bun,
        api::ManagerName::Cargo => ManagerName::Cargo,
        api::ManagerName::Chocolatey => ManagerName::Chocolatey,
        api::ManagerName::Dnf => ManagerName::Dnf,
        api::ManagerName::Dotnet => ManagerName::Dotnet,
        api::ManagerName::Flatpak => ManagerName::Flatpak,
        api::ManagerName::Homebrew => ManagerName::Homebrew,
        api::ManagerName::Npm => ManagerName::Npm,
        api::ManagerName::Pacman => ManagerName::Pacman,
        api::ManagerName::Pip => ManagerName::Pip,
        api::ManagerName::Scoop => ManagerName::Scoop,
        api::ManagerName::Snap => ManagerName::Snap,
        api::ManagerName::Vcpkg => ManagerName::Vcpkg,
    }
}

fn policy_scope(scope: now_policy_api::Scope) -> Scope {
    use now_policy_api as api;

    match scope {
        api::Scope::User => Scope::User,
        api::Scope::Machine => Scope::Machine,
    }
}

fn policy_architecture(architecture: now_policy_api::Architecture) -> Architecture {
    use now_policy_api as api;

    match architecture {
        api::Architecture::X86 => Architecture::X86,
        api::Architecture::X64 => Architecture::X64,
        api::Architecture::Arm64 => Architecture::Arm64,
        api::Architecture::Neutral => Architecture::Neutral,
    }
}

fn policy_elevation(elevation: now_policy_api::Elevation) -> Elevation {
    use now_policy_api as api;

    match elevation {
        api::Elevation::Standard => Elevation::Standard,
        api::Elevation::Elevated => Elevation::Elevated,
    }
}

fn operations_match(operation: now_policy_api::Operation, allowed: &BTreeSet<Operation>) -> bool {
    allowed.is_empty() || allowed.contains(&policy_operation(operation))
}

fn managers_match(manager: now_policy_api::ManagerName, allowed: &BTreeSet<ManagerName>) -> bool {
    allowed.is_empty() || allowed.contains(&policy_manager(manager))
}

/// Scope the operation runs in, or `None` when the package manager decides at execution time.
///
/// Mirrors the command builders when the request omits the scope:
/// - npm, pip, Cargo, Scoop, Bun, vcpkg and `dotnet tool` always run per user.
/// - PowerShell installs and updates default to `CurrentUser`; uninstall removes the module wherever it is installed.
/// - Chocolatey always runs machine-wide.
/// - WinGet leaves the scope to the installer.
fn effective_scope(request: &PackageRequest) -> Option<now_policy_api::Scope> {
    use now_policy_api::{ManagerName as M, Operation as O, Scope as S};

    if let Some(scope) = request.options.scope {
        return Some(scope);
    }

    match request.manager {
        M::Npm | M::Pip | M::Cargo | M::Scoop | M::Bun | M::Vcpkg | M::Dotnet => Some(S::User),
        M::PowerShell | M::PowerShell7 if request.operation != O::Uninstall => Some(S::User),
        M::Chocolatey => Some(S::Machine),
        _ => None,
    }
}

/// Architecture the operation selects, or `None` when the package manager decides at execution time.
///
/// Mirrors the command builders when the request omits the architecture:
/// - npm, pip, Cargo, Bun and PowerShell packages are architecture-neutral.
/// - vcpkg encodes the architecture in the triplet source name (`x64-windows`).
/// - WinGet, Chocolatey, Scoop and `dotnet tool` pick an architecture from the host, the package and user configuration.
fn effective_architecture(request: &PackageRequest) -> Option<now_policy_api::Architecture> {
    use now_policy_api::{Architecture as A, ManagerName as M};

    if let Some(architecture) = request.package.architecture {
        return Some(architecture);
    }

    match request.manager {
        M::Npm | M::Pip | M::Cargo | M::Bun | M::PowerShell | M::PowerShell7 => Some(A::Neutral),
        M::Vcpkg => match request.source.name.split('-').next() {
            Some(prefix) if prefix.eq_ignore_ascii_case("x64") => Some(A::X64),
            Some(prefix) if prefix.eq_ignore_ascii_case("x86") => Some(A::X86),
            Some(prefix) if prefix.eq_ignore_ascii_case("arm64") => Some(A::Arm64),
            _ => None,
        },
        _ => None,
    }
}

/// An unknown scope matches Deny rules only.
fn scopes_match(scope: Option<now_policy_api::Scope>, allowed: &BTreeSet<Scope>, decision: Decision) -> bool {
    if allowed.is_empty() {
        return true;
    }
    scope.map_or(decision == Decision::Deny, |scope| {
        allowed.contains(&policy_scope(scope))
    })
}

/// An unknown architecture matches Deny rules only.
fn architectures_match(
    architecture: Option<now_policy_api::Architecture>,
    allowed: &BTreeSet<Architecture>,
    decision: Decision,
) -> bool {
    if allowed.is_empty() {
        return true;
    }
    architecture.map_or(decision == Decision::Deny, |architecture| {
        allowed.contains(&policy_architecture(architecture))
    })
}

fn elevation_match(elevation: now_policy_api::Elevation, allowed: &BTreeSet<Elevation>) -> bool {
    allowed.is_empty() || allowed.contains(&policy_elevation(elevation))
}

fn source_names_match(
    manager: now_policy_api::ManagerName,
    value: &str,
    allowed: &BTreeSet<now_policy::SourceName>,
) -> bool {
    allowed.is_empty()
        || allowed.iter().any(|source| {
            if super::is_powershell_manager(manager) {
                literal_case_insensitive_match(value, source.as_ref())
            } else {
                source.as_ref().eq_ignore_ascii_case(value)
            }
        })
}

fn optional_bool_matches(value: bool, expected: Option<bool>) -> bool {
    expected.is_none_or(|expected| expected == value)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use now_policy::{Decision, PackageIdentifierCondition, PolicyMatch, ResourceId, StringPattern};
    use now_policy_api as api;

    use super::*;

    fn request() -> PackageRequest {
        PackageRequest {
            request_kind: api::PackageRequestKind,
            request_version: api::API_VERSION_STR.into(),
            request_id: api::ResourceId::from("req-1"),
            created_at: Utc::now(),
            operation: api::Operation::Install,
            manager: api::ManagerName::Winget,
            source: api::RequestSource {
                name: "winget".to_owned(),
                url: None,
            },
            package: api::RequestPackage {
                id: api::PackageIdentifier("Microsoft.VisualStudioCode".to_owned()),
                version: Some(api::VersionString("1.2.3".to_owned())),
                architecture: Some(api::Architecture::X64),
                channel: None,
            },
            options: api::RequestOptions {
                scope: Some(api::Scope::Machine),
                interactive: false,
                skip_hash_check: false,
                pre_release: false,
                custom_install_location: None,
                custom_parameters: Vec::new(),
                pre_operation_command: None,
                post_operation_command: None,
                kill_before_operation: Vec::new(),
                uninstall_previous: false,
                no_upgrade: false,
            },
            client: api::ClientContext {
                transport: api::Transport::HttpNamedPipe,
                requested_elevation: api::Elevation::Elevated,
                effective_user: "DOMAIN\\user".to_owned(),
                client_executable_path: "C:\\Program Files\\Devolutions\\Package Broker\\PackageBrokerClient.exe"
                    .to_owned(),
                client_version: "1.0.0".to_owned(),
            },
            include_command_preview: false,
            capture_output: false,
        }
    }

    fn rule(match_criteria: PolicyMatch) -> PolicyRule {
        PolicyRule {
            id: ResourceId::from("rule"),
            enabled: true,
            priority: 100,
            decision: Decision::Allow,
            reason: None,
            match_criteria,
            constraints: None,
        }
    }

    fn matches(match_criteria: PolicyMatch) -> bool {
        let request = request();
        let flags = RequestFlags::from_request(&request);
        rule_matches(&rule(match_criteria), &request, &flags, Some("1.2.3"))
    }

    #[test]
    fn empty_match_criteria_match_any_request() {
        assert!(matches(PolicyMatch::default()));
    }

    #[test]
    fn manager_operation_source_and_package_criteria_must_all_match() {
        assert!(matches(PolicyMatch {
            operations: BTreeSet::from([Operation::Install]),
            managers: BTreeSet::from([ManagerName::Winget]),
            source_names: BTreeSet::from([now_policy::SourceName::parse("winget").expect("valid source")]),
            package_identifiers: Some(PackageIdentifierCondition::Patterns(BTreeSet::from([StringPattern(
                "Microsoft.*Code".to_owned(),
            )]))),
            ..Default::default()
        }));

        assert!(!matches(PolicyMatch {
            managers: BTreeSet::from([ManagerName::PowerShell]),
            ..Default::default()
        }));
    }

    #[test]
    fn source_names_are_exact_not_wildcard_patterns() {
        assert!(!matches(PolicyMatch {
            managers: BTreeSet::from([ManagerName::Winget]),
            source_names: BTreeSet::from([now_policy::SourceName::parse("wing*").expect("valid source")]),
            ..Default::default()
        }));
    }

    #[test]
    fn non_powershell_source_names_remain_canonically_distinct() {
        let mut request = request();
        request.manager = api::ManagerName::Scoop;
        request.source.name = "CO\u{0308}RP".to_owned();
        let flags = RequestFlags::from_request(&request);
        let rule = rule(PolicyMatch {
            source_names: BTreeSet::from([now_policy::SourceName::parse("CÖRP").expect("valid source")]),
            ..Default::default()
        });

        assert!(!rule_matches(&rule, &request, &flags, Some("1.2.3")));
    }

    #[test]
    fn absent_scope_or_architecture_matches_only_deny_rules_that_restrict_them() {
        let mut request = request();
        request.options.scope = None;
        request.package.architecture = None;
        let flags = RequestFlags::from_request(&request);
        let rule = rule(PolicyMatch {
            scopes: BTreeSet::from([Scope::Machine]),
            architectures: BTreeSet::from([Architecture::X64]),
            ..Default::default()
        });

        assert!(!rule_matches(&rule, &request, &flags, Some("1.2.3")));

        let mut rule = rule;
        rule.decision = Decision::Deny;
        assert!(rule_matches(&rule, &request, &flags, Some("1.2.3")));
    }

    #[test]
    fn boolean_flags_match_request_options() {
        let mut request = request();
        request.options.interactive = true;
        let flags = RequestFlags::from_request(&request);
        let rule = rule(PolicyMatch {
            interactive: Some(true),
            ..Default::default()
        });

        assert!(rule_matches(&rule, &request, &flags, Some("1.2.3")));
    }

    #[test]
    fn machine_scope_uses_effective_elevated_execution_privilege() {
        let mut request = request();
        request.client.requested_elevation = api::Elevation::Standard;
        request.options.scope = Some(api::Scope::Machine);
        let flags = RequestFlags::from_request(&request);
        let rule = rule(PolicyMatch {
            execution_elevation: BTreeSet::from([Elevation::Elevated]),
            ..Default::default()
        });

        assert!(rule_matches(&rule, &request, &flags, Some("1.2.3")));
    }

    #[test]
    fn user_scope_without_requested_elevation_uses_standard_execution_privilege() {
        let mut request = request();
        request.client.requested_elevation = api::Elevation::Standard;
        request.options.scope = Some(api::Scope::User);
        let flags = RequestFlags::from_request(&request);
        let rule = rule(PolicyMatch {
            execution_elevation: BTreeSet::from([Elevation::Standard]),
            ..Default::default()
        });

        assert!(rule_matches(&rule, &request, &flags, Some("1.2.3")));
    }

    #[test]
    fn absent_scope_and_architecture_use_deterministic_manager_defaults() {
        use api::{Architecture as A, ManagerName as M, Operation as O, Scope as S};

        let cases = [
            (M::Npm, O::Install, "npm", Some(S::User), Some(A::Neutral)),
            (M::Pip, O::Install, "pip", Some(S::User), Some(A::Neutral)),
            (M::Cargo, O::Install, "crates.io", Some(S::User), Some(A::Neutral)),
            (M::Bun, O::Install, "npm", Some(S::User), Some(A::Neutral)),
            (M::Scoop, O::Install, "main", Some(S::User), None),
            (M::Dotnet, O::Install, "nuget.org", Some(S::User), None),
            (M::Vcpkg, O::Install, "x64-windows", Some(S::User), Some(A::X64)),
            (
                M::Vcpkg,
                O::Install,
                "arm64-windows-static",
                Some(S::User),
                Some(A::Arm64),
            ),
            (M::Vcpkg, O::Install, "custom-triplet", Some(S::User), None),
            (M::PowerShell, O::Install, "PSGallery", Some(S::User), Some(A::Neutral)),
            (M::PowerShell7, O::Update, "PSGallery", Some(S::User), Some(A::Neutral)),
            (M::PowerShell, O::Uninstall, "PSGallery", None, Some(A::Neutral)),
            (M::Chocolatey, O::Install, "chocolatey", Some(S::Machine), None),
            (M::Winget, O::Install, "winget", None, None),
        ];

        for (manager, operation, source, scope, architecture) in cases {
            let mut request = request();
            request.manager = manager;
            request.operation = operation;
            request.source.name = source.to_owned();
            request.options.scope = None;
            request.package.architecture = None;

            assert_eq!(effective_scope(&request), scope, "{manager:?} {operation:?}");
            assert_eq!(effective_architecture(&request), architecture, "{manager:?} {source}");
        }

        let mut request = request();
        request.manager = M::Npm;
        request.options.scope = Some(S::Machine);
        request.package.architecture = Some(A::X64);
        assert_eq!(effective_scope(&request), Some(S::Machine));
        assert_eq!(effective_architecture(&request), Some(A::X64));
    }

    #[test]
    fn constraints_narrow_allow_rules_but_not_deny_rules() {
        let mut request = request();
        request.options.interactive = true;
        let flags = RequestFlags::from_request(&request);
        let mut rule = rule(PolicyMatch {
            managers: BTreeSet::from([ManagerName::Winget]),
            ..Default::default()
        });
        rule.constraints = Some(now_policy::PolicyConstraints {
            allow_interactive: false,
            ..Default::default()
        });

        assert!(!rule_matches(&rule, &request, &flags, Some("1.2.3")));

        rule.decision = Decision::Deny;
        assert!(rule_matches(&rule, &request, &flags, Some("1.2.3")));
    }
}
