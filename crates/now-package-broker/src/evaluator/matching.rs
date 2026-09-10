//! Rule matching primitives.

use std::collections::BTreeSet;

use now_policy::{Architecture, Elevation, ManagerName, Operation, PolicyRule, Scope};
use now_policy_api::PackageRequest;

use super::RequestFlags;
use super::constraints::constraints_pass;
use super::version::version_range_matches;
use super::wildcard::wildcard_any;

pub(super) fn rule_matches(
    rule: &PolicyRule,
    request: &PackageRequest,
    flags: &RequestFlags,
    effective_version: &str,
) -> bool {
    let m = &rule.match_criteria;

    operations_match(request.operation, &m.operations)
        && managers_match(request.manager, &m.managers)
        && wildcard_any(&request.source.name, &m.sources)
        && wildcard_any(&request.package.id, &m.package_identifiers)
        && m.package_names.is_empty()
        && string_in_set(effective_version, &m.versions)
        && version_range_matches(effective_version, &m.version_range)
        && scopes_match(request.options.scope, &m.scopes)
        && architectures_match(request.package.architecture, &m.architectures)
        && elevation_match(request.client.requested_elevation, &m.elevation)
        && bool_in_set(request.options.interactive, &m.interactive)
        && bool_in_set(request.options.skip_hash_check, &m.skip_hash_check)
        && bool_in_set(request.options.pre_release, &m.pre_release)
        && bool_in_set(flags.has_custom_parameters, &m.has_custom_parameters)
        && bool_in_set(flags.has_custom_install_location, &m.has_custom_install_location)
        && bool_in_set(flags.has_pre_post_commands, &m.has_pre_post_commands)
        && bool_in_set(flags.has_kill_before_operation, &m.has_kill_before_operation)
        && bool_in_set(flags.has_uninstall_previous, &m.has_uninstall_previous)
        && constraints_pass(&rule.constraints, request, flags)
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

fn scopes_match(scope: Option<now_policy_api::Scope>, allowed: &BTreeSet<Scope>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    scope.map(policy_scope).is_some_and(|scope| allowed.contains(&scope))
}

fn architectures_match(architecture: Option<now_policy_api::Architecture>, allowed: &BTreeSet<Architecture>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    architecture
        .map(policy_architecture)
        .is_some_and(|architecture| allowed.contains(&architecture))
}

fn elevation_match(elevation: now_policy_api::Elevation, allowed: &BTreeSet<Elevation>) -> bool {
    allowed.is_empty() || allowed.contains(&policy_elevation(elevation))
}

fn bool_in_set(value: bool, set: &BTreeSet<bool>) -> bool {
    set.is_empty() || set.contains(&value)
}

fn string_in_set<S: AsRef<str>>(value: &str, set: &BTreeSet<S>) -> bool {
    if set.is_empty() {
        return true;
    }
    if value.is_empty() {
        // If no version specified and set requires specific versions, don't match.
        return false;
    }
    set.iter().any(|item| item.as_ref() == value)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use now_policy::{Decision, PolicyMatch, ResourceId, StringPattern};
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
        rule_matches(&rule(match_criteria), &request, &flags, "1.2.3")
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
            sources: BTreeSet::from([StringPattern("winget".to_owned())]),
            package_identifiers: BTreeSet::from([StringPattern("Microsoft.*Code".to_owned())]),
            ..Default::default()
        }));

        assert!(!matches(PolicyMatch {
            managers: BTreeSet::from([ManagerName::PowerShell]),
            ..Default::default()
        }));
    }

    #[test]
    fn absent_scope_or_architecture_in_request_fails_when_rule_restricts_them() {
        let mut request = request();
        request.options.scope = None;
        request.package.architecture = None;
        let flags = RequestFlags::from_request(&request);
        let rule = rule(PolicyMatch {
            scopes: BTreeSet::from([Scope::Machine]),
            architectures: BTreeSet::from([Architecture::X64]),
            ..Default::default()
        });

        assert!(!rule_matches(&rule, &request, &flags, "1.2.3"));
    }

    #[test]
    fn package_name_criteria_fail_closed_until_request_contains_display_name() {
        assert!(!matches(PolicyMatch {
            package_names: BTreeSet::from([StringPattern("Visual Studio Code".to_owned())]),
            ..Default::default()
        }));
    }

    #[test]
    fn boolean_flags_match_request_options() {
        let mut request = request();
        request.options.interactive = true;
        let flags = RequestFlags::from_request(&request);
        let rule = rule(PolicyMatch {
            interactive: BTreeSet::from([true]),
            ..Default::default()
        });

        assert!(rule_matches(&rule, &request, &flags, "1.2.3"));
    }
}
