#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use chrono::Utc;
use now_policy::{
    Decision, PackageIdentifier, PackageIdentifierCondition, PolicyDocument, PolicyEnforcement, PolicyFormatVersion,
    PolicyMatch, PolicyMetadata, PolicyRule, ResourceId, SemanticVersion, SourceName, VersionCondition, VersionRange,
    VersionString,
};
use now_policy_api::{self as api, PackageRequest};

use super::{evaluate, source_name_is_unambiguous, source_name_is_unambiguous_for_manager};

fn make_policy(default_decision: Decision, rules: Vec<PolicyRule>) -> PolicyDocument {
    PolicyDocument {
        policy_format_version: PolicyFormatVersion::current(),
        metadata: PolicyMetadata {
            id: ResourceId::from("test-policy"),
            publisher: "Test".to_owned(),
            revision: 1,
            published_at: Utc::now(),
            valid_from: None,
            valid_until: None,
            description: None,
            support_url: None,
        },
        enforcement: PolicyEnforcement {
            default_decision,
            audit_mode: None,
        },
        rules,
    }
}

fn make_request(operation: api::Operation, package_id: &str) -> PackageRequest {
    PackageRequest {
        request_kind: api::PackageRequestKind,
        request_version: api::API_VERSION_STR.into(),
        request_id: api::ResourceId::from("req-1"),
        created_at: Utc::now(),
        operation,
        manager: api::ManagerName::Winget,
        source: api::RequestSource {
            name: "winget".to_owned(),
            url: None,
        },
        package: api::RequestPackage {
            id: api::PackageIdentifier(package_id.to_owned()),
            version: None,
            architecture: None,
            channel: None,
        },
        options: api::RequestOptions {
            scope: None,
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

#[test]
fn allow_matching_package() {
    let policy = make_policy(
        Decision::Deny,
        vec![PolicyRule {
            id: ResourceId::from("allow-firefox"),
            enabled: true,
            priority: 100,
            decision: Decision::Allow,
            reason: Some("Firefox is allowed.".to_owned()),
            match_criteria: PolicyMatch {
                package_identifiers: Some(PackageIdentifierCondition::Exact(BTreeSet::from([
                    PackageIdentifier::parse("Mozilla.Firefox").expect("valid identifier"),
                ]))),
                ..Default::default()
            },
            constraints: None,
        }],
    );

    let request = make_request(api::Operation::Install, "Mozilla.Firefox");
    let result = evaluate(&policy, &request);
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.rule_id, "allow-firefox");
}

#[test]
fn deny_unmatched_package() {
    let policy = make_policy(
        Decision::Deny,
        vec![PolicyRule {
            id: ResourceId::from("allow-firefox"),
            enabled: true,
            priority: 100,
            decision: Decision::Allow,
            reason: None,
            match_criteria: PolicyMatch {
                package_identifiers: Some(PackageIdentifierCondition::Exact(BTreeSet::from([
                    PackageIdentifier::parse("Mozilla.Firefox").expect("valid identifier"),
                ]))),
                ..Default::default()
            },
            constraints: None,
        }],
    );

    let request = make_request(api::Operation::Install, "Evil.Malware");
    let result = evaluate(&policy, &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "<default>");
}

#[test]
fn unicode_case_equivalent_source_deny_outranks_allow() {
    let policy = make_policy(
        Decision::Deny,
        vec![
            PolicyRule {
                id: ResourceId::from("allow-any"),
                enabled: true,
                priority: 100,
                decision: Decision::Allow,
                reason: None,
                match_criteria: PolicyMatch::default(),
                constraints: None,
            },
            PolicyRule {
                id: ResourceId::from("deny-corp"),
                enabled: true,
                priority: 100,
                decision: Decision::Deny,
                reason: None,
                match_criteria: PolicyMatch {
                    source_names: BTreeSet::from([SourceName::parse("CÖRP").expect("valid source")]),
                    ..Default::default()
                },
                constraints: None,
            },
        ],
    );
    let mut request = make_request(api::Operation::Install, "Example.Package");
    request.manager = api::ManagerName::PowerShell;
    request.source.name = "cörp".to_owned();

    let result = evaluate(&policy, &request);

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "deny-corp");
}

#[test]
fn default_ignorable_source_spelling_is_rejected_before_evaluation() {
    assert!(!source_name_is_unambiguous("PS\u{00AD}Gallery"));
    assert!(!source_name_is_unambiguous("PSGallery "));
    assert!(!source_name_is_unambiguous(" PSGallery"));
    assert!(source_name_is_unambiguous("PSGallery"));
}

#[test]
fn powershell_wildcard_source_spelling_is_rejected_before_evaluation() {
    for source_name in ["Corp*", "Corp?", "Corp[1]", "Corp`*"] {
        assert!(!source_name_is_unambiguous_for_manager(
            api::ManagerName::PowerShell,
            source_name
        ));
        assert!(!source_name_is_unambiguous_for_manager(
            api::ManagerName::PowerShell7,
            source_name
        ));
        assert!(source_name_is_unambiguous_for_manager(
            api::ManagerName::Winget,
            source_name
        ));
    }
    assert!(source_name_is_unambiguous_for_manager(
        api::ManagerName::PowerShell7,
        "PSGallery"
    ));
}

#[test]
fn disabled_rules_are_ignored() {
    let policy = make_policy(
        Decision::Deny,
        vec![PolicyRule {
            id: ResourceId::from("disabled-allow"),
            enabled: false,
            priority: 1,
            decision: Decision::Allow,
            reason: None,
            match_criteria: PolicyMatch {
                package_identifiers: Some(PackageIdentifierCondition::Exact(BTreeSet::from([
                    PackageIdentifier::parse("Some.Package").expect("valid identifier"),
                ]))),
                ..Default::default()
            },
            constraints: None,
        }],
    );

    let request = make_request(api::Operation::Install, "Some.Package");
    let result = evaluate(&policy, &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "<default>");
}

#[test]
fn lower_priority_number_wins() {
    let policy = make_policy(
        Decision::Deny,
        vec![
            PolicyRule {
                id: ResourceId::from("allow-low-priority"),
                enabled: true,
                priority: 200,
                decision: Decision::Allow,
                reason: None,
                match_criteria: PolicyMatch::default(),
                constraints: None,
            },
            PolicyRule {
                id: ResourceId::from("deny-high-priority"),
                enabled: true,
                priority: 100,
                decision: Decision::Deny,
                reason: None,
                match_criteria: PolicyMatch::default(),
                constraints: None,
            },
        ],
    );

    let result = evaluate(&policy, &make_request(api::Operation::Install, "Some.Package"));
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "deny-high-priority");
}

#[test]
fn deny_wins_priority_ties() {
    let policy = make_policy(
        Decision::Allow,
        vec![
            PolicyRule {
                id: ResourceId::from("allow-tie"),
                enabled: true,
                priority: 100,
                decision: Decision::Allow,
                reason: None,
                match_criteria: PolicyMatch::default(),
                constraints: None,
            },
            PolicyRule {
                id: ResourceId::from("deny-tie"),
                enabled: true,
                priority: 100,
                decision: Decision::Deny,
                reason: None,
                match_criteria: PolicyMatch::default(),
                constraints: None,
            },
        ],
    );

    let result = evaluate(&policy, &make_request(api::Operation::Install, "Some.Package"));
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "deny-tie");
}

fn rule(id: &str, priority: u32, decision: Decision, match_criteria: PolicyMatch) -> PolicyRule {
    PolicyRule {
        id: ResourceId::from(id),
        enabled: true,
        priority,
        decision,
        reason: None,
        match_criteria,
        constraints: None,
    }
}

fn exact_identifier(identifier: &str) -> Option<PackageIdentifierCondition> {
    Some(PackageIdentifierCondition::Exact(BTreeSet::from([
        PackageIdentifier::parse(identifier).expect("valid identifier"),
    ])))
}

fn deny_range_policy() -> PolicyDocument {
    make_policy(
        Decision::Allow,
        vec![rule(
            "deny-old",
            10,
            Decision::Deny,
            PolicyMatch {
                package_identifiers: exact_identifier("Contoso.Tool"),
                version: Some(VersionCondition::Range(VersionRange {
                    min_version: None,
                    max_version: Some(SemanticVersion::parse("2.0.0").expect("valid version")),
                    include_prerelease: false,
                })),
                ..Default::default()
            },
        )],
    )
}

fn allow_exact_version_policy() -> PolicyDocument {
    make_policy(
        Decision::Deny,
        vec![rule(
            "allow-pinned",
            100,
            Decision::Allow,
            PolicyMatch {
                package_identifiers: exact_identifier("Contoso.Tool"),
                version: Some(VersionCondition::Exact(BTreeSet::from([
                    VersionString::parse("3.0.0").expect("valid version")
                ]))),
                ..Default::default()
            },
        )],
    )
}

fn versioned_request(version: Option<&str>) -> PackageRequest {
    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.package.version = version.map(|version| api::VersionString(version.to_owned()));
    request
}

#[test]
fn deny_identifiers_match_case_variants() {
    let policy = make_policy(
        Decision::Allow,
        vec![rule(
            "deny-git",
            10,
            Decision::Deny,
            PolicyMatch {
                package_identifiers: exact_identifier("Git.Git"),
                ..Default::default()
            },
        )],
    );

    let result = evaluate(&policy, &make_request(api::Operation::Install, "git.GIT"));
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "deny-git");
}

#[test]
fn identifiers_use_manager_name_equivalence() {
    let policy = make_policy(
        Decision::Deny,
        vec![rule(
            "allow-dateutil",
            100,
            Decision::Allow,
            PolicyMatch {
                package_identifiers: exact_identifier("python-dateutil"),
                ..Default::default()
            },
        )],
    );
    let mut request = make_request(api::Operation::Install, "Python_DateUtil");
    request.manager = api::ManagerName::Pip;

    let result = evaluate(&policy, &request);
    assert_eq!(result.decision, Decision::Allow);

    request.manager = api::ManagerName::Npm;
    let result = evaluate(&policy, &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "<default>");
}

#[test]
fn deny_version_conditions_match_unknown_or_equivalent_versions() {
    let policy = deny_range_policy();

    for version in [None, Some("latest"), Some("1.5.0.0"), Some("v1.5"), Some("2.0.0-beta")] {
        let result = evaluate(&policy, &versioned_request(version));
        assert_eq!(result.decision, Decision::Deny, "{version:?}");
        assert_eq!(result.rule_id, "deny-old", "{version:?}");
    }

    let result = evaluate(&policy, &versioned_request(Some("2.0.1")));
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.rule_id, "<default>");
}

#[test]
fn allow_version_conditions_require_the_exact_known_version() {
    let policy = allow_exact_version_policy();

    let result = evaluate(&policy, &versioned_request(Some("3.0.0")));
    assert_eq!(result.decision, Decision::Allow);

    for version in [None, Some("3.0.0.0"), Some("v3.0.0")] {
        let result = evaluate(&policy, &versioned_request(version));
        assert_eq!(result.decision, Decision::Deny, "{version:?}");
        assert_eq!(result.rule_id, "<default>", "{version:?}");
    }
}

#[test]
fn version_selecting_custom_parameters_make_the_version_unknown() {
    let mut request = versioned_request(Some("3.0.0"));
    request.options.custom_parameters = vec![api::CustomParameterString("--version=1.0.0".to_owned())];

    let result = evaluate(&deny_range_policy(), &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "deny-old");

    let result = evaluate(&allow_exact_version_policy(), &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "<default>");

    request.options.custom_parameters = vec![api::CustomParameterString("--silent".to_owned())];
    let result = evaluate(&deny_range_policy(), &request);
    assert_eq!(result.decision, Decision::Allow);
    let result = evaluate(&allow_exact_version_policy(), &request);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn version_conditions_do_not_apply_to_uninstall() {
    for version in [None, Some("1.0.0"), Some("3.0.0")] {
        let mut request = versioned_request(version);
        request.operation = api::Operation::Uninstall;

        let result = evaluate(&deny_range_policy(), &request);
        assert_eq!(result.decision, Decision::Allow, "{version:?}");
        assert_eq!(result.rule_id, "<default>", "{version:?}");
        let result = evaluate(&allow_exact_version_policy(), &request);
        assert_eq!(result.decision, Decision::Deny, "{version:?}");
        assert_eq!(result.rule_id, "<default>", "{version:?}");
    }

    // An install without a concrete version stays denied by a Deny rule with a version condition.
    let result = evaluate(&deny_range_policy(), &versioned_request(None));
    assert_eq!(result.rule_id, "deny-old");
}

#[test]
fn decorated_identifier_versions_are_unknown() {
    let mut request = versioned_request(Some("3.0.0"));
    request.manager = api::ManagerName::Npm;
    request.package.id = api::PackageIdentifier("Contoso.Tool@1.0.0".to_owned());
    let result = evaluate(&deny_range_policy(), &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "deny-old");
}

#[test]
fn unacceptable_install_locations_are_denied_before_rule_matching() {
    let policy = make_policy(
        Decision::Allow,
        vec![rule("allow-any", 1, Decision::Allow, PolicyMatch::default())],
    );

    for location in [
        r"C:\Tools\..\Windows\System32",
        "C:/Tools/../Windows",
        r"\\server\share",
        "Tools",
    ] {
        let mut request = make_request(api::Operation::Install, "Contoso.Tool");
        request.options.custom_install_location = Some(location.to_owned());

        let result = evaluate(&policy, &request);
        assert_eq!(result.decision, Decision::Deny, "{location}");
        assert_eq!(result.rule_id, "<validation-failure>", "{location}");
    }

    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.options.custom_install_location = Some("C:/Tools/Contoso/".to_owned());
    assert_eq!(evaluate(&policy, &request).rule_id, "allow-any");
}

#[test]
fn deterministic_scope_and_architecture_defaults_are_matched() {
    let deny_machine_x64 = make_policy(
        Decision::Allow,
        vec![rule(
            "deny-machine-x64",
            10,
            Decision::Deny,
            PolicyMatch {
                scopes: BTreeSet::from([now_policy::Scope::Machine]),
                architectures: BTreeSet::from([now_policy::Architecture::X64]),
                ..Default::default()
            },
        )],
    );
    let allow_user_neutral = make_policy(
        Decision::Deny,
        vec![rule(
            "allow-user-neutral",
            100,
            Decision::Allow,
            PolicyMatch {
                scopes: BTreeSet::from([now_policy::Scope::User]),
                architectures: BTreeSet::from([now_policy::Architecture::Neutral]),
                ..Default::default()
            },
        )],
    );

    // npm always runs per user with architecture-neutral packages.
    let mut request = make_request(api::Operation::Install, "contoso-tool");
    request.manager = api::ManagerName::Npm;
    assert_eq!(evaluate(&deny_machine_x64, &request).rule_id, "<default>");
    assert_eq!(evaluate(&allow_user_neutral, &request).rule_id, "allow-user-neutral");

    // WinGet leaves scope and architecture to the installer.
    let request = make_request(api::Operation::Install, "Contoso.Tool");
    assert_eq!(evaluate(&deny_machine_x64, &request).rule_id, "deny-machine-x64");
    assert_eq!(evaluate(&allow_user_neutral, &request).rule_id, "<default>");
}

#[test]
fn partial_npm_versions_are_unknown() {
    let deny_exact = make_policy(
        Decision::Allow,
        vec![rule(
            "deny-1.5.0",
            10,
            Decision::Deny,
            PolicyMatch {
                package_identifiers: exact_identifier("contoso-tool"),
                version: Some(VersionCondition::Exact(BTreeSet::from([
                    VersionString::parse("1.5.0").expect("valid version")
                ]))),
                ..Default::default()
            },
        )],
    );
    let allow_partial = make_policy(
        Decision::Deny,
        vec![rule(
            "allow-1",
            100,
            Decision::Allow,
            PolicyMatch {
                package_identifiers: exact_identifier("contoso-tool"),
                version: Some(VersionCondition::Exact(BTreeSet::from([
                    VersionString::parse("1").expect("valid version")
                ]))),
                ..Default::default()
            },
        )],
    );

    for version in ["1", "1.5"] {
        let mut request = make_request(api::Operation::Install, "contoso-tool");
        request.manager = api::ManagerName::Npm;
        request.package.version = Some(api::VersionString(version.to_owned()));

        let result = evaluate(&deny_exact, &request);
        assert_eq!(result.rule_id, "deny-1.5.0", "{version}");
        let result = evaluate(&allow_partial, &request);
        assert_eq!(result.rule_id, "<default>", "{version}");

        // WinGet pins the exact version, padding missing components with zeros.
        request.manager = api::ManagerName::Winget;
        let result = evaluate(&deny_exact, &request);
        let expected = if version == "1.5" {
            Decision::Deny
        } else {
            Decision::Allow
        };
        assert_eq!(result.decision, expected, "{version}");
    }

    let mut request = make_request(api::Operation::Install, "contoso-tool");
    request.manager = api::ManagerName::Npm;
    request.package.version = Some(api::VersionString("1.4.9".to_owned()));
    let result = evaluate(&deny_exact, &request);
    assert_eq!(result.rule_id, "<default>");
}

#[test]
fn winget_custom_parameters_apply_policy_relevant_options() {
    let allow_any = make_policy(
        Decision::Allow,
        vec![rule("allow-any", 100, Decision::Allow, PolicyMatch::default())],
    );
    let parameters = |values: &[&str]| {
        values
            .iter()
            .map(|value| api::CustomParameterString((*value).to_owned()))
            .collect::<Vec<_>>()
    };

    for values in [
        &["--location", r"C:\Tools\..\Windows"][..],
        &["-l=Tools"],
        &["--location"],
        &["--location", r"C:\Tools", "-l", r"D:\Tools"],
    ] {
        let mut request = make_request(api::Operation::Install, "Contoso.Tool");
        request.options.custom_parameters = parameters(values);
        assert_eq!(
            evaluate(&allow_any, &request).rule_id,
            "<validation-failure>",
            "{values:?}"
        );
    }

    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.options.custom_install_location = Some(r"C:\Tools".to_owned());
    request.options.custom_parameters = parameters(&["--location", r"D:\Tools"]);
    assert_eq!(evaluate(&allow_any, &request).rule_id, "<validation-failure>");

    let deny_skip_hash = make_policy(
        Decision::Allow,
        vec![rule(
            "deny-skip-hash",
            10,
            Decision::Deny,
            PolicyMatch {
                skip_hash_check: Some(true),
                ..Default::default()
            },
        )],
    );
    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.options.custom_parameters = parameters(&["--Ignore-Security-Hash"]);
    assert_eq!(evaluate(&deny_skip_hash, &request).rule_id, "deny-skip-hash");

    // Other managers reject custom parameters, so their values are not interpreted.
    request.manager = api::ManagerName::Npm;
    assert_eq!(evaluate(&deny_skip_hash, &request).rule_id, "<default>");
}

#[test]
fn explicitly_empty_install_location_is_denied() {
    let allow_any = make_policy(
        Decision::Allow,
        vec![rule("allow-any", 100, Decision::Allow, PolicyMatch::default())],
    );
    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.manager = api::ManagerName::Dotnet;
    request.options.custom_install_location = Some(String::new());

    assert_eq!(evaluate(&allow_any, &request).rule_id, "<validation-failure>");
}

#[test]
fn winget_installer_arguments_leave_the_install_location_unknown() {
    let policy = make_policy(
        Decision::Allow,
        vec![rule(
            "deny-custom-location",
            10,
            Decision::Deny,
            PolicyMatch {
                has_custom_install_location: Some(true),
                ..Default::default()
            },
        )],
    );
    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.options.custom_parameters = vec![
        api::CustomParameterString("--override".to_owned()),
        api::CustomParameterString("/DIR=C:\\Windows".to_owned()),
    ];

    assert_eq!(evaluate(&policy, &request).rule_id, "deny-custom-location");
}

#[test]
fn recommended_denied_custom_parameters_block_winget_installer_arguments() {
    let mut allow = rule("allow-winget", 100, Decision::Allow, PolicyMatch::default());
    allow.constraints = Some(now_policy::PolicyConstraints {
        allow_custom_parameters: true,
        denied_custom_parameters: vec![
            now_policy::CustomParameterString("--override*".to_owned()),
            now_policy::CustomParameterString("--custom*".to_owned()),
        ],
        ..Default::default()
    });
    let policy = make_policy(Decision::Deny, vec![allow]);

    for values in [
        &["--override", "/SILENT"][..],
        &["--OVERRIDE=/SILENT"],
        &["--Custom", "/DIR=C:\\Tools"],
    ] {
        let mut request = make_request(api::Operation::Install, "Contoso.Tool");
        request.options.custom_parameters = values
            .iter()
            .map(|value| api::CustomParameterString((*value).to_owned()))
            .collect();
        assert_eq!(evaluate(&policy, &request).rule_id, "<default>", "{values:?}");
    }

    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.options.custom_parameters = vec![api::CustomParameterString("--silent".to_owned())];
    assert_eq!(evaluate(&policy, &request).rule_id, "allow-winget");
}

#[test]
fn effective_elevation_lowers_explicit_user_scope_and_raises_machine_scope() {
    use api::{Elevation as E, Scope as S};

    assert_eq!(super::effective_elevation(E::Elevated, Some(S::User)), E::Standard);
    assert_eq!(super::effective_elevation(E::Elevated, None), E::Elevated);
    assert_eq!(super::effective_elevation(E::Elevated, Some(S::Machine)), E::Elevated);
    assert_eq!(super::effective_elevation(E::Standard, Some(S::Machine)), E::Elevated);
    assert_eq!(super::effective_elevation(E::Standard, Some(S::User)), E::Standard);
    assert_eq!(super::effective_elevation(E::Standard, None), E::Standard);
}

#[test]
fn unacceptable_kill_process_names_are_denied_before_rules() {
    let policy = make_policy(Decision::Allow, Vec::new());

    for name in ["*", "Code*.exe", r"C:\Tools\Code.exe", "Code.bat"] {
        let mut request = make_request(api::Operation::Install, "Microsoft.VisualStudioCode");
        request.options.kill_before_operation = vec![api::ProcessName(name.to_owned())];
        let result = evaluate(&policy, &request);
        assert_eq!(result.decision, Decision::Deny, "{name}");
        assert_eq!(result.rule_id, "<validation-failure>", "{name}");
    }

    let mut request = make_request(api::Operation::Install, "Microsoft.VisualStudioCode");
    request.options.kill_before_operation = vec![
        api::ProcessName("Code.exe".to_owned()),
        api::ProcessName("chrome".to_owned()),
    ];
    assert_eq!(evaluate(&policy, &request).decision, Decision::Allow);
}

#[test]
fn agent_uninstall_is_denied_before_rules() {
    let policy = make_policy(Decision::Allow, Vec::new());

    let request = make_request(api::Operation::Uninstall, "devolutions.agent");
    let result = evaluate(&policy, &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "<validation-failure>");

    let mut request = make_request(api::Operation::Update, "Devolutions.Agent");
    request.options.uninstall_previous = true;
    assert_eq!(evaluate(&policy, &request).decision, Decision::Deny);

    let mut request = make_request(api::Operation::Update, "Devolutions.Agent");
    request.options.custom_parameters = vec![api::CustomParameterString("--uninstall-previous".to_owned())];
    assert_eq!(evaluate(&policy, &request).decision, Decision::Deny);

    let mut request = make_request(api::Operation::Uninstall, "DEVO-AGENT");
    request.manager = api::ManagerName::Chocolatey;
    request.source.name = "chocolatey".to_owned();
    assert_eq!(evaluate(&policy, &request).decision, Decision::Deny);

    // Installs and updates that keep the previous version, and other packages, are left to the policy.
    let request = make_request(api::Operation::Update, "Devolutions.Agent");
    assert_eq!(evaluate(&policy, &request).decision, Decision::Allow);
    let request = make_request(api::Operation::Uninstall, "Devolutions.Agent.Extra");
    assert_eq!(evaluate(&policy, &request).decision, Decision::Allow);
    let mut request = make_request(api::Operation::Uninstall, "Devolutions.Agent");
    request.manager = api::ManagerName::Chocolatey;
    request.source.name = "chocolatey".to_owned();
    assert_eq!(evaluate(&policy, &request).decision, Decision::Allow);
}

#[test]
fn custom_parameter_user_scope_lowers_execution_elevation() {
    let custom = |values: &[&str]| {
        values
            .iter()
            .map(|value| api::CustomParameterString((*value).to_owned()))
            .collect::<Vec<_>>()
    };

    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.options.custom_parameters = custom(&["--scope", "user"]);
    assert_eq!(super::effective_execution_elevation(&request), api::Elevation::Standard);

    // A custom machine scope does not raise a standard request, and a typed scope takes precedence.
    request.client.requested_elevation = api::Elevation::Standard;
    request.options.custom_parameters = custom(&["--scope", "machine"]);
    assert_eq!(super::effective_execution_elevation(&request), api::Elevation::Standard);

    request.client.requested_elevation = api::Elevation::Elevated;
    request.options.scope = Some(api::Scope::Machine);
    request.options.custom_parameters = custom(&["--scope", "user"]);
    assert_eq!(super::effective_execution_elevation(&request), api::Elevation::Elevated);

    // Conflicting custom scopes leave the requested elevation unchanged.
    request.options.scope = None;
    request.options.custom_parameters = custom(&["--scope", "user", "--scope", "machine"]);
    assert_eq!(super::effective_execution_elevation(&request), api::Elevation::Elevated);
}

#[test]
fn supplied_install_location_is_kept_for_security_checks_when_installer_arguments_are_present() {
    let mut request = make_request(api::Operation::Install, "Contoso.Tool");
    request.options.custom_install_location = Some(r"c:\Users\alice\Downloads\App".to_owned());
    request.options.custom_parameters = vec![api::CustomParameterString("--custom=/quiet".to_owned())];
    assert_eq!(
        super::custom_install_location(&request).as_deref(),
        Some(r"C:\Users\alice\Downloads\App")
    );

    request.options.custom_install_location = None;
    request.options.custom_parameters = vec![
        api::CustomParameterString("--location".to_owned()),
        api::CustomParameterString(r"C:\Tools\App".to_owned()),
        api::CustomParameterString("--override".to_owned()),
        api::CustomParameterString("/S".to_owned()),
    ];
    assert_eq!(
        super::custom_install_location(&request).as_deref(),
        Some(r"C:\Tools\App")
    );
}

#[test]
fn agent_uninstall_by_installed_product_code_is_detected() {
    let product_code = uuid::uuid!("{0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}");
    let protects = |request: &PackageRequest| super::uninstalls_protected_package(request, Some(product_code));

    let request = make_request(
        api::Operation::Uninstall,
        r"ARP\Machine\X64\{0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}",
    );
    assert!(protects(&request));
    assert!(!super::uninstalls_protected_package(&request, None));

    let mut request = make_request(api::Operation::Uninstall, "Contoso.Tool");
    request.options.custom_parameters = vec![
        api::CustomParameterString("--product-code".to_owned()),
        api::CustomParameterString("{0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d}".to_owned()),
    ];
    assert!(protects(&request));

    let mut request = make_request(
        api::Operation::Update,
        r"ARP\Machine\X64\{0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}",
    );
    assert!(!protects(&request));
    request.options.uninstall_previous = true;
    assert!(protects(&request));

    let request = make_request(
        api::Operation::Uninstall,
        r"ARP\Machine\X64\{FFFFFFFF-4E5F-4A6B-8C7D-9E0F1A2B3C4D}",
    );
    assert!(!protects(&request));
}
