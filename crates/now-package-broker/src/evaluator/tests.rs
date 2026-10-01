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
fn uninstall_and_decorated_identifier_versions_are_unknown() {
    let mut request = versioned_request(Some("3.0.0"));
    request.operation = api::Operation::Uninstall;

    let result = evaluate(&deny_range_policy(), &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "deny-old");
    let result = evaluate(&allow_exact_version_policy(), &request);
    assert_eq!(result.rule_id, "<default>");

    let mut request = versioned_request(Some("3.0.0"));
    request.manager = api::ManagerName::Npm;
    request.package.id = api::PackageIdentifier("Contoso.Tool@1.0.0".to_owned());
    let result = evaluate(&deny_range_policy(), &request);
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.rule_id, "deny-old");
}
