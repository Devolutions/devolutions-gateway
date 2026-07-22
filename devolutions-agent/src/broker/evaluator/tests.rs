#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use chrono::Utc;
use now_policy::{
    Decision, PackageBrokerPolicy, PolicyDocument, PolicyEnforcement, PolicyMatch, PolicyMetadata, PolicyRule,
    PolicySchemaUri, ResourceId, RulePrecedence, SemanticVersion, StringPattern,
};
use now_policy_api::{self as api, PackageRequest};

use super::evaluate;

fn make_policy(default_decision: Decision, rules: Vec<PolicyRule>) -> PolicyDocument {
    PolicyDocument {
        _schema: PolicySchemaUri,
        policy_version: SemanticVersion::from("1.0.0"),
        policy_type: PackageBrokerPolicy,
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
            rule_precedence: RulePrecedence::PriorityThenDeny,
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
                package_identifiers: BTreeSet::from([StringPattern("Mozilla.Firefox".to_owned())]),
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
                package_identifiers: BTreeSet::from([StringPattern("Mozilla.Firefox".to_owned())]),
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
                package_identifiers: BTreeSet::from([StringPattern("Some.Package".to_owned())]),
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
