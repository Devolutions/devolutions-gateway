//! Policy evaluation engine.
//!
//! Implements the broker flow described in the UniGetUI package broker policies spec:
//! 1. Deserialize and validate request (type system performs validation)
//! 2. Match enabled rules against request
//! 3. Sort by priority (lowest wins), deny wins on tie
//! 4. Fall back to `enforcement.defaultDecision`

use std::collections::BTreeSet;

use crate::model::{
    Architecture, Decision, Elevation, ManagerName, Operation, PackageRequest, PolicyConstraints, PolicyDocument,
    PolicyRule, RequestFlags, Scope,
};

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub rule_id: String,
    pub reason: String,
}

/// Evaluate a parsed request against a parsed policy document.
///
/// Both the policy and request should have already been deserialized into typed structs
/// (validation happens during deserialization).
/// This function performs the rule-matching logic only.
pub fn evaluate(policy: &PolicyDocument, request: &PackageRequest) -> PolicyDecision {
    let flags = RequestFlags::from_request(request);
    let effective_version = get_effective_version(request);

    let mut matched_rules: Vec<(&str, u32, Decision, &str)> = Vec::new();

    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }

        if rule_matches(rule, request, &flags, &effective_version) {
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

// ─── Rule matching ───────────────────────────────────────────────────────────

fn rule_matches(rule: &PolicyRule, request: &PackageRequest, flags: &RequestFlags, effective_version: &str) -> bool {
    let m = &rule.match_criteria;

    operations_match(request.operation, &m.operations)
        && managers_match(request.manager.name, &m.managers)
        && wildcard_any(&request.source.name, &m.sources)
        && wildcard_any(&request.package.id, &m.package_identifiers)
        && wildcard_any(&request.package.name, &m.package_names)
        && string_in_set(effective_version, &m.versions)
        && version_range_matches(effective_version, &m.version_range)
        && scopes_match(request.options.scope, &m.scopes)
        && architectures_match(request.package.architecture, &m.architectures)
        && elevation_match(request.broker.requested_elevation, &m.elevation)
        && bool_in_set(request.options.interactive, &m.interactive)
        && bool_in_set(request.options.skip_hash_check, &m.skip_hash_check)
        && bool_in_set(request.options.pre_release, &m.pre_release)
        && bool_in_set(flags.has_custom_parameters, &m.has_custom_parameters)
        && bool_in_set(flags.has_custom_install_location, &m.has_custom_install_location)
        && bool_in_set(flags.has_pre_post_commands, &m.has_pre_post_commands)
        && bool_in_set(flags.has_kill_before_operation, &m.has_kill_before_operation)
        && constraints_pass(&rule.constraints, request, flags)
}

fn operations_match(op: Operation, allowed: &BTreeSet<Operation>) -> bool {
    allowed.is_empty() || allowed.contains(&op)
}

fn managers_match(name: ManagerName, allowed: &BTreeSet<ManagerName>) -> bool {
    allowed.is_empty() || allowed.contains(&name)
}

fn scopes_match(scope: Option<Scope>, allowed: &BTreeSet<Scope>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    match scope {
        Some(s) => allowed.contains(&s),
        None => true, // No scope specified = don't restrict.
    }
}

fn architectures_match(arch: Option<Architecture>, allowed: &BTreeSet<Architecture>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    match arch {
        Some(a) => allowed.contains(&a),
        None => true, // No architecture specified = don't restrict.
    }
}

fn elevation_match(elev: Elevation, allowed: &BTreeSet<Elevation>) -> bool {
    allowed.is_empty() || allowed.contains(&elev)
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

fn wildcard_any<S: AsRef<str>>(value: &str, patterns: &BTreeSet<S>) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

fn wildcard_any_vec<S: AsRef<str>>(value: &str, patterns: &[S]) -> bool {
    patterns.iter().any(|pattern| wildcard_match(value, pattern.as_ref()))
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    // Convert glob pattern to regex: escape everything except *, which becomes .*
    let regex_pattern = format!("^{}$", regex::escape(pattern).replace(r"\*", ".*"));
    regex::RegexBuilder::new(&regex_pattern)
        .case_insensitive(true)
        .build()
        .is_ok_and(|re| re.is_match(value))
}

// ─── Constraints ─────────────────────────────────────────────────────────────

fn constraints_pass(constraints: &Option<PolicyConstraints>, request: &PackageRequest, flags: &RequestFlags) -> bool {
    let Some(c) = constraints else {
        return true;
    };

    if !c.allow_interactive && request.options.interactive {
        return false;
    }
    if !c.allow_skip_hash_check && request.options.skip_hash_check {
        return false;
    }
    if !c.allow_pre_release && request.options.pre_release {
        return false;
    }
    if !c.allow_custom_install_location && flags.has_custom_install_location {
        return false;
    }
    if !c.allow_custom_parameters && flags.has_custom_parameters {
        return false;
    }
    if !c.allow_pre_post_commands && flags.has_pre_post_commands {
        return false;
    }
    if !c.allow_kill_before_operation && flags.has_kill_before_operation {
        return false;
    }

    // Check install location patterns.
    if flags.has_custom_install_location
        && !c.allowed_install_location_patterns.is_empty()
        && !wildcard_any_vec(&flags.custom_install_location, &c.allowed_install_location_patterns)
    {
        return false;
    }

    // Check custom parameters.
    for param in &flags.custom_parameters {
        if !c.denied_custom_parameters.is_empty() && wildcard_any_vec(param, &c.denied_custom_parameters) {
            return false;
        }
        if !c.allowed_custom_parameters.is_empty() || !c.allowed_custom_parameter_patterns.is_empty() {
            let exact_allowed = c
                .allowed_custom_parameters
                .iter()
                .any(|v| v.eq_ignore_ascii_case(param));
            let pattern_allowed = wildcard_any_vec(param, &c.allowed_custom_parameter_patterns);
            if !exact_allowed && !pattern_allowed {
                return false;
            }
        }
    }

    true
}

// ─── Version helpers ─────────────────────────────────────────────────────────

fn get_effective_version(request: &PackageRequest) -> String {
    match &request.package.version {
        Some(v) => v.0.clone(),
        None => String::new(),
    }
}

fn version_range_matches(version: &str, range: &Option<crate::model::VersionRange>) -> bool {
    let Some(range) = range else {
        return true;
    };
    if version.is_empty() {
        return false;
    }
    if version.contains('-') && !range.include_prerelease {
        return false;
    }
    if let Some(min) = &range.min_version
        && !min.is_empty()
        && compare_versions(version, min) < 0
    {
        return false;
    }
    if let Some(max) = &range.max_version
        && !max.is_empty()
        && compare_versions(version, max) > 0
    {
        return false;
    }
    true
}

/// Simple numeric version comparison (e.g. "1.2.3" vs "1.2.4").
fn compare_versions(a: &str, b: &str) -> i32 {
    let parse = |s: &str| -> Vec<u64> {
        s.split(['.', '-', '+'])
            .filter_map(|part| part.parse::<u64>().ok())
            .collect()
    };

    let va = parse(a);
    let vb = parse(b);
    let len = va.len().max(vb.len());

    for i in 0..len {
        let pa = va.get(i).copied().unwrap_or(0);
        let pb = vb.get(i).copied().unwrap_or(0);
        if pa < pb {
            return -1;
        }
        if pa > pb {
            return 1;
        }
    }
    0
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::*;

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

    fn make_request(operation: Operation, package_id: &str) -> PackageRequest {
        PackageRequest {
            _schema: RequestSchemaUri,
            request_version: SemanticVersion::from("1.0.0"),
            request_type: PackageOperation,
            request_id: ResourceId::from("req-1"),
            created_at: Utc::now(),
            operation,
            manager: RequestManager {
                name: ManagerName::Winget,
                display_name: "WinGet".to_owned(),
                executable_friendly_name: "winget".to_owned(),
            },
            source: RequestSource {
                name: "winget".to_owned(),
                url: None,
                is_virtual_manager: None,
            },
            package: RequestPackage {
                id: PackageIdentifier(package_id.to_owned()),
                name: "Test Package".to_owned(),
                version: None,
                architecture: None,
                channel: None,
            },
            options: RequestOptions {
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
            broker: BrokerContext {
                requested_elevation: Elevation::Elevated,
                effective_user: "DOMAIN\\user".to_owned(),
                client_version: None,
                client_process_path: None,
            },
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

        let request = make_request(Operation::Install, "Mozilla.Firefox");
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

        let request = make_request(Operation::Install, "Evil.Malware");
        let result = evaluate(&policy, &request);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.rule_id, "<default>");
    }

    #[test]
    fn powershell_manager_evaluates_policy() {
        let policy = make_policy(
            Decision::Allow,
            vec![PolicyRule {
                id: ResourceId::from("r1"),
                enabled: true,
                priority: 1,
                decision: Decision::Allow,
                reason: None,
                match_criteria: PolicyMatch {
                    operations: BTreeSet::from([Operation::Install]),
                    ..Default::default()
                },
                constraints: None,
            }],
        );

        let mut request = make_request(Operation::Install, "Some.Package");
        request.manager.name = ManagerName::PowerShell;

        let result = evaluate(&policy, &request);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn well_formed_policy_round_trips() {
        let policy = make_policy(
            Decision::Deny,
            vec![PolicyRule {
                id: ResourceId::from("rule-1"),
                enabled: true,
                priority: 100,
                decision: Decision::Allow,
                reason: None,
                match_criteria: PolicyMatch {
                    operations: BTreeSet::from([Operation::Install]),
                    managers: BTreeSet::from([ManagerName::Winget]),
                    ..Default::default()
                },
                constraints: None,
            }],
        );

        let json = serde_json::to_string(&policy).unwrap();
        let _roundtripped: PolicyDocument = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn malformed_policy_fails_deserialization() {
        let bad = r#"{ "policyVersion": "1.0.0" }"#;
        assert!(serde_json::from_str::<PolicyDocument>(bad).is_err());
    }
}
