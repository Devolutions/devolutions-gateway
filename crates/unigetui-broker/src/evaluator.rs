//! Policy evaluation engine.
//!
//! Implements the broker flow described in the UniGetUI package broker policies spec:
//! 1. Validate policy via JSON Schema (generated from Rust types via schemars)
//! 2. Validate request via JSON Schema
//! 3. Match enabled rules against request
//! 4. Sort by priority (lowest wins), deny wins on tie
//! 5. Fall back to `enforcement.defaultDecision`

use crate::models::{
    Architecture, Decision, Elevation, ManagerName, Operation, PackageRequest, PolicyConstraints, PolicyDocument,
    PolicyRule, RequestFlags, Scope,
};
use crate::schema::SchemaValidators;

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub rule_id: String,
    pub reason: String,
}

/// Errors from policy or request validation.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
}

/// Validate a policy document using the generated JSON Schema.
///
/// Call this during policy loading to fail early on malformed documents.
pub fn validate_policy(validators: &SchemaValidators, policy_value: &serde_json::Value) -> Result<(), PolicyError> {
    validators
        .validate_policy(policy_value)
        .map_err(|e| PolicyError::SchemaValidation(e.message))
}

/// Validate a request using the generated JSON Schema.
pub fn validate_request(validators: &SchemaValidators, request_value: &serde_json::Value) -> Result<(), PolicyError> {
    validators
        .validate_request(request_value)
        .map_err(|e| PolicyError::SchemaValidation(e.message))
}

/// Evaluate a parsed request against a parsed policy document.
///
/// Both the policy and request should have already been validated via `validate_policy`
/// and `validate_request` (schema validation) and then deserialized into typed structs.
/// This function performs the rule-matching logic only.
pub fn evaluate(policy: &PolicyDocument, request: &PackageRequest) -> Result<PolicyDecision, PolicyError> {
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
        return Ok(PolicyDecision {
            decision: policy.enforcement.default_decision,
            rule_id: "<default>".to_owned(),
            reason: format!(
                "No enabled rule matched; using defaultDecision '{}'.",
                policy.enforcement.default_decision
            ),
        });
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
    Ok(PolicyDecision {
        decision: winner.2,
        rule_id: winner.0.to_owned(),
        reason: winner.3.to_owned(),
    })
}

// ─── Rule matching ───────────────────────────────────────────────────────────

fn rule_matches(rule: &PolicyRule, request: &PackageRequest, flags: &RequestFlags, effective_version: &str) -> bool {
    let m = &rule.match_criteria;

    operations_match(request.operation, &m.operations)
        && managers_match(request.manager.name, &m.managers)
        && wildcard_any(&request.source.name, &m.sources)
        && wildcard_any(&request.package.id, &m.package_identifiers)
        && wildcard_any(&request.package.name, &m.package_names)
        && string_in_list(effective_version, &m.versions)
        && version_range_matches(effective_version, &m.version_range)
        && scopes_match(request.options.scope, &m.scopes)
        && architectures_match(request.options.architecture, &m.architectures)
        && elevation_match(request.broker.requested_elevation, &m.elevation)
        && bool_in_list(request.options.run_as_administrator, &m.run_as_administrator)
        && bool_in_list(request.options.interactive, &m.interactive)
        && bool_in_list(request.options.skip_hash_check, &m.skip_hash_check)
        && bool_in_list(request.options.pre_release, &m.pre_release)
        && bool_in_list(flags.has_custom_parameters, &m.has_custom_parameters)
        && bool_in_list(flags.has_custom_install_location, &m.has_custom_install_location)
        && bool_in_list(flags.has_pre_post_commands, &m.has_pre_post_commands)
        && bool_in_list(flags.has_kill_before_operation, &m.has_kill_before_operation)
        && constraints_pass(&rule.constraints, request, flags)
}

fn operations_match(op: Operation, allowed: &Option<Vec<Operation>>) -> bool {
    match allowed {
        None => true,
        Some(list) => list.contains(&op),
    }
}

fn managers_match(name: ManagerName, allowed: &Option<Vec<ManagerName>>) -> bool {
    match allowed {
        None => true,
        Some(list) => list.contains(&name),
    }
}

fn scopes_match(scope: Option<Scope>, allowed: &Option<Vec<Scope>>) -> bool {
    match allowed {
        None => true,
        Some(list) => match scope {
            Some(s) => list.contains(&s),
            None => true, // No scope specified = don't restrict.
        },
    }
}

fn architectures_match(arch: Option<Architecture>, allowed: &Option<Vec<Architecture>>) -> bool {
    match allowed {
        None => true,
        Some(list) => match arch {
            Some(a) => list.contains(&a),
            None => true, // No architecture specified = don't restrict.
        },
    }
}

fn elevation_match(elev: Elevation, allowed: &Option<Vec<Elevation>>) -> bool {
    match allowed {
        None => true,
        Some(list) => list.contains(&elev),
    }
}

fn bool_in_list(value: bool, list: &Option<Vec<bool>>) -> bool {
    match list {
        None => true,
        Some(items) => items.contains(&value),
    }
}

fn string_in_list(value: &str, list: &Option<Vec<String>>) -> bool {
    match list {
        None => true,
        Some(items) => {
            if value.is_empty() {
                // If no version specified and list requires specific versions, don't match.
                return false;
            }
            items.iter().any(|item| item == value)
        }
    }
}

fn wildcard_any(value: &str, patterns: &Option<Vec<String>>) -> bool {
    match patterns {
        None => true,
        Some(pats) => pats.iter().any(|pattern| wildcard_match(value, pattern)),
    }
}

fn wildcard_any_vec(value: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| wildcard_match(value, pattern))
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

    if c.allow_interactive == Some(false) && request.options.interactive {
        return false;
    }
    if c.allow_run_as_administrator == Some(false) && request.options.run_as_administrator {
        return false;
    }
    if c.allow_skip_hash_check == Some(false) && request.options.skip_hash_check {
        return false;
    }
    if c.allow_pre_release == Some(false) && request.options.pre_release {
        return false;
    }
    if c.allow_custom_install_location == Some(false) && flags.has_custom_install_location {
        return false;
    }
    if c.allow_custom_parameters == Some(false) && flags.has_custom_parameters {
        return false;
    }
    if c.allow_pre_post_commands == Some(false) && flags.has_pre_post_commands {
        return false;
    }
    if c.allow_kill_before_operation == Some(false) && flags.has_kill_before_operation {
        return false;
    }

    // Check install location patterns.
    if flags.has_custom_install_location
        && let Some(patterns) = &c.allowed_install_location_patterns
        && !wildcard_any_vec(&flags.custom_install_location, patterns)
    {
        return false;
    }

    // Check custom parameters.
    for param in &flags.custom_parameters {
        if let Some(denied) = &c.denied_custom_parameters
            && wildcard_any_vec(param, denied)
        {
            return false;
        }
        if c.allowed_custom_parameters.is_some() || c.allowed_custom_parameter_patterns.is_some() {
            let exact_allowed = c
                .allowed_custom_parameters
                .as_ref()
                .is_some_and(|list| list.iter().any(|v| v.eq_ignore_ascii_case(param)));
            let pattern_allowed = c
                .allowed_custom_parameter_patterns
                .as_ref()
                .is_some_and(|patterns| wildcard_any_vec(param, patterns));
            if !exact_allowed && !pattern_allowed {
                return false;
            }
        }
    }

    true
}

// ─── Version helpers ─────────────────────────────────────────────────────────

fn get_effective_version(request: &PackageRequest) -> String {
    if let Some(v) = &request.options.version
        && !v.is_empty()
    {
        return v.clone();
    }
    if let Some(v) = &request.package.new_version
        && !v.is_empty()
    {
        return v.clone();
    }
    if let Some(v) = &request.package.version
        && !v.is_empty()
    {
        return v.clone();
    }
    String::new()
}

fn version_range_matches(version: &str, range: &Option<crate::models::VersionRange>) -> bool {
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
    use super::*;
    use crate::models::*;

    fn make_policy(default_decision: Decision, rules: Vec<PolicyRule>) -> PolicyDocument {
        PolicyDocument {
            schema: None,
            policy_version: "1.0.0".to_owned(),
            policy_type: "packageBrokerPolicy".to_owned(),
            metadata: PolicyMetadata {
                id: "test-policy".to_owned(),
                publisher: "Test".to_owned(),
                revision: 1,
                published_at: "2025-01-01T00:00:00Z".to_owned(),
                valid_from: None,
                valid_until: None,
                description: None,
                support_url: None,
            },
            enforcement: PolicyEnforcement {
                default_decision,
                failure_decision: FailureDecision::Deny,
                rule_precedence: RulePrecedence::PriorityThenDeny,
                audit_mode: None,
            },
            rules,
        }
    }

    fn make_request(operation: Operation, package_id: &str) -> PackageRequest {
        PackageRequest {
            schema: None,
            request_version: "1.0.0".to_owned(),
            request_type: "packageOperation".to_owned(),
            request_id: "req-1".to_owned(),
            created_at: "2025-01-01T00:00:00Z".to_owned(),
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
                id: package_id.to_owned(),
                name: "Test Package".to_owned(),
                version: None,
                new_version: None,
                channel: None,
            },
            options: RequestOptions {
                scope: None,
                architecture: None,
                version: None,
                interactive: false,
                run_as_administrator: false,
                skip_hash_check: false,
                pre_release: false,
                custom_install_location: None,
                custom_parameters: None,
                pre_operation_command: None,
                post_operation_command: None,
                kill_before_operation: None,
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
                id: "allow-firefox".to_owned(),
                enabled: true,
                priority: 100,
                decision: Decision::Allow,
                description: None,
                reason: Some("Firefox is allowed.".to_owned()),
                match_criteria: PolicyMatch {
                    package_identifiers: Some(vec!["Mozilla.Firefox".to_owned()]),
                    ..Default::default()
                },
                constraints: None,
            }],
        );

        let request = make_request(Operation::Install, "Mozilla.Firefox");
        let result = evaluate(&policy, &request).unwrap();
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.rule_id, "allow-firefox");
    }

    #[test]
    fn deny_unmatched_package() {
        let policy = make_policy(
            Decision::Deny,
            vec![PolicyRule {
                id: "allow-firefox".to_owned(),
                enabled: true,
                priority: 100,
                decision: Decision::Allow,
                description: None,
                reason: None,
                match_criteria: PolicyMatch {
                    package_identifiers: Some(vec!["Mozilla.Firefox".to_owned()]),
                    ..Default::default()
                },
                constraints: None,
            }],
        );

        let request = make_request(Operation::Install, "Evil.Malware");
        let result = evaluate(&policy, &request).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.rule_id, "<default>");
    }

    #[test]
    fn powershell_manager_evaluates_policy() {
        let policy = make_policy(
            Decision::Allow,
            vec![PolicyRule {
                id: "r1".to_owned(),
                enabled: true,
                priority: 1,
                decision: Decision::Allow,
                description: None,
                reason: None,
                match_criteria: PolicyMatch::default(),
                constraints: None,
            }],
        );

        let mut request = make_request(Operation::Install, "Some.Package");
        request.manager.name = ManagerName::PowerShell;

        let result = evaluate(&policy, &request).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn schema_validates_well_formed_policy() {
        let validators = SchemaValidators::new();
        let policy = make_policy(
            Decision::Deny,
            vec![PolicyRule {
                id: "rule-1".to_owned(),
                enabled: true,
                priority: 100,
                decision: Decision::Allow,
                description: None,
                reason: None,
                match_criteria: PolicyMatch {
                    operations: Some(vec![Operation::Install]),
                    managers: Some(vec![ManagerName::Winget]),
                    ..Default::default()
                },
                constraints: None,
            }],
        );

        let value = serde_json::to_value(&policy).unwrap();
        validate_policy(&validators, &value).unwrap();
    }

    #[test]
    fn schema_rejects_malformed_policy() {
        let validators = SchemaValidators::new();
        let bad = serde_json::json!({ "policyVersion": "1.0.0" });
        assert!(validate_policy(&validators, &bad).is_err());
    }
}
