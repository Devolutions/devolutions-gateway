//! Policy evaluation engine.
//!
//! Implements the broker flow described in the UniGetUI package broker policies spec:
//! 1. Validate policy shape
//! 2. Validate request shape
//! 3. Match enabled rules against request
//! 4. Sort by priority (lowest wins), deny wins on tie
//! 5. Fall back to `enforcement.defaultDecision`

use crate::models::{
    PackageRequest, PolicyConstraints, PolicyDocument, PolicyRule, RequestFlags,
};

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: String,
    pub rule_id: String,
    pub reason: String,
}

/// Errors from policy or request validation.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    ValidationError(String),
}

/// Validate basic policy structure without evaluating rules.
/// Used during policy loading to fail early.
pub fn validate_policy_basics(policy: &PolicyDocument) -> Result<(), PolicyError> {
    validate_policy_shape(policy)
}

/// Evaluate a request against a policy document.
pub fn evaluate(policy: &PolicyDocument, request: &PackageRequest) -> Result<PolicyDecision, PolicyError> {
    validate_policy_shape(policy)?;
    validate_request_shape(request)?;

    let flags = RequestFlags::from_request(request);
    let effective_version = get_effective_version(request);

    let mut matched_rules: Vec<(&str, i32, &str, &str)> = Vec::new();

    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }

        if rule_matches(rule, request, &flags, &effective_version) {
            matched_rules.push((
                &rule.id,
                rule.priority,
                &rule.decision,
                rule.reason.as_deref().unwrap_or("Rule matched."),
            ));
        }
    }

    if matched_rules.is_empty() {
        return Ok(PolicyDecision {
            decision: policy.enforcement.default_decision.clone(),
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
            let a_is_deny = a.2.eq_ignore_ascii_case("deny");
            let b_is_deny = b.2.eq_ignore_ascii_case("deny");
            b_is_deny.cmp(&a_is_deny)
        })
    });

    let winner = matched_rules[0];
    Ok(PolicyDecision {
        decision: winner.2.to_owned(),
        rule_id: winner.0.to_owned(),
        reason: winner.3.to_owned(),
    })
}

fn validate_policy_shape(policy: &PolicyDocument) -> Result<(), PolicyError> {
    if policy.policy_type != "packageBrokerPolicy" {
        return Err(PolicyError::ValidationError(
            "policy field 'policyType' must be 'packageBrokerPolicy'".to_owned(),
        ));
    }
    if policy.policy_version.is_empty() {
        return Err(PolicyError::ValidationError(
            "policy field 'policyVersion' is required".to_owned(),
        ));
    }
    if policy.metadata.id.is_empty() {
        return Err(PolicyError::ValidationError(
            "policy field 'metadata.id' is required".to_owned(),
        ));
    }
    if policy.enforcement.failure_decision != "deny" {
        return Err(PolicyError::ValidationError(
            "policy field 'enforcement.failureDecision' must be 'deny'".to_owned(),
        ));
    }
    if policy.enforcement.default_decision != "allow" && policy.enforcement.default_decision != "deny" {
        return Err(PolicyError::ValidationError(
            "policy field 'enforcement.defaultDecision' must be 'allow' or 'deny'".to_owned(),
        ));
    }
    if policy.enforcement.rule_precedence != "priorityThenDeny" {
        return Err(PolicyError::ValidationError(
            "policy field 'enforcement.rulePrecedence' must be 'priorityThenDeny'".to_owned(),
        ));
    }
    if policy.rules.is_empty() {
        return Err(PolicyError::ValidationError(
            "policy field 'rules' must contain at least one rule".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request_shape(request: &PackageRequest) -> Result<(), PolicyError> {
    if request.request_type != "packageOperation" {
        return Err(PolicyError::ValidationError(
            "request field 'requestType' must be 'packageOperation'".to_owned(),
        ));
    }
    if request.request_version.is_empty() {
        return Err(PolicyError::ValidationError(
            "request field 'requestVersion' is required".to_owned(),
        ));
    }
    if request.request_id.is_empty() {
        return Err(PolicyError::ValidationError(
            "request field 'requestId' is required".to_owned(),
        ));
    }
    if !matches!(request.operation.as_str(), "install" | "update" | "uninstall") {
        return Err(PolicyError::ValidationError(format!(
            "request operation '{}' is not supported",
            request.operation
        )));
    }
    // For first iteration, only Winget is fully supported.
    if request.manager.name != "Winget" {
        return Err(PolicyError::ValidationError(format!(
            "manager '{}' is not supported in this version; only 'Winget' is supported",
            request.manager.name
        )));
    }
    if request.source.name.is_empty() {
        return Err(PolicyError::ValidationError(
            "request source.name is required".to_owned(),
        ));
    }
    if request.package.id.is_empty() {
        return Err(PolicyError::ValidationError(
            "request package.id is required".to_owned(),
        ));
    }
    if request.package.name.is_empty() {
        return Err(PolicyError::ValidationError(
            "request package.name is required".to_owned(),
        ));
    }
    if !matches!(
        request.broker.requested_elevation.as_str(),
        "standard" | "elevated"
    ) {
        return Err(PolicyError::ValidationError(
            "request broker.requestedElevation must be 'standard' or 'elevated'".to_owned(),
        ));
    }
    Ok(())
}

fn rule_matches(
    rule: &PolicyRule,
    request: &PackageRequest,
    flags: &RequestFlags,
    effective_version: &str,
) -> bool {
    let m = &rule.match_criteria;

    value_in_list(&request.operation, &m.operations)
        && value_in_list(&request.manager.name, &m.managers)
        && wildcard_any(&request.source.name, &m.sources)
        && wildcard_any(&request.package.id, &m.package_identifiers)
        && wildcard_any(&request.package.name, &m.package_names)
        && string_in_list(effective_version, &m.versions)
        && version_range_matches(effective_version, &m.version_range)
        && optional_in_list(&request.options.scope, &m.scopes)
        && optional_in_list(&request.options.architecture, &m.architectures)
        && value_in_list(&request.broker.requested_elevation, &m.elevation)
        && bool_in_list(request.options.run_as_administrator.unwrap_or(false), &m.run_as_administrator)
        && bool_in_list(request.options.interactive.unwrap_or(false), &m.interactive)
        && bool_in_list(request.options.skip_hash_check.unwrap_or(false), &m.skip_hash_check)
        && bool_in_list(request.options.pre_release.unwrap_or(false), &m.pre_release)
        && bool_in_list(flags.has_custom_parameters, &m.has_custom_parameters)
        && bool_in_list(flags.has_custom_install_location, &m.has_custom_install_location)
        && bool_in_list(flags.has_pre_post_commands, &m.has_pre_post_commands)
        && bool_in_list(flags.has_kill_before_operation, &m.has_kill_before_operation)
        && constraints_pass(&rule.constraints, request, flags)
}

fn constraints_pass(
    constraints: &Option<PolicyConstraints>,
    request: &PackageRequest,
    flags: &RequestFlags,
) -> bool {
    let Some(c) = constraints else {
        return true;
    };

    if c.allow_interactive == Some(false) && request.options.interactive.unwrap_or(false) {
        return false;
    }
    if c.allow_run_as_administrator == Some(false) && request.options.run_as_administrator.unwrap_or(false) {
        return false;
    }
    if c.allow_skip_hash_check == Some(false) && request.options.skip_hash_check.unwrap_or(false) {
        return false;
    }
    if c.allow_pre_release == Some(false) && request.options.pre_release.unwrap_or(false) {
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
    if flags.has_custom_install_location {
        if let Some(patterns) = &c.allowed_install_location_patterns {
            if !wildcard_any_vec(&flags.custom_install_location, patterns) {
                return false;
            }
        }
    }

    // Check custom parameters.
    for param in &flags.custom_parameters {
        if let Some(denied) = &c.denied_custom_parameters {
            if wildcard_any_vec(param, denied) {
                return false;
            }
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

fn value_in_list(value: &str, list: &Option<Vec<String>>) -> bool {
    match list {
        None => true,
        Some(items) => items.iter().any(|item| item.eq_ignore_ascii_case(value)),
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

fn optional_in_list(value: &Option<String>, list: &Option<Vec<String>>) -> bool {
    match list {
        None => true,
        Some(items) => match value {
            Some(v) => items.iter().any(|item| item.eq_ignore_ascii_case(v)),
            None => true, // If the request doesn't specify, don't restrict.
        },
    }
}

fn bool_in_list(value: bool, list: &Option<Vec<bool>>) -> bool {
    match list {
        None => true,
        Some(items) => items.contains(&value),
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
    let regex_pattern = format!(
        "^{}$",
        regex::escape(pattern).replace(r"\*", ".*")
    );
    regex::RegexBuilder::new(&regex_pattern)
        .case_insensitive(true)
        .build()
        .is_ok_and(|re| re.is_match(value))
}

fn get_effective_version(request: &PackageRequest) -> String {
    if let Some(v) = &request.options.version {
        if !v.is_empty() {
            return v.clone();
        }
    }
    if let Some(v) = &request.package.new_version {
        if !v.is_empty() {
            return v.clone();
        }
    }
    if let Some(v) = &request.package.version {
        if !v.is_empty() {
            return v.clone();
        }
    }
    String::new()
}

fn version_range_matches(
    version: &str,
    range: &Option<crate::models::VersionRange>,
) -> bool {
    let Some(range) = range else {
        return true;
    };
    if version.is_empty() {
        return false;
    }
    if version.contains('-') && !range.include_prerelease {
        return false;
    }
    if let Some(min) = &range.min_version {
        if !min.is_empty() && compare_versions(version, min) < 0 {
            return false;
        }
    }
    if let Some(max) = &range.max_version {
        if !max.is_empty() && compare_versions(version, max) > 0 {
            return false;
        }
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
        match pa.cmp(&pb) {
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Greater => return 1,
            std::cmp::Ordering::Equal => {}
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    fn sample_policy() -> PolicyDocument {
        PolicyDocument {
            policy_version: "1.0.0".to_owned(),
            policy_type: "packageBrokerPolicy".to_owned(),
            metadata: PolicyMetadata {
                id: "test-policy".to_owned(),
                publisher: None,
                revision: 1,
                published_at: None,
            },
            enforcement: PolicyEnforcement {
                default_decision: "deny".to_owned(),
                failure_decision: "deny".to_owned(),
                rule_precedence: "priorityThenDeny".to_owned(),
            },
            rules: vec![PolicyRule {
                id: "allow.winget.vscode".to_owned(),
                enabled: true,
                priority: 100,
                decision: "allow".to_owned(),
                reason: Some("VS Code is approved.".to_owned()),
                match_criteria: PolicyMatch {
                    managers: Some(vec!["Winget".to_owned()]),
                    package_identifiers: Some(vec!["Microsoft.VisualStudioCode".to_owned()]),
                    ..Default::default()
                },
                constraints: None,
            }],
        }
    }

    fn sample_request() -> PackageRequest {
        PackageRequest {
            request_version: "1.0.0".to_owned(),
            request_type: "packageOperation".to_owned(),
            request_id: "req-test-1".to_owned(),
            created_at: "2026-05-05T12:00:00Z".to_owned(),
            operation: "install".to_owned(),
            manager: RequestManager {
                name: "Winget".to_owned(),
                display_name: Some("WinGet".to_owned()),
                executable_friendly_name: Some("winget.exe".to_owned()),
            },
            source: RequestSource {
                name: "winget".to_owned(),
                url: None,
                is_virtual_manager: None,
            },
            package: RequestPackage {
                id: "Microsoft.VisualStudioCode".to_owned(),
                name: "Microsoft Visual Studio Code".to_owned(),
                version: None,
                new_version: None,
            },
            options: RequestOptions {
                scope: Some("machine".to_owned()),
                architecture: Some("x64".to_owned()),
                interactive: Some(false),
                run_as_administrator: Some(true),
                skip_hash_check: Some(false),
                pre_release: Some(false),
                version: None,
                custom_parameters: Some(vec![]),
                custom_install_location: None,
                kill_before_operation: Some(vec![]),
                pre_operation_command: None,
                post_operation_command: None,
            },
            broker: BrokerContext {
                requested_elevation: "elevated".to_owned(),
                effective_user: "CONTOSO\\alice".to_owned(),
                client_version: "3.2.0".to_owned(),
            },
        }
    }

    #[test]
    fn test_allow_matching_package() {
        let policy = sample_policy();
        let request = sample_request();
        let result = evaluate(&policy, &request).unwrap();
        assert_eq!(result.decision, "allow");
        assert_eq!(result.rule_id, "allow.winget.vscode");
    }

    #[test]
    fn test_deny_unmatched_package() {
        let policy = sample_policy();
        let mut request = sample_request();
        request.package.id = "Some.Other.Package".to_owned();
        request.package.name = "Other Package".to_owned();
        let result = evaluate(&policy, &request).unwrap();
        assert_eq!(result.decision, "deny");
        assert_eq!(result.rule_id, "<default>");
    }

    #[test]
    fn test_unsupported_manager() {
        let policy = sample_policy();
        let mut request = sample_request();
        request.manager.name = "Scoop".to_owned();
        let result = evaluate(&policy, &request);
        assert!(result.is_err());
    }
}
