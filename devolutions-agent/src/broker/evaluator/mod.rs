//! Policy evaluation engine.
//!
//! Implements the broker flow described in the package broker policies spec:
//! 1. Match enabled rules against request
//! 2. Sort by priority (lowest wins), deny wins on tie
//! 3. Fall back to `enforcement.defaultDecision`

use now_policy::{Decision, PolicyDocument};
use now_policy_api::PackageRequest;

mod constraints;
mod matching;
mod version;
mod wildcard;

#[cfg(test)]
mod tests;

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub rule_id: String,
    pub reason: String,
}

struct RequestFlags {
    has_custom_parameters: bool,
    has_custom_install_location: bool,
    has_pre_post_commands: bool,
    has_kill_before_operation: bool,
    has_uninstall_previous: bool,
    no_upgrade: bool,
    custom_install_location: String,
    custom_parameters: Vec<String>,
}

impl RequestFlags {
    fn from_request(request: &PackageRequest) -> Self {
        Self {
            has_custom_parameters: !request.options.custom_parameters.is_empty(),
            has_custom_install_location: request
                .options
                .custom_install_location
                .as_deref()
                .is_some_and(|location| !location.is_empty()),
            has_pre_post_commands: request.options.pre_operation_command.is_some()
                || request.options.post_operation_command.is_some(),
            has_kill_before_operation: !request.options.kill_before_operation.is_empty(),
            has_uninstall_previous: request.options.uninstall_previous,
            no_upgrade: request.options.no_upgrade,
            custom_install_location: request.options.custom_install_location.clone().unwrap_or_default(),
            custom_parameters: request
                .options
                .custom_parameters
                .iter()
                .map(|parameter| parameter.as_ref().to_owned())
                .collect(),
        }
    }
}

/// Evaluate a parsed request against a parsed policy document.
///
/// Both the policy and request should have already been deserialized into typed structs.
/// This function performs the rule-matching logic only.
pub fn evaluate(policy: &PolicyDocument, request: &PackageRequest) -> PolicyDecision {
    let flags = RequestFlags::from_request(request);
    let effective_version = version::get_effective_version(request);

    let mut matched_rules: Vec<(&str, u32, Decision, &str)> = Vec::new();

    for rule in &policy.rules {
        if !rule.enabled {
            continue;
        }

        if matching::rule_matches(rule, request, &flags, &effective_version) {
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
