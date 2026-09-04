//! Strict deterministic validation for editable policy documents.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use now_policy::{Decision, PolicyConstraints, PolicyDraftDocument, PolicyDraftMetadata, PolicyMatch, PolicyRule};
use now_policy_api::{
    API_VERSION_STR, PolicyFinding, PolicyFindingCode, PolicyFindingSeverity, PolicyValidationResult,
};

pub const VALIDATOR_VERSION: &str = "now-package-broker-policy-validator/4";
const MAX_RULES: usize = 1024;
const MAX_RULE_PRIORITY: u32 = i32::MAX as u32;
const MAX_FINDING_MESSAGE_CHARS: usize = 2048;
const MAX_FINDINGS: usize = 128;
const FINDINGS_TRUNCATED_MESSAGE: &str = "additional validation findings were omitted";
const MATCH_COLLECTION_MAXIMA: &[(&str, usize)] = &[
    ("Operations", 3),
    ("Managers", 16),
    ("Sources", 128),
    ("PackageIdentifiers", 1024),
    ("PackageNames", 1024),
    ("Versions", 256),
    ("Scopes", 2),
    ("Architectures", 5),
    ("Elevation", 2),
];
const BOOLEAN_MATCH_FIELDS: &[&str] = &[
    "Interactive",
    "SkipHashCheck",
    "PreRelease",
    "HasCustomParameters",
    "HasCustomInstallLocation",
    "HasPrePostCommands",
    "HasKillBeforeOperation",
    "HasUninstallPrevious",
];
const CONSTRAINT_COLLECTION_MAXIMA: &[(&str, usize)] = &[
    ("AllowedInstallLocationPatterns", 64),
    ("AllowedCustomParameters", 128),
    ("AllowedCustomParameterPatterns", 128),
    ("DeniedCustomParameters", 128),
];
struct Findings {
    values: Vec<PolicyFinding>,
    saturated: bool,
}
impl Findings {
    fn new() -> Self {
        Self {
            values: Vec::with_capacity(MAX_FINDINGS),
            saturated: false,
        }
    }
    fn push(&mut self, finding: PolicyFinding) {
        if self.saturated {
            return;
        }
        if self.values.len() == MAX_FINDINGS - 1 {
            self.values.push(error(
                PolicyFindingCode::SchemaViolation,
                "",
                FINDINGS_TRUNCATED_MESSAGE,
            ));
            self.saturated = true;
        } else {
            self.values.push(finding);
        }
    }
    fn is_saturated(&self) -> bool {
        self.saturated
    }
}
pub fn validate_draft(raw: &serde_json::Value) -> PolicyValidationResult {
    let mut findings = Findings::new();
    if !raw.is_object() {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            "",
            "the policy draft must be a JSON object",
        ));
        return invalid_result(findings);
    }
    check_constant(
        raw,
        "$schema",
        "/$schema",
        now_policy::POLICY_DRAFT_SCHEMA_URI,
        PolicyFindingCode::UnsupportedSchema,
        &mut findings,
    );
    check_constant(
        raw,
        "PolicyType",
        "/PolicyType",
        "PackageBrokerPolicy",
        PolicyFindingCode::UnsupportedPolicyType,
        &mut findings,
    );
    check_policy_version(raw, &mut findings);
    if has_error(&findings) {
        return invalid_result(findings);
    }
    if check_raw_collection_bounds(raw, &mut findings) {
        return invalid_result(findings);
    }
    match serde_json::from_value::<PolicyDraftDocument>(raw.clone()) {
        Ok(draft) => {
            semantic_checks(&draft, &mut findings);
            if has_error(&findings) {
                invalid_result(findings)
            } else {
                valid_result(draft, findings)
            }
        }
        Err(parse_error) => {
            findings.push(classify_parse_error(&parse_error));
            invalid_result(findings)
        }
    }
}
pub(crate) fn validate_committed_policy(policy: &now_policy::PolicyDocument) -> PolicyValidationResult {
    let raw = serde_json::to_value(policy.to_draft()).expect("committed policy draft serializes");
    validate_draft(&raw)
}
fn has_error(findings: &Findings) -> bool {
    findings
        .values
        .iter()
        .any(|finding| finding.severity == PolicyFindingSeverity::Error)
}
fn invalid_result(findings: Findings) -> PolicyValidationResult {
    PolicyValidationResult {
        result_version: API_VERSION_STR.into(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        is_valid: false,
        canonical_draft: None,
        validation_receipt: None,
        findings: findings.values,
    }
}
fn valid_result(draft: PolicyDraftDocument, findings: Findings) -> PolicyValidationResult {
    PolicyValidationResult {
        result_version: API_VERSION_STR.into(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        is_valid: true,
        canonical_draft: Some(draft),
        validation_receipt: None,
        findings: findings.values,
    }
}
fn finding(
    severity: PolicyFindingSeverity,
    code: PolicyFindingCode,
    path: impl Into<String>,
    message: impl Into<String>,
) -> PolicyFinding {
    let message = message.into();
    let message = if message.chars().count() <= MAX_FINDING_MESSAGE_CHARS {
        message
    } else {
        let mut bounded = message.chars().take(MAX_FINDING_MESSAGE_CHARS - 3).collect::<String>();
        bounded.push_str("...");
        bounded
    };
    PolicyFinding {
        finding_version: API_VERSION_STR.into(),
        severity,
        code,
        path: path.into(),
        rule_id: None,
        arguments: BTreeMap::new(),
        message,
    }
}
fn error(code: PolicyFindingCode, path: impl Into<String>, message: impl Into<String>) -> PolicyFinding {
    finding(PolicyFindingSeverity::Error, code, path, message)
}
fn warning(code: PolicyFindingCode, path: impl Into<String>, message: impl Into<String>) -> PolicyFinding {
    finding(PolicyFindingSeverity::Warning, code, path, message)
}
fn rule_finding(
    rule: &PolicyRule,
    severity: PolicyFindingSeverity,
    code: PolicyFindingCode,
    path: impl Into<String>,
    message: impl Into<String>,
) -> PolicyFinding {
    let mut finding = finding(severity, code, path, message);
    finding.rule_id = Some(now_policy_api::ResourceId::from(rule.id.0.as_str()));
    finding
}
fn check_constant(
    raw: &serde_json::Value,
    key: &str,
    path: &str,
    expected: &str,
    mismatch_code: PolicyFindingCode,
    findings: &mut Findings,
) {
    match raw.get(key) {
        None => findings.push(error(
            PolicyFindingCode::MissingRequiredField,
            path,
            format!("missing required field '{key}'"),
        )),
        Some(serde_json::Value::String(value)) if value == expected => {}
        Some(serde_json::Value::String(value)) => findings.push(error(
            mismatch_code,
            path,
            format!("unsupported value '{value}'; expected '{expected}'"),
        )),
        Some(_) => findings.push(error(
            PolicyFindingCode::InvalidFieldType,
            path,
            format!("'{key}' must be a string"),
        )),
    }
}
fn check_policy_version(raw: &serde_json::Value, findings: &mut Findings) {
    const PATH: &str = "/PolicyVersion";
    match raw.get("PolicyVersion") {
        None => findings.push(error(
            PolicyFindingCode::MissingRequiredField,
            PATH,
            "missing required field 'PolicyVersion'",
        )),
        Some(serde_json::Value::String(value)) if value.len() > 128 => findings.push(error(
            PolicyFindingCode::InvalidFieldValue,
            PATH,
            "PolicyVersion exceeds the maximum length of 128",
        )),
        Some(serde_json::Value::String(value)) => match semver::Version::parse(value) {
            Ok(version) if version.major == 1 => {}
            Ok(version) => findings.push(error(
                PolicyFindingCode::UnsupportedPolicyVersion,
                PATH,
                format!("unsupported PolicyVersion major '{}'; expected 1.x", version.major),
            )),
            Err(parse_error) => findings.push(error(
                PolicyFindingCode::InvalidFieldValue,
                PATH,
                format!("PolicyVersion is not a valid semantic version: {parse_error}"),
            )),
        },
        Some(_) => findings.push(error(
            PolicyFindingCode::InvalidFieldType,
            PATH,
            "'PolicyVersion' must be a string",
        )),
    }
}
pub(crate) fn classify_parse_error(parse_error: &serde_json::Error) -> PolicyFinding {
    let message = parse_error.to_string();
    let code = if message.contains("boolean match arrays") {
        PolicyFindingCode::IneffectiveBooleanMatch
    } else if message.contains("missing field") {
        PolicyFindingCode::MissingRequiredField
    } else if message.contains("unknown field") {
        PolicyFindingCode::UnknownField
    } else if message.contains("invalid type") {
        PolicyFindingCode::InvalidFieldType
    } else {
        PolicyFindingCode::InvalidFieldValue
    };
    error(
        code,
        "",
        format!("policy draft does not match the expected schema: {message}"),
    )
}
fn check_raw_collection_bounds(raw: &serde_json::Value, findings: &mut Findings) -> bool {
    let Some(rules) = raw.get("Rules").and_then(serde_json::Value::as_array) else {
        return false;
    };
    if rules.len() > MAX_RULES {
        check_max_len(rules.len(), MAX_RULES, "/Rules", findings);
        return true;
    }
    for (index, rule) in rules.iter().enumerate() {
        let Some(rule) = rule.as_object() else {
            continue;
        };
        let base = format!("/Rules/{index}");
        if let Some(matches) = rule.get("Match").and_then(serde_json::Value::as_object) {
            for &(field, max) in MATCH_COLLECTION_MAXIMA {
                check_raw_array_len(matches, field, max, &format!("{base}/Match/{field}"), findings);
            }
            for &field in BOOLEAN_MATCH_FIELDS {
                if matches
                    .get(field)
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|values| values.len() > 1)
                {
                    findings.push(error(
                        PolicyFindingCode::IneffectiveBooleanMatch,
                        format!("{base}/Match/{field}"),
                        "boolean match arrays may contain at most one value",
                    ));
                }
            }
        }
        if let Some(constraints) = rule.get("Constraints").and_then(serde_json::Value::as_object) {
            for &(field, max) in CONSTRAINT_COLLECTION_MAXIMA {
                check_raw_array_len(
                    constraints,
                    field,
                    max,
                    &format!("{base}/Constraints/{field}"),
                    findings,
                );
            }
        }
        if findings.is_saturated() {
            break;
        }
    }
    has_error(findings)
}
fn check_raw_array_len(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    max: usize,
    path: &str,
    findings: &mut Findings,
) {
    if let Some(values) = object.get(field).and_then(serde_json::Value::as_array) {
        check_max_len(values.len(), max, path, findings);
    }
}
#[derive(Debug, Clone, Copy)]
pub(crate) enum DiskFailureReason {
    Unreadable,
    InsecureStorage,
    MalformedContent,
    UnsupportedFormat,
    FailedSemanticValidation,
    WatcherUnavailable,
}
pub(crate) fn disk_failure_finding(reason: DiskFailureReason) -> PolicyFinding {
    let message = match reason {
        DiskFailureReason::Unreadable => "the configured policy file could not be opened or read",
        DiskFailureReason::InsecureStorage => "the configured policy file failed storage security validation",
        DiskFailureReason::MalformedContent => {
            "the configured policy file does not contain a policy matching the expected schema"
        }
        DiskFailureReason::UnsupportedFormat => "the configured policy path uses an unsupported format",
        DiskFailureReason::FailedSemanticValidation => "the configured policy file failed semantic validation",
        DiskFailureReason::WatcherUnavailable => "policy change monitoring is unavailable",
    };
    error(PolicyFindingCode::SchemaViolation, "", message)
}
fn semantic_checks(draft: &PolicyDraftDocument, findings: &mut Findings) {
    if draft.rules.len() > MAX_RULES {
        check_max_len(draft.rules.len(), MAX_RULES, "/Rules", findings);
        return;
    }
    check_metadata(&draft.metadata, findings);
    check_duplicate_rule_ids(&draft.rules, findings);
    for (index, rule) in draft.rules.iter().enumerate() {
        if findings.is_saturated() {
            return;
        }
        check_rule(index, rule, findings);
    }
    if findings.is_saturated() {
        return;
    }
    if draft.enforcement.audit_mode == Some(true) {
        findings.push(warning(
            PolicyFindingCode::AuditModeEnabled,
            "/Enforcement/AuditMode",
            "audit mode is enabled; decisions are not enforced",
        ));
    }
    if draft.enforcement.default_decision == Decision::Allow {
        findings.push(warning(
            PolicyFindingCode::DefaultAllow,
            "/Enforcement/DefaultDecision",
            "the default decision is Allow",
        ));
    }
    for (index, rule) in draft.rules.iter().enumerate() {
        if findings.is_saturated() {
            return;
        }
        check_sensitive_options(index, rule, findings);
    }
}
fn check_metadata(metadata: &PolicyDraftMetadata, findings: &mut Findings) {
    check_string_len(&metadata.publisher, 1, 128, "/Metadata/Publisher", findings);
    if let Some(description) = &metadata.description {
        check_string_len(description, 0, 512, "/Metadata/Description", findings);
    }
    if let (Some(valid_from), Some(valid_until)) = (metadata.valid_from, metadata.valid_until)
        && valid_from > valid_until
    {
        findings.push(error(
            PolicyFindingCode::InvalidValidityInterval,
            "/Metadata/ValidUntil",
            "ValidUntil is before ValidFrom",
        ));
    }
}
fn check_duplicate_rule_ids(rules: &[PolicyRule], findings: &mut Findings) {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for (index, rule) in rules.iter().enumerate() {
        if findings.is_saturated() {
            return;
        }
        if let Some(first_index) = seen.insert(&rule.id.0, index) {
            findings.push(rule_finding(
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::DuplicateRuleId,
                format!("/Rules/{index}/Id"),
                format!("rule id '{}' duplicates rule at index {first_index}", rule.id),
            ));
        }
    }
}
fn check_rule(index: usize, rule: &PolicyRule, findings: &mut Findings) {
    let base = format!("/Rules/{index}");
    let matches = &rule.match_criteria;
    if rule.priority > MAX_RULE_PRIORITY {
        findings.push(rule_finding(
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::InvalidFieldValue,
            format!("{base}/Priority"),
            format!("Priority exceeds {MAX_RULE_PRIORITY}"),
        ));
    }
    if let Some(reason) = &rule.reason {
        check_string_len(reason, 0, 512, &format!("{base}/Reason"), findings);
    }
    check_max_len(matches.managers.len(), 16, &format!("{base}/Match/Managers"), findings);
    check_max_len(matches.sources.len(), 128, &format!("{base}/Match/Sources"), findings);
    check_max_len(
        matches.package_identifiers.len(),
        1024,
        &format!("{base}/Match/PackageIdentifiers"),
        findings,
    );
    check_max_len(
        matches.package_names.len(),
        1024,
        &format!("{base}/Match/PackageNames"),
        findings,
    );
    check_max_len(matches.versions.len(), 256, &format!("{base}/Match/Versions"), findings);
    if !matches.package_names.is_empty() {
        findings.push(rule_finding(
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::InvalidFieldValue,
            format!("{base}/Match/PackageNames"),
            "PackageNames is unsupported because requests do not provide a package display name",
        ));
    }
    check_version_range(index, rule, findings);
    check_patterns(
        index,
        rule,
        "Match/Sources",
        matches.sources.iter().take(128).map(AsRef::as_ref),
        findings,
    );
    check_patterns(
        index,
        rule,
        "Match/PackageIdentifiers",
        matches.package_identifiers.iter().take(1024).map(AsRef::as_ref),
        findings,
    );
    if let Some(constraints) = &rule.constraints {
        check_constraints(index, rule, constraints, findings);
    }
}
fn check_constraints(index: usize, rule: &PolicyRule, constraints: &PolicyConstraints, findings: &mut Findings) {
    let base = format!("/Rules/{index}/Constraints");
    check_max_len(
        constraints.allowed_install_location_patterns.len(),
        64,
        &format!("{base}/AllowedInstallLocationPatterns"),
        findings,
    );
    check_max_len(
        constraints.allowed_custom_parameters.len(),
        128,
        &format!("{base}/AllowedCustomParameters"),
        findings,
    );
    check_max_len(
        constraints.allowed_custom_parameter_patterns.len(),
        128,
        &format!("{base}/AllowedCustomParameterPatterns"),
        findings,
    );
    check_max_len(
        constraints.denied_custom_parameters.len(),
        128,
        &format!("{base}/DeniedCustomParameters"),
        findings,
    );
    check_patterns(
        index,
        rule,
        "Constraints/AllowedInstallLocationPatterns",
        constraints
            .allowed_install_location_patterns
            .iter()
            .take(64)
            .map(AsRef::as_ref),
        findings,
    );
    check_patterns(
        index,
        rule,
        "Constraints/AllowedCustomParameterPatterns",
        constraints
            .allowed_custom_parameter_patterns
            .iter()
            .take(128)
            .map(AsRef::as_ref),
        findings,
    );
    let matches = &rule.match_criteria;
    for (values, allowed, name) in [
        (&matches.interactive, constraints.allow_interactive, "Interactive"),
        (
            &matches.skip_hash_check,
            constraints.allow_skip_hash_check,
            "SkipHashCheck",
        ),
        (&matches.pre_release, constraints.allow_pre_release, "PreRelease"),
        (
            &matches.has_custom_install_location,
            constraints.allow_custom_install_location,
            "HasCustomInstallLocation",
        ),
        (
            &matches.has_custom_parameters,
            constraints.allow_custom_parameters,
            "HasCustomParameters",
        ),
        (
            &matches.has_pre_post_commands,
            constraints.allow_pre_post_commands,
            "HasPrePostCommands",
        ),
        (
            &matches.has_kill_before_operation,
            constraints.allow_kill_before_operation,
            "HasKillBeforeOperation",
        ),
        (
            &matches.has_uninstall_previous,
            constraints.allow_uninstall_previous,
            "HasUninstallPrevious",
        ),
    ] {
        if findings.is_saturated() {
            return;
        }
        if !allowed && values.len() == 1 && values.contains(&true) {
            findings.push(rule_finding(
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::ContradictoryConstraints,
                &base,
                format!("rule requires {name}=true but its constraints deny {name}"),
            ));
        }
    }
}
fn check_version_range(index: usize, rule: &PolicyRule, findings: &mut Findings) {
    let Some(range) = &rule.match_criteria.version_range else {
        return;
    };
    let base = format!("/Rules/{index}/Match/VersionRange");
    let min = parse_version_bound(
        range.min_version.as_deref(),
        &format!("{base}/MinVersion"),
        rule,
        findings,
    );
    let max = parse_version_bound(
        range.max_version.as_deref(),
        &format!("{base}/MaxVersion"),
        rule,
        findings,
    );
    if range.min_version.is_none() && range.max_version.is_none() {
        findings.push(rule_finding(
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::EmptyVersionRange,
            &base,
            "version range must specify MinVersion or MaxVersion",
        ));
    } else if let (Some(min), Some(max)) = (min, max)
        && min > max
    {
        findings.push(rule_finding(
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::EmptyVersionRange,
            &base,
            "MinVersion is greater than MaxVersion",
        ));
    }
}
fn parse_version_bound(
    value: Option<&str>,
    path: &str,
    rule: &PolicyRule,
    findings: &mut Findings,
) -> Option<semver::Version> {
    let value = value?;
    if value.is_empty() || value.len() > 128 {
        findings.push(rule_finding(
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::InvalidVersionRange,
            path,
            "version bound must contain 1 to 128 characters",
        ));
        return None;
    }
    match semver::Version::parse(value) {
        Ok(version) => Some(version),
        Err(parse_error) => {
            findings.push(rule_finding(
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::InvalidVersionRange,
                path,
                format!("invalid semantic version: {parse_error}"),
            ));
            None
        }
    }
}
fn check_patterns<S: AsRef<str>>(
    index: usize,
    rule: &PolicyRule,
    field: &str,
    patterns: impl Iterator<Item = S>,
    findings: &mut Findings,
) {
    for pattern in patterns {
        if findings.is_saturated() {
            return;
        }
        let pattern = pattern.as_ref();
        let regex = format!("^{}$", regex::escape(pattern).replace(r"\*", ".*"));
        if regex::RegexBuilder::new(&regex).case_insensitive(true).build().is_err() {
            findings.push(rule_finding(
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::InvalidWildcardPattern,
                format!("/Rules/{index}/{field}"),
                "wildcard pattern is too complex to evaluate",
            ));
        }
    }
}
fn check_sensitive_options(index: usize, rule: &PolicyRule, findings: &mut Findings) {
    if !rule.enabled || rule.decision != Decision::Allow {
        return;
    }
    let defaults = PolicyConstraints::default();
    let constraints = rule.constraints.as_ref().unwrap_or(&defaults);
    let matches: &PolicyMatch = &rule.match_criteria;
    let reachable = |values: &BTreeSet<bool>| values.is_empty() || values.contains(&true);
    let options = [
        (
            constraints.allow_skip_hash_check && reachable(&matches.skip_hash_check),
            "SkipHashCheck",
        ),
        (
            constraints.allow_pre_release && reachable(&matches.pre_release),
            "PreRelease",
        ),
        (
            constraints.allow_custom_install_location && reachable(&matches.has_custom_install_location),
            "AllowCustomInstallLocation",
        ),
        (
            constraints.allow_pre_post_commands && reachable(&matches.has_pre_post_commands),
            "AllowPrePostCommands",
        ),
        (
            constraints.allow_kill_before_operation && reachable(&matches.has_kill_before_operation),
            "AllowKillBeforeOperation",
        ),
        (
            constraints.allow_uninstall_previous && reachable(&matches.has_uninstall_previous),
            "AllowUninstallPrevious",
        ),
        (
            constraints.allow_custom_parameters
                && reachable(&matches.has_custom_parameters)
                && !constraints
                    .denied_custom_parameters
                    .iter()
                    .take(128)
                    .any(|pattern| pattern.as_ref() == "*"),
            "AllowCustomParameters",
        ),
    ];
    for (enabled, option) in options {
        if findings.is_saturated() {
            return;
        }
        if enabled {
            let path = if rule.constraints.is_some() {
                format!("/Rules/{index}/Constraints/{option}")
            } else {
                format!("/Rules/{index}")
            };
            let mut finding = rule_finding(
                rule,
                PolicyFindingSeverity::Warning,
                PolicyFindingCode::SensitiveOptionAllowed,
                path,
                format!("rule '{}' allows {option}", rule.id),
            );
            finding
                .arguments
                .insert("Option".to_owned(), serde_json::Value::from(option));
            findings.push(finding);
        }
    }
}
fn check_string_len(value: &str, min: usize, max: usize, path: &str, findings: &mut Findings) {
    let length = value.chars().count();
    if !(min..=max).contains(&length) {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            path,
            format!("{path} must contain between {min} and {max} characters"),
        ));
    }
}
fn check_max_len(len: usize, max: usize, path: &str, findings: &mut Findings) {
    if len > max {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            path,
            format!("{path} has {len} entries, exceeding the maximum of {max}"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    fn draft() -> serde_json::Value {
        json!({
            "$schema": now_policy::POLICY_DRAFT_SCHEMA_URI,
            "PolicyVersion": "1.0.0",
            "PolicyType": "PackageBrokerPolicy",
            "Metadata": { "Id": "policy-a", "Publisher": "Test" },
            "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
            "Rules": []
        })
    }
    fn rule(id: &str, match_value: serde_json::Value) -> serde_json::Value {
        json!({
            "Id": id,
            "Priority": 1,
            "Decision": "Deny",
            "Match": match_value
        })
    }
    fn has_code(result: &PolicyValidationResult, code: PolicyFindingCode) -> bool {
        result.findings.iter().any(|finding| finding.code == code)
    }
    #[test]
    fn strict_valid_draft_is_canonicalized_deterministically() {
        let raw = draft();
        let first = validate_draft(&raw);
        let second = validate_draft(&raw);
        assert!(first.is_valid);
        assert_eq!(
            serde_json::to_value(first.canonical_draft).expect("serialize canonical draft"),
            serde_json::to_value(second.canonical_draft).expect("serialize canonical draft")
        );
    }
    #[test]
    fn constants_and_unknown_fields_are_rejected() {
        for (pointer, value, code) in [
            ("/$schema", json!("wrong"), PolicyFindingCode::UnsupportedSchema),
            (
                "/PolicyType",
                json!("OtherPolicy"),
                PolicyFindingCode::UnsupportedPolicyType,
            ),
            (
                "/PolicyVersion",
                json!("2.0.0"),
                PolicyFindingCode::UnsupportedPolicyVersion,
            ),
        ] {
            let mut raw = draft();
            *raw.pointer_mut(pointer).expect("pointer exists") = value;
            assert!(has_code(&validate_draft(&raw), code));
        }
        let mut raw = draft();
        raw["Unexpected"] = json!(true);
        assert!(has_code(&validate_draft(&raw), PolicyFindingCode::UnknownField));
    }
    #[test]
    fn structural_bounds_and_duplicate_ids_are_rejected() {
        let mut raw = draft();
        raw["Metadata"]["Publisher"] = json!("x".repeat(129));
        assert!(has_code(&validate_draft(&raw), PolicyFindingCode::SchemaViolation));
        let mut raw = draft();
        raw["Rules"] = json!([
            rule("duplicate", json!({ "Managers": ["Winget"] })),
            rule("duplicate", json!({ "Managers": ["Npm"] }))
        ]);
        assert!(has_code(&validate_draft(&raw), PolicyFindingCode::DuplicateRuleId));
    }
    #[test]
    fn oversized_rules_stop_after_one_structural_finding() {
        let mut raw = draft();
        raw["Rules"] = serde_json::Value::Array(
            (0..=MAX_RULES)
                .map(|_| rule("duplicate", json!({ "Managers": ["Winget"] })))
                .collect(),
        );
        let started = std::time::Instant::now();
        let result = validate_draft(&raw);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(!result.is_valid);
        assert!(result.canonical_draft.is_none());
        assert!(result.validation_receipt.is_none());
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].code, PolicyFindingCode::SchemaViolation);
        assert_eq!(result.findings[0].path, "/Rules");
    }
    #[test]
    fn findings_are_capped_with_a_stable_terminal_finding() {
        let mut raw = draft();
        raw["Rules"] = serde_json::Value::Array(
            (0..64)
                .map(|index| {
                    let mut value = rule(&format!("allow-{index}"), json!({ "Managers": ["Winget"] }));
                    value["Decision"] = json!("Allow");
                    value
                })
                .collect(),
        );
        let started = std::time::Instant::now();
        let first = validate_draft(&raw);
        let second = validate_draft(&raw);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(!first.is_valid);
        assert!(first.canonical_draft.is_none());
        assert!(first.validation_receipt.is_none());
        assert_eq!(first.findings.len(), MAX_FINDINGS);
        assert_eq!(
            first.findings.last().expect("terminal finding").code,
            PolicyFindingCode::SchemaViolation
        );
        assert_eq!(
            first.findings.last().expect("terminal finding").message,
            FINDINGS_TRUNCATED_MESSAGE
        );
        assert_eq!(
            serde_json::to_value(&first.findings).expect("serialize findings"),
            serde_json::to_value(&second.findings).expect("serialize findings")
        );
    }
    #[test]
    fn oversized_pattern_collections_have_bounded_ordered_findings() {
        let mut raw = draft();
        let sources: Vec<_> = (0..2048).map(|index| json!(format!("source-{index}"))).collect();
        let packages: Vec<_> = (0..2048).map(|index| json!(format!("package-{index}"))).collect();
        raw["Rules"] = json!([rule(
            "oversized",
            json!({ "Sources": sources, "PackageIdentifiers": packages })
        )]);
        let result = validate_draft(&raw);
        assert!(!result.is_valid);
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].path, "/Rules/0/Match/Sources");
        assert_eq!(result.findings[1].path, "/Rules/0/Match/PackageIdentifiers");
    }
    #[test]
    fn every_schema_array_bound_is_rejected_before_typed_parsing() {
        let collections = MATCH_COLLECTION_MAXIMA
            .iter()
            .map(|&(field, max)| ("Match", field, max))
            .chain(BOOLEAN_MATCH_FIELDS.iter().map(|&field| ("Match", field, 1)))
            .chain(
                CONSTRAINT_COLLECTION_MAXIMA
                    .iter()
                    .map(|&(field, max)| ("Constraints", field, max)),
            );
        for (section, field, max) in collections {
            let mut raw = draft();
            let mut value = rule("bounded", json!({ "Managers": ["Winget"] }));
            value[section][field] = serde_json::Value::Array(vec![json!(false); max + 1]);
            raw["Rules"] = json!([value]);
            let result = validate_draft(&raw);
            assert!(!result.is_valid, "{section}/{field}");
            assert!(result.canonical_draft.is_none(), "{section}/{field}");
            assert!(result.validation_receipt.is_none(), "{section}/{field}");
            assert_eq!(result.findings.len(), 1, "{section}/{field}");
            assert_eq!(result.findings[0].path, format!("/Rules/0/{section}/{field}"));
        }
    }

    #[test]
    fn large_boolean_arrays_are_rejected_quickly_and_deterministically() {
        let oversized = serde_json::Value::Array(vec![json!(true); 125_000]);
        let mut match_value = serde_json::Map::new();
        for field in BOOLEAN_MATCH_FIELDS {
            match_value.insert((*field).to_owned(), oversized.clone());
        }
        let mut raw = draft();
        raw["Rules"] = json!([rule("booleans", match_value.into())]);
        let started = std::time::Instant::now();
        let first = validate_draft(&raw);
        let second = validate_draft(&raw);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(!first.is_valid && first.canonical_draft.is_none() && first.validation_receipt.is_none());
        assert_eq!(first.findings.len(), BOOLEAN_MATCH_FIELDS.len());
        assert_eq!(
            serde_json::to_value(first.findings).expect("serialize findings"),
            serde_json::to_value(second.findings).expect("serialize findings")
        );
    }

    #[test]
    fn ineffective_boolean_matches_and_unsupported_criteria_are_rejected() {
        let mut raw = draft();
        raw["Rules"] = json!([rule("r1", json!({ "Interactive": [false, true] }))]);
        assert!(has_code(
            &validate_draft(&raw),
            PolicyFindingCode::IneffectiveBooleanMatch
        ));
        raw["Rules"] = json!([rule("r1", json!({ "PackageNames": ["Display Name"] }))]);
        assert!(has_code(&validate_draft(&raw), PolicyFindingCode::InvalidFieldValue));
    }

    #[test]
    fn invalid_ranges_validity_and_contradictions_are_rejected() {
        let mut raw = draft();
        raw["Rules"] = json!([rule(
            "r1",
            json!({ "VersionRange": { "MinVersion": "2.0.0", "MaxVersion": "1.0.0" } })
        )]);
        assert!(has_code(&validate_draft(&raw), PolicyFindingCode::EmptyVersionRange));
        let mut raw = draft();
        raw["Metadata"]["ValidFrom"] = json!("2026-02-01T00:00:00Z");
        raw["Metadata"]["ValidUntil"] = json!("2026-01-01T00:00:00Z");
        assert!(has_code(
            &validate_draft(&raw),
            PolicyFindingCode::InvalidValidityInterval
        ));
        let mut raw = draft();
        let mut contradictory = rule("r1", json!({ "Interactive": [true] }));
        contradictory["Constraints"] = json!({ "AllowInteractive": false });
        raw["Rules"] = json!([contradictory]);
        assert!(has_code(
            &validate_draft(&raw),
            PolicyFindingCode::ContradictoryConstraints
        ));
    }

    #[test]
    fn risky_postures_produce_ordered_warnings() {
        let mut raw = draft();
        raw["Enforcement"]["AuditMode"] = json!(true);
        raw["Enforcement"]["DefaultDecision"] = json!("Allow");
        let mut allow = rule("allow", json!({ "Managers": ["Winget"] }));
        allow["Decision"] = json!("Allow");
        raw["Rules"] = json!([allow]);
        let result = validate_draft(&raw);
        assert!(result.is_valid);
        assert_eq!(result.findings[0].code, PolicyFindingCode::AuditModeEnabled);
        assert_eq!(result.findings[1].code, PolicyFindingCode::DefaultAllow);
        assert!(has_code(&result, PolicyFindingCode::SensitiveOptionAllowed));
    }

    #[test]
    fn disk_diagnostics_are_sanitized_and_bounded() {
        let finding = disk_failure_finding(DiskFailureReason::MalformedContent);
        assert_eq!(finding.code, PolicyFindingCode::SchemaViolation);
        assert!(!finding.message.contains("secret"));
        assert!(finding.message.chars().count() <= MAX_FINDING_MESSAGE_CHARS);
    }
}
