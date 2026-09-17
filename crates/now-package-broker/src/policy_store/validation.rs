//! Strict deterministic validation for editable policy documents.

use std::collections::{BTreeMap, HashMap, HashSet};

use now_policy::{
    Decision, PackageIdentifierCondition, PolicyConstraints, PolicyDraftDocument, PolicyDraftMetadata, PolicyMatch,
    PolicyRule, VersionCondition,
};
use now_policy_api::{
    API_VERSION_STR, PolicyFinding, PolicyFindingCode, PolicyFindingSeverity, PolicyValidationResult,
};

pub(super) const VALIDATOR_VERSION: &str = "now-package-broker-policy-validator/10";
const MAX_RULES: usize = 1024;
const MAX_RULE_PRIORITY: u32 = i32::MAX as u32;
const MAX_FINDING_MESSAGE_CHARS: usize = 2048;
const MAX_FINDINGS: usize = 128;
const MATCH_COLLECTION_MAXIMA: &[(&str, usize)] = &[
    ("Operations", 3),
    ("Managers", 16),
    ("SourceNames", 128),
    ("Scopes", 2),
    ("Architectures", 5),
    ("ExecutionElevation", 2),
];
const CONSTRAINT_COLLECTION_MAXIMA: &[(&str, usize)] = &[
    ("AllowedInstallLocationPatterns", 64),
    ("AllowedCustomParameters", 128),
    ("AllowedCustomParameterPatterns", 128),
    ("DeniedCustomParameters", 128),
];

struct Findings {
    values: Vec<PolicyFinding>,
    has_error: bool,
}

impl Findings {
    fn new() -> Self {
        Self {
            values: Vec::with_capacity(MAX_FINDINGS),
            has_error: false,
        }
    }

    fn push(&mut self, finding: PolicyFinding) {
        let is_error = finding.severity == PolicyFindingSeverity::Error;
        self.has_error |= is_error;
        if self.values.len() < MAX_FINDINGS {
            self.values.push(finding);
        } else if is_error
            && !self
                .values
                .iter()
                .any(|existing| existing.severity == PolicyFindingSeverity::Error)
        {
            self.values[MAX_FINDINGS - 1] = finding;
        }
    }

    fn is_saturated(&self) -> bool {
        self.values.len() == MAX_FINDINGS
    }
}

pub(super) fn validate_draft(raw: &serde_json::Value) -> PolicyValidationResult {
    let mut findings = Findings::new();
    if !raw.is_object() {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            "",
            "the policy draft must be a JSON object",
        ));
        return invalid_result(findings);
    }
    check_policy_format_version(raw, &mut findings);
    check_raw_validity_interval(raw, &mut findings);
    if has_error(&findings) || check_raw_collection_bounds(raw, &mut findings) {
        return invalid_result(findings);
    }

    match serde_json::from_value::<PolicyDraftDocument>(raw.clone()) {
        Ok(draft) => {
            semantic_checks(raw, &draft, &mut findings);
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

pub(super) fn validate_committed_policy(policy: &now_policy::PolicyDocument) -> PolicyValidationResult {
    let raw = serde_json::to_value(policy.to_draft()).expect("committed policy draft serializes");
    validate_draft(&raw)
}

fn has_error(findings: &Findings) -> bool {
    findings.has_error
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

fn check_policy_format_version(raw: &serde_json::Value, findings: &mut Findings) {
    const PATH: &str = "/PolicyFormatVersion";
    match raw.get("PolicyFormatVersion") {
        None => findings.push(error(
            PolicyFindingCode::MissingRequiredField,
            PATH,
            "missing required field 'PolicyFormatVersion'",
        )),
        Some(serde_json::Value::String(value)) if value.len() > 128 => findings.push(error(
            PolicyFindingCode::InvalidFieldValue,
            PATH,
            "PolicyFormatVersion exceeds the maximum length of 128",
        )),
        Some(serde_json::Value::String(value)) => match semver::Version::parse(value) {
            Ok(version) if version.major == 1 => {}
            Ok(version) => findings.push(error(
                PolicyFindingCode::UnsupportedPolicyFormatVersion,
                PATH,
                format!(
                    "unsupported PolicyFormatVersion major '{}'; expected 1.x",
                    version.major
                ),
            )),
            Err(parse_error) => findings.push(error(
                PolicyFindingCode::InvalidFieldValue,
                PATH,
                format!("PolicyFormatVersion is not a valid semantic version: {parse_error}"),
            )),
        },
        Some(_) => findings.push(error(
            PolicyFindingCode::InvalidFieldType,
            PATH,
            "'PolicyFormatVersion' must be a string",
        )),
    }
}

pub(crate) fn classify_parse_error(parse_error: &serde_json::Error) -> PolicyFinding {
    let message = parse_error.to_string();
    let code = if message.contains("missing field") {
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
                check_raw_set_array(matches, field, max, &format!("{base}/Match/{field}"), findings);
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

fn check_raw_set_array(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    max: usize,
    path: &str,
    findings: &mut Findings,
) {
    let Some(values) = object.get(field).and_then(serde_json::Value::as_array) else {
        return;
    };
    check_max_len(values.len(), max, path, findings);
    if values.len() > max {
        return;
    }
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_str() else {
            return;
        };
        if !seen.insert(value) {
            findings.push(error(
                PolicyFindingCode::SchemaViolation,
                path,
                format!("{path} contains duplicate value '{value}'"),
            ));
            return;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

fn semantic_checks(raw: &serde_json::Value, draft: &PolicyDraftDocument, findings: &mut Findings) {
    check_metadata(&draft.metadata, findings);
    check_duplicate_rule_ids(&draft.rules, findings);
    for (index, rule) in draft.rules.iter().enumerate() {
        if findings.is_saturated() {
            return;
        }
        check_rule(index, rule, findings);
    }
    if has_error(findings) {
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
        check_sensitive_options(raw, index, rule, findings);
    }
}

fn check_metadata(metadata: &PolicyDraftMetadata, findings: &mut Findings) {
    check_string_len(&metadata.publisher, 1, 128, "/Metadata/Publisher", findings);
    if let Some(description) = &metadata.description {
        check_string_len(description, 0, 512, "/Metadata/Description", findings);
    }
}

fn check_raw_validity_interval(raw: &serde_json::Value, findings: &mut Findings) {
    let Some(metadata) = raw.get("Metadata").and_then(serde_json::Value::as_object) else {
        return;
    };
    let parse = |field| {
        metadata
            .get(field)
            .and_then(serde_json::Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
    };
    if let (Some(valid_from), Some(valid_until)) = (parse("ValidFrom"), parse("ValidUntil"))
        && valid_from >= valid_until
    {
        findings.push(error(
            PolicyFindingCode::InvalidValidityInterval,
            "/Metadata/ValidUntil",
            "ValidUntil must be after ValidFrom",
        ));
    }
}

fn check_duplicate_rule_ids(rules: &[PolicyRule], findings: &mut Findings) {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for (index, rule) in rules.iter().enumerate() {
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
    if let Some(PackageIdentifierCondition::Patterns(patterns)) = &rule.match_criteria.package_identifiers {
        check_patterns(
            index,
            rule,
            "Match/PackageIdentifiers/Patterns",
            patterns.iter().map(AsRef::as_ref),
            findings,
        );
    }
    if let Some(VersionCondition::Range(range)) = &rule.match_criteria.version {
        check_version_range(index, rule, range, findings);
    }
    if let Some(constraints) = &rule.constraints {
        check_constraints(index, rule, constraints, findings);
    }
}

fn check_constraints(index: usize, rule: &PolicyRule, constraints: &PolicyConstraints, findings: &mut Findings) {
    let base = format!("/Rules/{index}/Constraints");
    check_patterns(
        index,
        rule,
        "Constraints/AllowedInstallLocationPatterns",
        constraints.allowed_install_location_patterns.iter().map(AsRef::as_ref),
        findings,
    );
    check_patterns(
        index,
        rule,
        "Constraints/AllowedCustomParameterPatterns",
        constraints.allowed_custom_parameter_patterns.iter().map(AsRef::as_ref),
        findings,
    );
    for (value, allowed, name) in [
        (
            rule.match_criteria.interactive,
            constraints.allow_interactive,
            "Interactive",
        ),
        (
            rule.match_criteria.skip_hash_check,
            constraints.allow_skip_hash_check,
            "SkipHashCheck",
        ),
        (
            rule.match_criteria.pre_release,
            constraints.allow_pre_release,
            "PreRelease",
        ),
        (
            rule.match_criteria.has_custom_install_location,
            constraints.allow_custom_install_location,
            "HasCustomInstallLocation",
        ),
        (
            rule.match_criteria.has_custom_parameters,
            constraints.allow_custom_parameters,
            "HasCustomParameters",
        ),
        (
            rule.match_criteria.has_pre_post_commands,
            constraints.allow_pre_post_commands,
            "HasPrePostCommands",
        ),
        (
            rule.match_criteria.has_kill_before_operation,
            constraints.allow_kill_before_operation,
            "HasKillBeforeOperation",
        ),
        (
            rule.match_criteria.has_uninstall_previous,
            constraints.allow_uninstall_previous,
            "HasUninstallPrevious",
        ),
    ] {
        if value == Some(true) && !allowed {
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

fn check_version_range(index: usize, rule: &PolicyRule, range: &now_policy::VersionRange, findings: &mut Findings) {
    let base = format!("/Rules/{index}/Match/Version/Range");
    let min = range
        .min_version
        .as_ref()
        .and_then(|version| semver::Version::parse(version).ok());
    let max = range
        .max_version
        .as_ref()
        .and_then(|version| semver::Version::parse(version).ok());
    if let (Some(min), Some(max)) = (min.as_ref(), max.as_ref())
        && min > max
    {
        findings.push(rule_finding(
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::EmptyVersionRange,
            &base,
            "MinVersion is greater than MaxVersion",
        ));
    } else if !range.include_prerelease
        && let Some(max) = max
        && let Some(mut first_stable) =
            min.or_else(|| range.min_version.is_none().then(|| semver::Version::new(0, 0, 0)))
    {
        first_stable.pre = semver::Prerelease::EMPTY;
        first_stable.build = semver::BuildMetadata::EMPTY;
        if max < first_stable {
            findings.push(rule_finding(
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::EmptyVersionRange,
                &base,
                "version range contains no stable version",
            ));
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
        let regex = format!("^{}$", regex::escape(pattern.as_ref()).replace(r"\*", ".*"));
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

fn check_sensitive_options(raw: &serde_json::Value, index: usize, rule: &PolicyRule, findings: &mut Findings) {
    if !rule.enabled || rule.decision != Decision::Allow {
        return;
    }
    let defaults = PolicyConstraints::default();
    let constraints = rule.constraints.as_ref().unwrap_or(&defaults);
    let matches: &PolicyMatch = &rule.match_criteria;
    let reachable = |value: Option<bool>| value != Some(false);
    let options = [
        (
            constraints.allow_skip_hash_check && reachable(matches.skip_hash_check),
            "SkipHashCheck",
            "SkipHashCheck",
            "AllowSkipHashCheck",
        ),
        (
            constraints.allow_pre_release && reachable(matches.pre_release),
            "PreRelease",
            "PreRelease",
            "AllowPreRelease",
        ),
        (
            constraints.allow_custom_install_location && reachable(matches.has_custom_install_location),
            "AllowCustomInstallLocation",
            "HasCustomInstallLocation",
            "AllowCustomInstallLocation",
        ),
        (
            constraints.allow_pre_post_commands && reachable(matches.has_pre_post_commands),
            "AllowPrePostCommands",
            "HasPrePostCommands",
            "AllowPrePostCommands",
        ),
        (
            constraints.allow_kill_before_operation && reachable(matches.has_kill_before_operation),
            "AllowKillBeforeOperation",
            "HasKillBeforeOperation",
            "AllowKillBeforeOperation",
        ),
        (
            constraints.allow_uninstall_previous && reachable(matches.has_uninstall_previous),
            "AllowUninstallPrevious",
            "HasUninstallPrevious",
            "AllowUninstallPrevious",
        ),
        (
            constraints.allow_custom_parameters
                && reachable(matches.has_custom_parameters)
                && !constraints
                    .denied_custom_parameters
                    .iter()
                    .any(|pattern| pattern.as_ref() == "*"),
            "AllowCustomParameters",
            "HasCustomParameters",
            "AllowCustomParameters",
        ),
    ];
    for (enabled, option, match_field, constraint_field) in options {
        if enabled {
            let rule_path = format!("/Rules/{index}");
            let match_path = format!("{rule_path}/Match/{match_field}");
            let constraint_path = format!("{rule_path}/Constraints/{constraint_field}");
            let path = if raw.pointer(&match_path).is_some() {
                match_path
            } else if raw.pointer(&constraint_path).is_some() {
                constraint_path
            } else {
                rule_path
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
                .insert("option".to_owned(), serde_json::Value::from(option));
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
            "PolicyFormatVersion": "1.0.0",
            "Metadata": { "Id": "policy-a", "Publisher": "Test" },
            "Enforcement": { "DefaultDecision": "Deny" },
            "Rules": []
        })
    }

    fn rule(id: &str, match_value: serde_json::Value) -> serde_json::Value {
        json!({ "Id": id, "Priority": 1, "Decision": "Deny", "Match": match_value })
    }

    #[test]
    fn final_contract_is_canonical_and_uses_scalar_booleans() {
        let mut raw = draft();
        raw["Rules"] = json!([rule(
            "allow",
            json!({
                "Managers": ["Winget"],
                "SourceNames": ["winget"],
                "PackageIdentifiers": { "Exact": ["Microsoft.PowerToys"] },
                "Interactive": false
            })
        )]);
        let result = validate_draft(&raw);
        assert!(result.is_valid);
        let canonical =
            serde_json::to_value(result.canonical_draft.expect("canonical draft")).expect("serialize draft");
        assert_eq!(canonical.pointer("/Rules/0/Match/Interactive"), Some(&json!(false)));
    }

    #[test]
    fn shared_contract_rejects_invalid_rule_shapes() {
        let cases = [
            json!({ "SourceNames": ["winget"] }),
            json!({ "Managers": ["Winget"], "Interactive": [true] }),
            json!({ "Managers": ["Winget"], "PackageIdentifiers": { "Exact": [] } }),
        ];
        for match_value in cases {
            let mut raw = draft();
            raw["Rules"] = json!([rule("rule", match_value)]);
            assert!(!validate_draft(&raw).is_valid);
        }
        let mut deny_with_constraints = rule("rule", json!({ "Managers": ["Winget"] }));
        deny_with_constraints["Constraints"] = json!({ "AllowInteractive": false });
        let mut raw = draft();
        raw["Rules"] = json!([deny_with_constraints]);
        assert!(!validate_draft(&raw).is_valid);
    }

    #[test]
    fn validity_window_must_be_strictly_increasing() {
        let mut raw = draft();
        raw["Metadata"]["ValidFrom"] = json!("2026-01-01T00:00:00Z");
        raw["Metadata"]["ValidUntil"] = json!("2026-01-01T00:00:00Z");
        let result = validate_draft(&raw);
        assert!(!result.is_valid);
        assert_eq!(result.findings[0].code, PolicyFindingCode::InvalidValidityInterval);
        assert_eq!(result.findings[0].path, "/Metadata/ValidUntil");
    }

    #[test]
    fn version_range_must_contain_a_stable_version_without_prerelease_opt_in() {
        let mut raw = draft();
        raw["Rules"] = json!([rule(
            "rule",
            json!({
                "Managers": ["Winget"],
                "Version": {
                    "Range": {
                        "MinVersion": "1.0.0-alpha",
                        "MaxVersion": "1.0.0-beta",
                        "IncludePrerelease": false
                    }
                }
            }),
        )]);
        let result = validate_draft(&raw);
        assert!(!result.is_valid);
        assert_eq!(result.findings[0].code, PolicyFindingCode::EmptyVersionRange);
        assert_eq!(result.findings[0].path, "/Rules/0/Match/Version/Range");
    }

    #[test]
    fn metadata_schema_bounds_are_enforced() {
        for (pointer, value) in [
            ("/Metadata/Publisher", json!("")),
            ("/Metadata/Publisher", json!("x".repeat(129))),
            ("/Metadata/Description", json!("x".repeat(513))),
        ] {
            let mut raw = draft();
            if pointer == "/Metadata/Description" {
                raw["Metadata"]["Description"] = value;
            } else {
                raw["Metadata"]["Publisher"] = value;
            }
            assert!(!validate_draft(&raw).is_valid, "{pointer} must be rejected");
        }
    }

    #[test]
    fn empty_match_collections_are_omitted_from_canonical_drafts() {
        let mut raw = draft();
        raw["Rules"] = json!([rule("rule", json!({ "Managers": ["Winget"], "Scopes": [] }))]);
        let result = validate_draft(&raw);
        assert!(result.is_valid);
        let canonical =
            serde_json::to_value(result.canonical_draft.expect("canonical draft")).expect("serialize draft");
        assert!(canonical.pointer("/Rules/0/Match/Scopes").is_none());
    }

    #[test]
    fn null_boolean_criteria_are_absent_in_canonical_drafts() {
        let mut raw = draft();
        raw["Rules"] = json!([rule("rule", json!({ "Managers": ["Winget"], "Interactive": null }))]);
        let result = validate_draft(&raw);
        assert!(result.is_valid);
        let canonical =
            serde_json::to_value(result.canonical_draft.expect("canonical draft")).expect("serialize draft");
        assert!(canonical.pointer("/Rules/0/Match/Interactive").is_none());
    }
}
