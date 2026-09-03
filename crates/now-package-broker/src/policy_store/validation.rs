//! Authoritative, deterministic validation of raw policy draft JSON.
//!
//! Validation is strict: it never silently ignores unknown members, ineffective match
//! values, or unsupported constants. It is also authoritative: it reparses the raw JSON
//! from scratch every time rather than trusting any previously computed result, so it can
//! run identically from `POST /v1/policy/validate` and again inside the `PUT /v1/policy`
//! replacement transaction.
//!
//! Two disjoint kinds of findings are produced:
//! - Errors: the draft is rejected outright (schema/strict failures, duplicate rule ids,
//!   version-range/wildcard/validity problems, contradictory constraints, unsupported
//!   schema/type/version constants).
//! - Warnings: the draft is accepted, but flags choices worth a human's attention (audit
//!   mode, a default-allow posture, and specific sensitive capabilities enabled by an
//!   effective `Allow` rule). Warnings are computed per-rule from that rule's own match
//!   and constraints only; this deliberately does not attempt any cross-rule shadowing or
//!   "which rule wins" analysis.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use now_policy::{
    Decision, PolicyConstraints, PolicyDraftDocument, PolicyDraftMetadata, PolicyEnforcement, PolicyMatch, PolicyRule,
};
use now_policy_api::{
    API_VERSION_STR, PolicyFinding, PolicyFindingCode, PolicyFindingSeverity, PolicyValidationResult,
};

use crate::evaluator::wildcard::pattern_compiles;

/// Identifies the logic that produced a [`PolicyValidationResult`], bound into every
/// validation receipt. Bump this whenever validation semantics change, so a receipt
/// computed by an older/newer broker can never be mistaken for a match against the
/// current logic.
pub const VALIDATOR_VERSION: &str = "now-package-broker-policy-validator/2";

/// Maximum number of rules accepted in a single policy, mirroring the shared contract's
/// documented schema bound (`schemars(length(max = 1024))` on `PolicyDraftDocument::rules`),
/// which is not itself enforced at deserialization time.
const MAX_RULES: usize = 1024;

/// Authoritatively validate raw draft JSON.
///
/// Never panics on attacker/administrator-controlled input; parsing and structural
/// failures are reported as findings rather than propagated as Rust errors.
///
/// This is the keyless, deterministic half of validation: `validation_receipt` is always
/// `None`, even for a valid result. Binding a receipt requires a process-random key that
/// only `PolicyStore` holds; API callers reach this function through
/// `PolicyStore::validate_draft`, never directly, so `POST /v1/policy/validate` and the
/// `PUT /v1/policy` replacement transaction always bind against the exact same key.
pub fn validate_draft(raw: &serde_json::Value) -> PolicyValidationResult {
    let mut findings = Vec::new();

    if !raw.is_object() {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            "",
            "the policy draft must be a JSON object",
        ));
        return invalid_result(findings);
    }

    // Pin the fixed-constant fields precisely before attempting the full structural
    // parse, so a mismatch is reported with its specific code (an "unsupported constant")
    // instead of a generic schema-violation message from the marker types' own strict
    // deserialization.
    check_constant_field(
        raw,
        "$schema",
        "/$schema",
        now_policy::POLICY_DRAFT_SCHEMA_URI,
        PolicyFindingCode::UnsupportedSchema,
        &mut findings,
    );
    check_constant_field(
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

/// Authoritatively (re)validate an on-disk committed [`now_policy::PolicyDocument`] the
/// same deterministic way a submitted draft is validated (item 30): duplicate rule ids,
/// out-of-bounds lengths, invalid wildcard/version/constraint/validity values, and so on
/// are never silently accepted just because the bytes happened to structurally parse
/// into the typed model. Called for every observation of the configured file (including
/// immediately after this store's own write, so a freshly persisted policy is verified
/// through the exact same path it would be re-observed through later) and, at the
/// authoritative validator-version level, is the *same* logic a submitted draft goes
/// through: a committed document can never be less scrutinized than a draft that
/// produced it.
///
/// Warnings (audit mode, default-allow, sensitive options enabled) do not affect the
/// result: [`PolicyValidationResult::is_valid`] already only reflects Error-severity
/// findings (see [`validate_draft`]), so a committed document with only warnings still
/// activates normally (Active), matching how a replacement with only warnings commits
/// once acknowledged.
///
/// Additionally requires a nonzero revision: [`PolicyDraftDocument::into_policy_document`]
/// itself rejects revision 0 when this store commits a document, so a *committed* file
/// claiming revision 0 could only be tampering or corruption, never this store's own output.
///
/// Returns the full [`PolicyValidationResult`] (including specific findings) purely for
/// the caller to trace for operator diagnosis: like [`disk_failure_finding`], the specific
/// findings for a *committed* file must never be exposed through the management API,
/// which only ever sees the generic, sanitized [`DiskFailureReason::FailedSemanticValidation`].
pub(crate) fn validate_committed_policy(policy: &now_policy::PolicyDocument) -> PolicyValidationResult {
    if policy.metadata.revision == 0 {
        return invalid_result(vec![error(
            PolicyFindingCode::SchemaViolation,
            "/Metadata/Revision",
            "committed policy revision must be at least 1",
        )]);
    }

    let draft = policy.to_draft();
    let raw = serde_json::to_value(&draft).expect("BUG: a committed PolicyDocument's derived draft always serializes");
    validate_draft(&raw)
}

fn has_error(findings: &[PolicyFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == PolicyFindingSeverity::Error)
}

fn invalid_result(findings: Vec<PolicyFinding>) -> PolicyValidationResult {
    PolicyValidationResult {
        result_version: API_VERSION_STR.into(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        is_valid: false,
        canonical_draft: None,
        validation_receipt: None,
        findings,
    }
}

fn valid_result(draft: PolicyDraftDocument, findings: Vec<PolicyFinding>) -> PolicyValidationResult {
    PolicyValidationResult {
        result_version: API_VERSION_STR.into(),
        validator_version: VALIDATOR_VERSION.to_owned(),
        is_valid: true,
        canonical_draft: Some(draft),
        validation_receipt: None,
        findings,
    }
}

fn finding(
    severity: PolicyFindingSeverity,
    code: PolicyFindingCode,
    path: impl Into<String>,
    message: impl Into<String>,
) -> PolicyFinding {
    PolicyFinding {
        finding_version: API_VERSION_STR.into(),
        severity,
        code,
        path: path.into(),
        rule_id: None,
        arguments: BTreeMap::new(),
        message: message.into(),
    }
}

fn error(code: PolicyFindingCode, path: impl Into<String>, message: impl Into<String>) -> PolicyFinding {
    finding(PolicyFindingSeverity::Error, code, path, message)
}

fn warning(code: PolicyFindingCode, path: impl Into<String>, message: impl Into<String>) -> PolicyFinding {
    finding(PolicyFindingSeverity::Warning, code, path, message)
}

fn push_rule_finding(
    findings: &mut Vec<PolicyFinding>,
    rule: &PolicyRule,
    severity: PolicyFindingSeverity,
    code: PolicyFindingCode,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    let mut f = finding(severity, code, path, message);
    f.rule_id = Some(api_resource_id(&rule.id));
    findings.push(f);
}

/// Convert a `now_policy::ResourceId` (the policy document/rule identifier type) into the
/// API crate's own distinct `ResourceId` type used by [`PolicyFinding::rule_id`].
fn api_resource_id(id: &now_policy::ResourceId) -> now_policy_api::ResourceId {
    now_policy_api::ResourceId::from(id.0.as_str())
}

// ─── Pre-parse constant checks ──────────────────────────────────────────────

fn check_constant_field(
    raw: &serde_json::Value,
    key: &str,
    path: &str,
    expected: &str,
    mismatch_code: PolicyFindingCode,
    findings: &mut Vec<PolicyFinding>,
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
            format!("unsupported value '{value}' for '{key}'; expected '{expected}'"),
        )),
        Some(_) => findings.push(error(
            PolicyFindingCode::InvalidFieldType,
            path,
            format!("'{key}' must be a string"),
        )),
    }
}

fn check_policy_version(raw: &serde_json::Value, findings: &mut Vec<PolicyFinding>) {
    const PATH: &str = "/PolicyVersion";

    match raw.get("PolicyVersion") {
        None => findings.push(error(
            PolicyFindingCode::MissingRequiredField,
            PATH,
            "missing required field 'PolicyVersion'",
        )),
        Some(serde_json::Value::String(value)) => match semver::Version::parse(value) {
            Ok(version) if version.major == 1 => {}
            Ok(version) => findings.push(error(
                PolicyFindingCode::UnsupportedPolicyVersion,
                PATH,
                format!(
                    "unsupported PolicyVersion major '{}'; this broker implements schema version 1.x",
                    version.major
                ),
            )),
            Err(parse_error) => findings.push(error(
                PolicyFindingCode::InvalidFieldValue,
                PATH,
                format!("PolicyVersion '{value}' is not a valid semantic version: {parse_error}"),
            )),
        },
        Some(_) => findings.push(error(
            PolicyFindingCode::InvalidFieldType,
            PATH,
            "'PolicyVersion' must be a string",
        )),
    }
}

/// Heuristically classify a strict-deserialization failure of the overall draft shape.
///
/// `serde_json::Error` from a `Value`-based deserialization carries no JSON-pointer path,
/// only a human-readable message; this maps that message to the closest
/// [`PolicyFindingCode`]. Semantic checks below run on the successfully typed draft and
/// therefore always produce precise, path-qualified findings — this heuristic path is
/// only reached for structural/strict-schema failures of the raw JSON itself.
///
/// Only used for a client-submitted draft (`POST /v1/policy/validate` and the `PUT
/// /v1/policy` replacement transaction): the detailed message helps the submitter fix
/// their own input, and cannot leak anything they do not already know, since it is their
/// own content. A parse failure of the *committed on-disk* document is a different trust
/// boundary and must never repeat raw parser text back through the management API to a
/// caller who did not necessarily write that file; see [`disk_failure_finding`].
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

/// Category of a disk-level failure that prevented the configured policy file from being
/// trusted, parsed, or activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiskFailureReason {
    /// The file could not be opened, its identity/security state could not be queried, or
    /// its content could not be read.
    Unreadable,
    /// The file's owner/DACL failed storage security validation.
    InsecureStorage,
    /// The file was read successfully but is not valid JSON matching the expected schema.
    MalformedContent,
    /// The configured path itself does not have a supported shape (relative, empty
    /// leaf, trailing separator, `.`/`..` component, ...) or extension (anything other
    /// than case-insensitive `.json`); see `windows::validate_configured_path_shape`.
    /// The file, if any exists at that path, is never touched.
    UnsupportedFormat,
    /// The file parsed as structurally valid JSON matching [`now_policy::PolicyDocument`],
    /// but failed the same deterministic semantic validation a submitted draft would
    /// (duplicate rule ids, out-of-bounds lengths, invalid wildcard/version/constraint/
    /// validity values, ...), or has a zero committed revision. See item 30: a committed
    /// document is never activated on structural parseability alone.
    FailedSemanticValidation,
}

/// Build a generic, sanitized diagnostic finding for a storage-level failure (I/O,
/// security, parse, or semantic-validation) that prevented the on-disk policy file from
/// being trusted or activated.
///
/// Deliberately carries none of the underlying OS/serde error text, specific validation
/// findings, or any bytes from the file itself: unlike [`classify_parse_error`], this
/// describes the *committed on-disk* document, which `GET /v1/policy/management` exposes
/// to any authenticated (but not necessarily elevated/Administrator) caller. Repeating
/// raw parser/OS error text or the specific semantic-validation findings here could leak
/// fragments of attacker- or corruption-controlled file content, or implementation/
/// filesystem detail, to a caller who may not even be the one who wrote that file. The
/// detailed error/findings are only ever traced (`tracing::warn!`) at the call site in
/// `policy_store::windows`, for operator diagnosis.
pub(crate) fn disk_failure_finding(reason: DiskFailureReason) -> PolicyFinding {
    let message = match reason {
        DiskFailureReason::Unreadable => "the configured policy file could not be opened or read",
        DiskFailureReason::InsecureStorage => {
            "the configured policy file failed storage security validation (unexpected owner or write permissions)"
        }
        DiskFailureReason::MalformedContent => {
            "the configured policy file does not contain valid JSON matching the expected policy schema"
        }
        DiskFailureReason::UnsupportedFormat => {
            "the configured policy path does not have a supported file extension; only '.json' is supported"
        }
        DiskFailureReason::FailedSemanticValidation => {
            "the configured policy file contains a policy that fails validation (see server logs for detail)"
        }
    };
    error(PolicyFindingCode::SchemaViolation, "", message)
}

// ─── Semantic checks on the successfully parsed draft ───────────────────────

fn semantic_checks(draft: &PolicyDraftDocument, findings: &mut Vec<PolicyFinding>) {
    check_metadata_bounds(&draft.metadata, findings);
    check_validity_interval(&draft.metadata, findings);
    check_duplicate_rule_ids(&draft.rules, findings);

    if draft.rules.len() > MAX_RULES {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            "/Rules",
            format!(
                "policy defines {} rules, exceeding the maximum of {MAX_RULES}",
                draft.rules.len()
            ),
        ));
    }

    for (idx, rule) in draft.rules.iter().enumerate() {
        check_version_range(idx, rule, findings);
        check_wildcard_patterns(idx, rule, findings);
        check_match_collection_bounds(idx, rule, findings);
        check_supported_match_criteria(idx, rule, findings);
        check_rule_bounds(idx, rule, findings);
        check_contradictory_constraints(idx, rule, findings);
    }

    // Warnings are computed unconditionally alongside the hard-error checks above; an
    // invalid draft's finding set may legitimately mix errors and warnings.
    check_audit_mode(&draft.enforcement, findings);
    check_default_allow(&draft.enforcement, findings);
    for (idx, rule) in draft.rules.iter().enumerate() {
        check_sensitive_options(idx, rule, findings);
    }
}

/// Enforce a plain (non-newtype-validated) human-text string field's declared bounds:
/// the shared contract documents these via `#[schemars(length(...))]`, which only
/// affects generated JSON Schema, not `serde` deserialization -- unlike e.g.
/// `ResourceId`, this field has no custom `Deserialize` impl enforcing it, so nothing
/// rejects an out-of-bounds value before it reaches here.
///
/// Counts Unicode scalar values (`chars().count()`), not UTF-8 bytes: JSON Schema's
/// `minLength`/`maxLength` (what `schemars(length(...))` generates) are defined in terms
/// of Unicode code points, and these fields (publisher, description, reason, ...) are
/// arbitrary human text with no ASCII restriction. A 128-character CJK publisher name is
/// three times that many UTF-8 bytes, so counting bytes here would reject well-formed
/// values far below their documented limit. This is deliberately distinct from the
/// shared contract's own newtypes (`ResourceId`, version/pattern strings, ...), which
/// are ASCII-constrained by their own regex and correctly count bytes for that reason;
/// see [`check_version_bound`] for one of those.
fn check_string_bounds(value: &str, min: usize, max: usize, path: &str, findings: &mut Vec<PolicyFinding>) {
    let length = value.chars().count();
    if length < min {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            path,
            format!("{path} has length {length}, below the documented minimum of {min}"),
        ));
    } else if length > max {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            path,
            format!("{path} has length {length}, exceeding the documented maximum of {max}"),
        ));
    }
}

/// Enforce a collection's declared maximum length: see [`check_string_bounds`] for why
/// this is not already covered by `serde`/`schemars`.
fn check_max_len(len: usize, max: usize, path: &str, findings: &mut Vec<PolicyFinding>) {
    if len > max {
        findings.push(error(
            PolicyFindingCode::SchemaViolation,
            path,
            format!("{path} has {len} entries, exceeding the documented maximum of {max}"),
        ));
    }
}

fn check_metadata_bounds(metadata: &PolicyDraftMetadata, findings: &mut Vec<PolicyFinding>) {
    check_string_bounds(&metadata.publisher, 1, 128, "/Metadata/Publisher", findings);
    if let Some(description) = &metadata.description {
        check_string_bounds(description, 0, 512, "/Metadata/Description", findings);
    }
}

fn check_validity_interval(metadata: &PolicyDraftMetadata, findings: &mut Vec<PolicyFinding>) {
    if let (Some(valid_from), Some(valid_until)) = (metadata.valid_from, metadata.valid_until)
        && valid_from > valid_until
    {
        findings.push(error(
            PolicyFindingCode::InvalidValidityInterval,
            "/Metadata/ValidUntil",
            format!("ValidUntil ({valid_until}) is before ValidFrom ({valid_from})"),
        ));
    }
}

fn check_duplicate_rule_ids(rules: &[PolicyRule], findings: &mut Vec<PolicyFinding>) {
    let mut seen: HashMap<&str, usize> = HashMap::new();

    for (idx, rule) in rules.iter().enumerate() {
        let id: &str = &rule.id;

        if let Some(&first_idx) = seen.get(id) {
            push_rule_finding(
                findings,
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::DuplicateRuleId,
                format!("/Rules/{idx}/Id"),
                format!("rule id '{id}' is already used by the rule at index {first_idx}"),
            );
        } else {
            seen.insert(id, idx);
        }
    }
}

/// Match-criteria collections whose declared maximum length is *not* structurally
/// guaranteed by their element type: `sources`/`package_identifiers`/`package_names` are
/// sets of an unbounded [`now_policy::StringPattern`], and `versions` a set of an
/// unbounded [`now_policy::VersionString`], so any number of distinct values can be
/// submitted regardless of the documented bound.
///
/// `operations` (max 3), `scopes` (max 2), and `elevation` (max 2) are deliberately not
/// checked here: each is a `BTreeSet` of a fully enumerated, closed enum whose own variant
/// count matches its declared schema maximum exactly, so a set of that type can
/// structurally never violate the bound. `architectures` (max 5, 4 variants) is the same,
/// with headroom to spare. `managers`, by contrast, *is* checked: it declares a maximum of
/// 16, but `now_policy::ManagerName` has 17 variants, so a set naming every manager would
/// silently exceed the documented bound without this check.
fn check_match_collection_bounds(idx: usize, rule: &PolicyRule, findings: &mut Vec<PolicyFinding>) {
    let m: &PolicyMatch = &rule.match_criteria;
    let base = format!("/Rules/{idx}/Match");
    check_max_len(m.managers.len(), 16, &format!("{base}/Managers"), findings);
    check_max_len(m.sources.len(), 128, &format!("{base}/Sources"), findings);
    check_max_len(
        m.package_identifiers.len(),
        1024,
        &format!("{base}/PackageIdentifiers"),
        findings,
    );
    check_max_len(m.package_names.len(), 1024, &format!("{base}/PackageNames"), findings);
    check_max_len(m.versions.len(), 256, &format!("{base}/Versions"), findings);
}

fn check_supported_match_criteria(idx: usize, rule: &PolicyRule, findings: &mut Vec<PolicyFinding>) {
    if !rule.match_criteria.package_names.is_empty() {
        push_rule_finding(
            findings,
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::InvalidFieldValue,
            format!("/Rules/{idx}/Match/PackageNames"),
            "PackageNames is not supported because package requests do not provide a package display name; leave this collection empty",
        );
    }
}

/// `Reason` and the `Constraints` allow/deny collections, none of which are covered by
/// `serde`/`schemars` enforcement (plain `Option<String>`/`Vec<CustomParameterString>`
/// fields with no bound-checking `Deserialize` impl of their own).
fn check_rule_bounds(idx: usize, rule: &PolicyRule, findings: &mut Vec<PolicyFinding>) {
    if let Some(reason) = &rule.reason {
        check_string_bounds(reason, 0, 512, &format!("/Rules/{idx}/Reason"), findings);
    }

    let Some(constraints) = &rule.constraints else {
        return;
    };
    let base = format!("/Rules/{idx}/Constraints");
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
}

fn check_version_range(idx: usize, rule: &PolicyRule, findings: &mut Vec<PolicyFinding>) {
    let Some(range) = &rule.match_criteria.version_range else {
        return;
    };
    let base = format!("/Rules/{idx}/Match/VersionRange");

    let min_ok = check_version_bound(
        range.min_version.as_deref(),
        &format!("{base}/MinVersion"),
        rule,
        findings,
    );
    let max_ok = check_version_bound(
        range.max_version.as_deref(),
        &format!("{base}/MaxVersion"),
        rule,
        findings,
    );

    if let (Some(min_version), Some(max_version)) = (&min_ok, &max_ok)
        && min_version > max_version
    {
        push_rule_finding(
            findings,
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::EmptyVersionRange,
            base,
            format!("MinVersion {min_version} is greater than MaxVersion {max_version}; this range can never match"),
        );
    }
}

/// Validate one `VersionRange` bound (`MinVersion`/`MaxVersion`). Enforces the shared
/// contract's documented (but, being a plain `Option<String>`, not `serde`/`schemars`-
/// enforced) nonempty/max-length bound *before* attempting a semantic-version parse, so a
/// present-but-empty or oversized value is reported precisely rather than silently
/// treated as absent (this crate's validation is strict: see the module docs). Returns
/// the parsed version on success, for the caller's min/max ordering check.
///
/// Deliberately counts UTF-8 bytes (`value.len()`), unlike [`check_string_bounds`]'s
/// Unicode scalar count: a semantic version is required to parse with [`semver::Version`],
/// whose grammar is ASCII-only, so byte and scalar counts always coincide here and this
/// mirrors the shared contract's own ASCII-constrained newtypes (e.g. `ResourceId`).
fn check_version_bound(
    value: Option<&str>,
    path: &str,
    rule: &PolicyRule,
    findings: &mut Vec<PolicyFinding>,
) -> Option<semver::Version> {
    let value = value?;

    if value.is_empty() || value.len() > 128 {
        push_rule_finding(
            findings,
            rule,
            PolicyFindingSeverity::Error,
            PolicyFindingCode::InvalidVersionRange,
            path,
            format!(
                "must be non-empty and at most 128 characters when present, got length {}",
                value.len()
            ),
        );
        return None;
    }

    match semver::Version::parse(value) {
        Ok(version) => Some(version),
        Err(parse_error) => {
            push_rule_finding(
                findings,
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::InvalidVersionRange,
                path,
                format!("'{value}' is not a valid semantic version: {parse_error}"),
            );
            None
        }
    }
}

fn check_wildcard_patterns(idx: usize, rule: &PolicyRule, findings: &mut Vec<PolicyFinding>) {
    let m = &rule.match_criteria;
    check_patterns(idx, rule, "Match/Sources", &m.sources, findings);
    check_patterns(idx, rule, "Match/PackageIdentifiers", &m.package_identifiers, findings);

    if let Some(constraints) = &rule.constraints {
        check_patterns(
            idx,
            rule,
            "Constraints/AllowedInstallLocationPatterns",
            &constraints.allowed_install_location_patterns,
            findings,
        );
        check_patterns(
            idx,
            rule,
            "Constraints/AllowedCustomParameterPatterns",
            &constraints.allowed_custom_parameter_patterns,
            findings,
        );
    }
}

/// Check every pattern in any wildcard-pattern collection (`BTreeSet` match criteria or
/// `Vec` constraint allow-lists alike) for the same compile-ability the evaluator itself
/// requires at request-evaluation time.
fn check_patterns<'a, S: AsRef<str> + 'a>(
    idx: usize,
    rule: &PolicyRule,
    field_name: &str,
    patterns: impl IntoIterator<Item = &'a S>,
    findings: &mut Vec<PolicyFinding>,
) {
    for pattern in patterns {
        if !pattern_compiles(pattern.as_ref()) {
            push_rule_finding(
                findings,
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::InvalidWildcardPattern,
                format!("/Rules/{idx}/{field_name}"),
                format!("pattern '{}' is too large or complex to evaluate", pattern.as_ref()),
            );
        }
    }
}

/// Flag a rule whose own match criteria and own constraints can never be simultaneously
/// satisfied, making the rule permanently unreachable. This only inspects a rule against
/// itself (its match vs. its own constraints), never other rules, so it is not a
/// cross-rule shadowing analysis.
fn check_contradictory_constraints(idx: usize, rule: &PolicyRule, findings: &mut Vec<PolicyFinding>) {
    if !rule.enabled {
        return;
    }
    let Some(constraints) = &rule.constraints else {
        return;
    };
    let m = &rule.match_criteria;

    let mut check = |bool_match: &BTreeSet<bool>, allow_flag: bool, option_name: &str| {
        if !allow_flag && bool_match.len() == 1 && bool_match.contains(&true) {
            push_rule_finding(
                findings,
                rule,
                PolicyFindingSeverity::Error,
                PolicyFindingCode::ContradictoryConstraints,
                format!("/Rules/{idx}/Constraints"),
                format!(
                    "rule matches only requests where {option_name}=true, but Constraints denies {option_name}; \
                     this rule can never match"
                ),
            );
        }
    };

    check(&m.interactive, constraints.allow_interactive, "Interactive");
    check(&m.skip_hash_check, constraints.allow_skip_hash_check, "SkipHashCheck");
    check(&m.pre_release, constraints.allow_pre_release, "PreRelease");
    check(
        &m.has_custom_install_location,
        constraints.allow_custom_install_location,
        "HasCustomInstallLocation",
    );
    check(
        &m.has_custom_parameters,
        constraints.allow_custom_parameters,
        "HasCustomParameters",
    );
    check(
        &m.has_pre_post_commands,
        constraints.allow_pre_post_commands,
        "HasPrePostCommands",
    );
    check(
        &m.has_kill_before_operation,
        constraints.allow_kill_before_operation,
        "HasKillBeforeOperation",
    );
    check(
        &m.has_uninstall_previous,
        constraints.allow_uninstall_previous,
        "HasUninstallPrevious",
    );
}

// ─── Warnings ────────────────────────────────────────────────────────────────

fn check_audit_mode(enforcement: &PolicyEnforcement, findings: &mut Vec<PolicyFinding>) {
    if enforcement.audit_mode == Some(true) {
        findings.push(warning(
            PolicyFindingCode::AuditModeEnabled,
            "/Enforcement/AuditMode",
            "audit mode is enabled; decisions are logged but not enforced",
        ));
    }
}

fn check_default_allow(enforcement: &PolicyEnforcement, findings: &mut Vec<PolicyFinding>) {
    if enforcement.default_decision == Decision::Allow {
        findings.push(warning(
            PolicyFindingCode::DefaultAllow,
            "/Enforcement/DefaultDecision",
            "the default decision is Allow; requests matching no rule are permitted",
        ));
    }
}

/// Emit a deterministic, per-rule warning for specifically named sensitive capabilities
/// that an enabled `Allow` rule leaves open: `SkipHashCheck`, `PreRelease`, custom install
/// location, custom parameters, pre/post operation commands, killing processes before the
/// operation, and uninstalling a previous version. `Interactive` and `AllowUpgrade` are
/// deliberately excluded: an interactive install is the ordinary case for a
/// non-elevated/user-scope request, and skipping an upgrade when one is already installed
/// is not a privilege-relevant capability.
///
/// A warning fires only when the rule's own match criteria could actually be reached by a
/// request that has the sensitive option set (the match is absent for that flag, meaning
/// it matches both `true` and `false`, or explicitly includes `true`) *and* the rule's own
/// constraints (defaulting to the fully permissive [`PolicyConstraints::default`] when
/// absent, matching evaluator semantics in `constraints_pass`) permit it. This only
/// inspects the rule against itself, never other rules or overall reachability.
///
/// For custom install location and custom parameters, any configured restriction (an
/// allow-pattern list, an exact allow-list, or a deny-list) is reported in the finding's
/// structured `arguments` rather than used to silently suppress the warning: a partial
/// restriction is still worth a human's attention, and hiding it behind silence would be
/// misleading. The one exception is a *provably* catch-all deny -- a
/// `denied_custom_parameters` entry of exactly `"*"`, which unconditionally rejects every
/// possible value regardless of any allow-list -- which suppresses the warning outright,
/// since no request carrying a custom parameter can ever be let through.
fn check_sensitive_options(idx: usize, rule: &PolicyRule, findings: &mut Vec<PolicyFinding>) {
    if !rule.enabled || rule.decision != Decision::Allow {
        return;
    }

    let default_constraints = PolicyConstraints::default();
    let constraints = rule.constraints.as_ref().unwrap_or(&default_constraints);
    let m: &PolicyMatch = &rule.match_criteria;

    let mut warn = |option_name: &str, detail: &str, arguments: Vec<(&str, serde_json::Value)>| {
        let path = match &rule.constraints {
            Some(_) => format!("/Rules/{idx}/Constraints/{option_name}"),
            None => format!("/Rules/{idx}"),
        };
        let mut f = warning(
            PolicyFindingCode::SensitiveOptionAllowed,
            path,
            format!("rule '{}' allows {option_name}: {detail}", rule.id),
        );
        f.rule_id = Some(api_resource_id(&rule.id));
        f.arguments
            .insert("Option".to_owned(), serde_json::Value::from(option_name));
        for (key, value) in arguments {
            f.arguments.insert(key.to_owned(), value);
        }
        findings.push(f);
    };

    // A rule can only ever be reached by a request whose sensitive-option value is `true`
    // if its own match either does not restrict that flag at all (matches both `true` and
    // `false`) or explicitly matches `true`.
    let reachable_when_true = |flag_match: &BTreeSet<bool>| flag_match.is_empty() || flag_match.contains(&true);

    if constraints.allow_skip_hash_check && reachable_when_true(&m.skip_hash_check) {
        warn("SkipHashCheck", "requests may skip package hash verification", vec![]);
    }
    if constraints.allow_pre_release && reachable_when_true(&m.pre_release) {
        warn(
            "PreRelease",
            "requests may install pre-release package versions",
            vec![],
        );
    }
    if constraints.allow_custom_install_location && reachable_when_true(&m.has_custom_install_location) {
        let patterns = &constraints.allowed_install_location_patterns;
        let arguments = if patterns.is_empty() {
            Vec::new()
        } else {
            vec![(
                "AllowedInstallLocationPatterns",
                serde_json::Value::from(patterns.iter().map(|p| p.as_ref().to_owned()).collect::<Vec<_>>()),
            )]
        };
        warn(
            "AllowCustomInstallLocation",
            "requests may install to a custom location",
            arguments,
        );
    }
    if constraints.allow_pre_post_commands && reachable_when_true(&m.has_pre_post_commands) {
        warn(
            "AllowPrePostCommands",
            "requests may run arbitrary pre/post operation commands",
            vec![],
        );
    }
    if constraints.allow_kill_before_operation && reachable_when_true(&m.has_kill_before_operation) {
        warn(
            "AllowKillBeforeOperation",
            "requests may terminate arbitrary processes before the operation runs",
            vec![],
        );
    }
    if constraints.allow_uninstall_previous && reachable_when_true(&m.has_uninstall_previous) {
        warn(
            "AllowUninstallPrevious",
            "requests may uninstall a previously installed version before installing an update",
            vec![],
        );
    }
    if constraints.allow_custom_parameters
        && reachable_when_true(&m.has_custom_parameters)
        && !denies_every_custom_parameter(constraints)
    {
        let mut arguments = Vec::new();
        if !constraints.allowed_custom_parameters.is_empty() {
            arguments.push((
                "AllowedCustomParameters",
                serde_json::Value::from(
                    constraints
                        .allowed_custom_parameters
                        .iter()
                        .map(|p| p.as_ref().to_owned())
                        .collect::<Vec<_>>(),
                ),
            ));
        }
        if !constraints.allowed_custom_parameter_patterns.is_empty() {
            arguments.push((
                "AllowedCustomParameterPatterns",
                serde_json::Value::from(
                    constraints
                        .allowed_custom_parameter_patterns
                        .iter()
                        .map(|p| p.as_ref().to_owned())
                        .collect::<Vec<_>>(),
                ),
            ));
        }
        if !constraints.denied_custom_parameters.is_empty() {
            arguments.push((
                "DeniedCustomParameters",
                serde_json::Value::from(
                    constraints
                        .denied_custom_parameters
                        .iter()
                        .map(|p| p.as_ref().to_owned())
                        .collect::<Vec<_>>(),
                ),
            ));
        }
        warn(
            "AllowCustomParameters",
            "requests may pass custom parameters",
            arguments,
        );
    }
}

/// Whether `constraints.denied_custom_parameters` provably rejects every possible custom
/// parameter value, regardless of any allow-list: an exact `"*"` entry. This is
/// deliberately narrow (only the single literal universal pattern, not a general
/// subsumption analysis of arbitrary glob patterns), so it only ever suppresses a warning
/// when doing so is certain to be safe.
fn denies_every_custom_parameter(constraints: &PolicyConstraints) -> bool {
    constraints
        .denied_custom_parameters
        .iter()
        .any(|pattern| pattern.as_ref() == "*")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;

    fn minimal_draft() -> serde_json::Value {
        json!({
            "$schema": now_policy::POLICY_DRAFT_SCHEMA_URI,
            "PolicyVersion": "1.0.0",
            "PolicyType": "PackageBrokerPolicy",
            "Metadata": { "Id": "test-policy", "Publisher": "Test" },
            "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
            "Rules": [],
        })
    }

    #[test]
    fn minimal_draft_is_valid_with_no_findings() {
        let result = validate_draft(&minimal_draft());
        assert!(result.is_valid);
        assert!(result.canonical_draft.is_some());
        // `validate_draft` is the keyless half of validation; binding a receipt requires
        // `PolicyStore`'s process-random key (see `PolicyStore::validate_draft`).
        assert!(result.validation_receipt.is_none());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn non_object_draft_is_a_schema_violation() {
        let result = validate_draft(&json!("not an object"));
        assert!(!result.is_valid);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].code, PolicyFindingCode::SchemaViolation);
    }

    #[test]
    fn committed_schema_uri_is_rejected_for_a_draft() {
        let mut draft = minimal_draft();
        draft["$schema"] = json!(now_policy::POLICY_SCHEMA_URI);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::UnsupportedSchema && f.path == "/$schema")
        );
    }

    #[test]
    fn wrong_policy_type_constant_is_reported_precisely() {
        let mut draft = minimal_draft();
        draft["PolicyType"] = json!("SomethingElse");
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::UnsupportedPolicyType)
        );
    }

    #[test]
    fn unsupported_policy_version_major_is_reported() {
        let mut draft = minimal_draft();
        draft["PolicyVersion"] = json!("2.0.0");
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::UnsupportedPolicyVersion)
        );
    }

    #[test]
    fn missing_required_field_is_reported() {
        let mut draft = minimal_draft();
        draft.as_object_mut().unwrap().remove("Metadata");
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::MissingRequiredField)
        );
    }

    #[test]
    fn unknown_field_is_reported() {
        let mut draft = minimal_draft();
        draft["UnexpectedField"] = json!(true);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::UnknownField)
        );
    }

    fn rule(id: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut base = json!({
            "Id": id,
            "Enabled": true,
            "Priority": 100,
            "Decision": "Allow",
            "Match": { "Managers": ["Winget"] },
        });
        for (key, value) in extra.as_object().into_iter().flatten() {
            base[key] = value.clone();
        }
        base
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule("dup", json!({})), rule("dup", json!({}))]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::DuplicateRuleId && f.path == "/Rules/1/Id")
        );
    }

    #[test]
    fn empty_version_range_is_rejected() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Match": { "Managers": ["Winget"], "VersionRange": { "MinVersion": "2.0.0", "MaxVersion": "1.0.0" } } })
        )]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::EmptyVersionRange)
        );
    }

    #[test]
    fn invalid_version_range_bound_is_rejected() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Match": { "Managers": ["Winget"], "VersionRange": { "MinVersion": "not-a-version" } } })
        )]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::InvalidVersionRange)
        );
    }

    #[test]
    fn empty_version_bound_is_rejected_rather_than_silently_ignored() {
        // `VersionRange` fields are documented as non-empty-when-present
        // (`schemars(length(min = 1))`), but being plain `Option<String>` this is not
        // itself enforced by serde/schemars; validation must not silently treat an empty
        // string the same as an absent field (see the module docs: validation is strict).
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Match": { "Managers": ["Winget"], "VersionRange": { "MinVersion": "" } } })
        )]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::InvalidVersionRange)
        );
    }

    #[test]
    fn oversized_version_bound_is_rejected() {
        let mut draft = minimal_draft();
        let mut oversized = "1.".to_owned();
        oversized.push_str(&"0".repeat(200));
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Match": { "Managers": ["Winget"], "VersionRange": { "MinVersion": oversized } } })
        )]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::InvalidVersionRange)
        );
    }

    #[test]
    fn publisher_below_minimum_length_is_rejected() {
        let mut draft = minimal_draft();
        draft["Metadata"]["Publisher"] = json!("");
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Metadata/Publisher")
        );
    }

    #[test]
    fn publisher_over_maximum_length_is_rejected() {
        let mut draft = minimal_draft();
        draft["Metadata"]["Publisher"] = json!("x".repeat(129));
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Metadata/Publisher")
        );
    }

    #[test]
    fn publisher_at_maximum_length_is_accepted() {
        let mut draft = minimal_draft();
        draft["Metadata"]["Publisher"] = json!("x".repeat(128));
        let result = validate_draft(&draft);
        assert!(result.is_valid, "{:?}", result.findings);
    }

    /// Regression test for length being counted in Unicode scalar values (code points),
    /// not UTF-8 bytes: 128 CJK characters is exactly at the documented maximum, but each
    /// character is 3 bytes in UTF-8 (384 bytes total), so a byte-counting implementation
    /// would incorrectly reject this well-formed value.
    #[test]
    fn publisher_at_maximum_length_with_cjk_characters_is_accepted() {
        let mut draft = minimal_draft();
        let publisher: String = "世".repeat(128);
        assert_eq!(publisher.chars().count(), 128);
        assert_eq!(
            publisher.len(),
            384,
            "sanity check: each CJK character is 3 UTF-8 bytes"
        );
        draft["Metadata"]["Publisher"] = json!(publisher);
        let result = validate_draft(&draft);
        assert!(result.is_valid, "{:?}", result.findings);
    }

    /// Companion to the acceptance test above: one character past the documented maximum
    /// (129 Unicode scalar values) must still be rejected, proving the check is not
    /// simply disabled for multi-byte content.
    #[test]
    fn publisher_over_maximum_length_with_cjk_characters_is_rejected() {
        let mut draft = minimal_draft();
        let publisher: String = "世".repeat(129);
        draft["Metadata"]["Publisher"] = json!(publisher);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Metadata/Publisher")
        );
    }

    #[test]
    fn description_over_maximum_length_is_rejected() {
        let mut draft = minimal_draft();
        draft["Metadata"]["Description"] = json!("x".repeat(513));
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Metadata/Description")
        );
    }

    /// Same Unicode-scalar-counting regression as the publisher tests above, for the
    /// other plain human-text field sharing `check_string_bounds`.
    #[test]
    fn description_at_maximum_length_with_cjk_characters_is_accepted() {
        let mut draft = minimal_draft();
        let description: String = "説".repeat(512);
        assert_eq!(description.chars().count(), 512);
        draft["Metadata"]["Description"] = json!(description);
        let result = validate_draft(&draft);
        assert!(result.is_valid, "{:?}", result.findings);
    }

    /// Companion to the acceptance test above: one character past the documented maximum
    /// (513 Unicode scalar values) must still be rejected, proving the check is not
    /// simply disabled for multi-byte content.
    #[test]
    fn description_over_maximum_length_with_cjk_characters_is_rejected() {
        let mut draft = minimal_draft();
        let description: String = "説".repeat(513);
        draft["Metadata"]["Description"] = json!(description);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Metadata/Description")
        );
    }

    #[test]
    fn rule_reason_over_maximum_length_is_rejected() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule("r1", json!({ "Reason": "x".repeat(513) }))]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Rules/0/Reason")
        );
    }

    /// Same Unicode-scalar-counting regression as the publisher/description tests above,
    /// for the third and last plain human-text field sharing `check_string_bounds`.
    #[test]
    fn rule_reason_at_maximum_length_with_cjk_characters_is_accepted() {
        let mut draft = minimal_draft();
        let reason: String = "理".repeat(512);
        assert_eq!(reason.chars().count(), 512);
        draft["Rules"] = json!([rule("r1", json!({ "Reason": reason }))]);
        let result = validate_draft(&draft);
        assert!(result.is_valid, "{:?}", result.findings);
    }

    #[test]
    fn rule_reason_over_maximum_length_with_cjk_characters_is_rejected() {
        let mut draft = minimal_draft();
        let reason: String = "理".repeat(513);
        draft["Rules"] = json!([rule("r1", json!({ "Reason": reason }))]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Rules/0/Reason")
        );
    }

    #[test]
    fn managers_over_maximum_count_is_rejected() {
        // `ManagerName` has 17 variants, one more than the documented `Managers` bound of
        // 16: naming every manager is a real, reachable violation, not just a
        // structurally-impossible edge case.
        let all_managers = [
            "Winget",
            "PowerShell",
            "PowerShell7",
            "Apt",
            "Bun",
            "Cargo",
            "Chocolatey",
            "Dnf",
            "Dotnet",
            "Flatpak",
            "Homebrew",
            "Npm",
            "Pacman",
            "Pip",
            "Scoop",
            "Snap",
            "Vcpkg",
        ];
        assert_eq!(
            all_managers.len(),
            17,
            "test fixture must list every ManagerName variant"
        );

        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule("r1", json!({ "Match": { "Managers": all_managers } }))]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Rules/0/Match/Managers")
        );
    }

    #[test]
    fn sources_over_maximum_count_is_rejected() {
        let patterns: Vec<String> = (0..129).map(|i| format!("source-{i}")).collect();
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule("r1", json!({ "Match": { "Sources": patterns } }))]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation && f.path == "/Rules/0/Match/Sources")
        );
    }

    #[test]
    fn allowed_install_location_patterns_over_maximum_count_is_rejected() {
        let patterns: Vec<String> = (0..65).map(|i| format!("C:\\Tools{i}\\*")).collect();
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Constraints": { "AllowedInstallLocationPatterns": patterns } })
        )]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::SchemaViolation
                    && f.path == "/Rules/0/Constraints/AllowedInstallLocationPatterns")
        );
    }

    #[test]
    fn managers_at_maximum_count_is_accepted() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Match": { "Managers": [
                "Winget", "PowerShell", "PowerShell7", "Apt", "Bun", "Cargo", "Chocolatey", "Dnf",
                "Dotnet", "Flatpak", "Homebrew", "Npm", "Pacman", "Pip", "Scoop", "Snap",
            ] } })
        )]);
        let result = validate_draft(&draft);
        assert!(result.is_valid, "{:?}", result.findings);
    }

    #[test]
    fn non_empty_package_names_are_rejected_until_requests_expose_a_display_name() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Match": { "PackageNames": ["Visual Studio Code"] } })
        )]);

        let result = validate_draft(&draft);

        assert!(!result.is_valid);
        assert!(result.findings.iter().any(|finding| {
            finding.code == PolicyFindingCode::InvalidFieldValue
                && finding.path == "/Rules/0/Match/PackageNames"
                && finding.rule_id == Some(now_policy_api::ResourceId::from("r1"))
                && finding.message
                    == "PackageNames is not supported because package requests do not provide a package display name; \
                        leave this collection empty"
        }));
    }

    #[test]
    fn empty_package_names_remain_valid() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Match": { "Managers": ["Winget"], "PackageNames": [] } })
        )]);

        let result = validate_draft(&draft);

        assert!(result.is_valid, "{:?}", result.findings);
    }

    #[test]
    fn disk_failure_finding_never_interpolates_content() {
        // Never takes any variable/attacker-controlled input at all: its whole point is
        // that no code path can accidentally make it echo raw OS/serde error text or file
        // content. Assert every category's message is a fixed, non-empty string.
        for reason in [
            DiskFailureReason::Unreadable,
            DiskFailureReason::InsecureStorage,
            DiskFailureReason::MalformedContent,
        ] {
            let finding = disk_failure_finding(reason);
            assert_eq!(finding.code, PolicyFindingCode::SchemaViolation);
            assert_eq!(finding.path, "");
            assert!(!finding.message.is_empty());
        }
    }

    #[test]
    fn singleton_true_denied_constraint_is_contradictory() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({
                "Match": { "Interactive": [true] },
                "Constraints": { "AllowInteractive": false }
            })
        )]);
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::ContradictoryConstraints)
        );
    }

    #[test]
    fn singleton_false_denied_constraint_remains_reachable() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({
                "Match": { "Interactive": [false] },
                "Constraints": { "AllowInteractive": false }
            })
        )]);

        let result = validate_draft(&draft);

        assert!(result.is_valid, "{:?}", result.findings);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.code != PolicyFindingCode::ContradictoryConstraints)
        );
    }

    #[test]
    fn mixed_boolean_set_is_not_itself_a_contradiction() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({
                "Match": { "Interactive": [false] },
                "Constraints": { "AllowInteractive": false }
            })
        )]);
        let mut parsed: PolicyDraftDocument = serde_json::from_value(draft).expect("valid singleton boolean set");
        let rule = &mut parsed.rules[0];
        rule.match_criteria.interactive.insert(true);
        let mut findings = Vec::new();

        check_contradictory_constraints(0, rule, &mut findings);

        assert!(
            findings
                .iter()
                .all(|finding| finding.code != PolicyFindingCode::ContradictoryConstraints)
        );
    }

    #[test]
    fn mixed_boolean_set_is_rejected_structurally() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({
                "Match": { "Interactive": [false, true] },
                "Constraints": { "AllowInteractive": false }
            })
        )]);

        let result = validate_draft(&draft);

        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.code != PolicyFindingCode::ContradictoryConstraints)
        );
    }

    #[test]
    fn audit_mode_and_default_allow_are_warnings_only() {
        let mut draft = minimal_draft();
        draft["Enforcement"] =
            json!({ "DefaultDecision": "Allow", "RulePrecedence": "PriorityThenDeny", "AuditMode": true });
        let result = validate_draft(&draft);
        assert!(result.is_valid, "warnings must not invalidate an otherwise-valid draft");
        let codes: Vec<_> = result.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&PolicyFindingCode::AuditModeEnabled));
        assert!(codes.contains(&PolicyFindingCode::DefaultAllow));
        assert!(
            result
                .findings
                .iter()
                .all(|f| f.severity == PolicyFindingSeverity::Warning)
        );
    }

    /// (constraint field name in the draft JSON, corresponding `Match` field name,
    /// `Option` argument value reported on the finding) for every sensitive capability
    /// this validator flags. `Interactive` and `AllowUpgrade` are deliberately absent:
    /// see `check_sensitive_options`'s doc comment for why.
    const SENSITIVE_OPTIONS: &[(&str, &str, &str)] = &[
        ("AllowSkipHashCheck", "SkipHashCheck", "SkipHashCheck"),
        ("AllowPreRelease", "PreRelease", "PreRelease"),
        (
            "AllowCustomInstallLocation",
            "HasCustomInstallLocation",
            "AllowCustomInstallLocation",
        ),
        ("AllowCustomParameters", "HasCustomParameters", "AllowCustomParameters"),
        ("AllowPrePostCommands", "HasPrePostCommands", "AllowPrePostCommands"),
        (
            "AllowKillBeforeOperation",
            "HasKillBeforeOperation",
            "AllowKillBeforeOperation",
        ),
        (
            "AllowUninstallPrevious",
            "HasUninstallPrevious",
            "AllowUninstallPrevious",
        ),
    ];

    fn obj_with(pairs: &[(&str, serde_json::Value)]) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (key, value) in pairs {
            map.insert((*key).to_owned(), value.clone());
        }
        serde_json::Value::Object(map)
    }

    fn is_warned_for(result: &PolicyValidationResult, option: &str) -> bool {
        result.findings.iter().any(|f| {
            f.code == PolicyFindingCode::SensitiveOptionAllowed
                && f.arguments.get("Option") == Some(&serde_json::Value::from(option))
        })
    }

    #[test]
    fn sensitive_options_warn_when_match_is_absent_and_constraint_allows() {
        for (constraint_field, _match_field, option) in SENSITIVE_OPTIONS {
            let mut draft = minimal_draft();
            draft["Rules"] = json!([rule(
                "r1",
                json!({ "Constraints": obj_with(&[(constraint_field, json!(true))]) })
            )]);
            let result = validate_draft(&draft);
            assert!(result.is_valid, "{constraint_field}: {:?}", result.findings);
            assert!(
                is_warned_for(&result, option),
                "{constraint_field} should warn when Match does not restrict it"
            );
        }
    }

    #[test]
    fn sensitive_options_warn_when_match_is_true() {
        for (constraint_field, match_field, option) in SENSITIVE_OPTIONS {
            let mut draft = minimal_draft();
            draft["Rules"] = json!([rule(
                "r1",
                json!({
                    "Match": obj_with(&[("Managers", json!(["Winget"])), (match_field, json!([true]))]),
                    "Constraints": obj_with(&[(constraint_field, json!(true))]),
                })
            )]);
            let result = validate_draft(&draft);
            assert!(result.is_valid, "{constraint_field}: {:?}", result.findings);
            assert!(
                is_warned_for(&result, option),
                "{constraint_field} should warn when Match=[true]"
            );
        }
    }

    #[test]
    fn sensitive_options_do_not_warn_when_match_is_false_only() {
        for (constraint_field, match_field, option) in SENSITIVE_OPTIONS {
            let mut draft = minimal_draft();
            draft["Rules"] = json!([rule(
                "r1",
                json!({
                    "Match": obj_with(&[("Managers", json!(["Winget"])), (match_field, json!([false]))]),
                    "Constraints": obj_with(&[(constraint_field, json!(true))]),
                })
            )]);
            let result = validate_draft(&draft);
            assert!(result.is_valid, "{constraint_field}: {:?}", result.findings);
            assert!(
                !is_warned_for(&result, option),
                "{constraint_field} must not warn when Match=[false] can never see it true"
            );
        }
    }

    #[test]
    fn sensitive_options_do_not_warn_when_constraint_denies() {
        for (constraint_field, _match_field, option) in SENSITIVE_OPTIONS {
            let mut draft = minimal_draft();
            draft["Rules"] = json!([rule(
                "r1",
                json!({ "Constraints": obj_with(&[(constraint_field, json!(false))]) })
            )]);
            let result = validate_draft(&draft);
            assert!(
                !is_warned_for(&result, option),
                "{constraint_field}=false must not warn"
            );
        }
    }

    #[test]
    fn sensitive_options_do_not_warn_when_rule_disabled_or_deny() {
        for (constraint_field, _match_field, option) in SENSITIVE_OPTIONS {
            let mut draft = minimal_draft();
            draft["Rules"] = json!([
                rule(
                    "r1",
                    json!({ "Enabled": false, "Constraints": obj_with(&[(constraint_field, json!(true))]) })
                ),
                rule(
                    "r2",
                    json!({ "Decision": "Deny", "Constraints": obj_with(&[(constraint_field, json!(true))]) })
                ),
            ]);
            let result = validate_draft(&draft);
            assert!(result.is_valid);
            assert!(
                !is_warned_for(&result, option),
                "{constraint_field} on a disabled or Deny rule must not warn"
            );
        }
    }

    #[test]
    fn unrestricted_custom_parameters_are_warned() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule("r1", json!({ "Constraints": { "AllowCustomParameters": true } }))]);
        let result = validate_draft(&draft);
        assert!(result.is_valid);
        let finding = result
            .findings
            .iter()
            .find(|f| {
                f.code == PolicyFindingCode::SensitiveOptionAllowed
                    && f.arguments.get("Option") == Some(&serde_json::Value::from("AllowCustomParameters"))
            })
            .expect("unrestricted custom parameters must be warned");
        assert!(
            !finding.arguments.contains_key("AllowedCustomParameters"),
            "an unrestricted rule must not report an allow-list that does not exist"
        );
    }

    #[test]
    fn restricted_custom_parameters_are_warned_with_restriction_details() {
        // A partial allow-list is still worth a human's attention: it must not silently
        // suppress the warning, only enrich it with the actual restriction in effect.
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Constraints": { "AllowCustomParameters": true, "AllowedCustomParameters": ["--silent"] } })
        )]);
        let result = validate_draft(&draft);
        assert!(result.is_valid);
        let finding = result
            .findings
            .iter()
            .find(|f| {
                f.code == PolicyFindingCode::SensitiveOptionAllowed
                    && f.arguments.get("Option") == Some(&serde_json::Value::from("AllowCustomParameters"))
            })
            .expect("a restricted-but-not-catch-all-denied rule must still be warned");
        assert_eq!(
            finding.arguments.get("AllowedCustomParameters"),
            Some(&json!(["--silent"]))
        );
    }

    #[test]
    fn provable_catch_all_deny_suppresses_custom_parameters_warning() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Constraints": { "AllowCustomParameters": true, "DeniedCustomParameters": ["*"] } })
        )]);
        let result = validate_draft(&draft);
        assert!(result.is_valid);
        assert!(
            !is_warned_for(&result, "AllowCustomParameters"),
            "a denied_custom_parameters entry of exactly '*' rejects every value, so nothing can get through"
        );
    }

    #[test]
    fn partial_deny_list_does_not_suppress_custom_parameters_warning() {
        // Only an exact `"*"` is a *provable* catch-all; a merely broad-looking pattern
        // must not be trusted to suppress the warning.
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({ "Constraints": { "AllowCustomParameters": true, "DeniedCustomParameters": ["--force"] } })
        )]);
        let result = validate_draft(&draft);
        assert!(result.is_valid);
        assert!(is_warned_for(&result, "AllowCustomParameters"));
    }

    #[test]
    fn custom_install_location_restriction_is_included_in_structured_args() {
        let mut draft = minimal_draft();
        draft["Rules"] = json!([rule(
            "r1",
            json!({
                "Constraints": {
                    "AllowCustomInstallLocation": true,
                    "AllowedInstallLocationPatterns": ["C:\\Tools\\*"],
                }
            })
        )]);
        let result = validate_draft(&draft);
        assert!(result.is_valid);
        let finding = result
            .findings
            .iter()
            .find(|f| {
                f.code == PolicyFindingCode::SensitiveOptionAllowed
                    && f.arguments.get("Option") == Some(&serde_json::Value::from("AllowCustomInstallLocation"))
            })
            .expect("a restricted custom install location must still be warned");
        assert_eq!(
            finding.arguments.get("AllowedInstallLocationPatterns"),
            Some(&json!(["C:\\Tools\\*"]))
        );
    }

    #[test]
    fn invalid_wildcard_pattern_is_rejected() {
        // `StringPattern` enforces a 256-character cap at deserialization time, so a
        // pattern large enough to blow past the regex engine's compiled-program size
        // limit can only be constructed directly (bypassing JSON parsing), exercising
        // `check_wildcard_patterns` at the Rust level instead of through `validate_draft`.
        let huge_pattern = now_policy::StringPattern("a*".repeat(2_000_000));
        let rule = PolicyRule {
            id: now_policy::ResourceId::from("r1"),
            enabled: true,
            priority: 100,
            decision: Decision::Allow,
            reason: None,
            match_criteria: PolicyMatch {
                sources: BTreeSet::from([huge_pattern]),
                ..Default::default()
            },
            constraints: None,
        };

        let mut findings = Vec::new();
        check_wildcard_patterns(0, &rule, &mut findings);

        assert!(
            findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::InvalidWildcardPattern)
        );
    }

    #[test]
    fn validity_interval_order_is_enforced() {
        let mut draft = minimal_draft();
        draft["Metadata"]["ValidFrom"] = json!("2030-01-01T00:00:00Z");
        draft["Metadata"]["ValidUntil"] = json!("2020-01-01T00:00:00Z");
        let result = validate_draft(&draft);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::InvalidValidityInterval)
        );
    }

    #[test]
    fn canonical_draft_is_deterministic_for_the_same_input() {
        let draft = minimal_draft();
        let first = validate_draft(&draft);
        let second = validate_draft(&draft);
        assert_eq!(
            serde_json::to_value(first.canonical_draft).unwrap(),
            serde_json::to_value(second.canonical_draft).unwrap()
        );
    }

    #[test]
    fn canonical_draft_reflects_input_changes() {
        let first = validate_draft(&minimal_draft());
        let mut other = minimal_draft();
        other["Metadata"]["Publisher"] = json!("Someone Else");
        let second = validate_draft(&other);
        assert_ne!(
            serde_json::to_value(first.canonical_draft).unwrap(),
            serde_json::to_value(second.canonical_draft).unwrap()
        );
    }

    // ─── validate_committed_policy (item 30) ───────────────────────────────────

    fn minimal_committed_policy(id: &str, revision: u32) -> now_policy::PolicyDocument {
        serde_json::from_value(json!({
            "$schema": now_policy::POLICY_SCHEMA_URI,
            "PolicyVersion": "1.0.0",
            "PolicyType": "PackageBrokerPolicy",
            "Metadata": { "Id": id, "Publisher": "Test", "Revision": revision, "PublishedAt": chrono::Utc::now() },
            "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
            "Rules": [],
        }))
        .expect("test committed policy is well-formed")
    }

    #[test]
    fn well_formed_committed_policy_is_valid() {
        let policy = minimal_committed_policy("test-policy", 1);
        let result = validate_committed_policy(&policy);
        assert!(result.is_valid, "{:?}", result.findings);
    }

    #[test]
    fn committed_policy_with_zero_revision_is_invalid() {
        // The shared model rejects revision 0 during parsing and serialization.
        // Mutate an otherwise-valid model to exercise this defensive validation independently.
        let mut policy = minimal_committed_policy("test-policy", 1);
        policy.metadata.revision = 0;
        let result = validate_committed_policy(&policy);
        assert!(!result.is_valid);
    }

    #[test]
    fn committed_policy_with_duplicate_rule_ids_is_invalid() {
        let mut policy = minimal_committed_policy("test-policy", 1);
        let one_rule: PolicyRule = serde_json::from_value(rule("r1", json!({}))).unwrap();
        policy.rules = vec![one_rule.clone(), one_rule];
        let result = validate_committed_policy(&policy);
        assert!(!result.is_valid);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::DuplicateRuleId)
        );
    }

    #[test]
    fn committed_policy_with_only_warnings_is_still_valid() {
        // Warnings (audit mode, default-allow, sensitive options) never block
        // activation, whether for a submitted draft or an already-committed document:
        // `is_valid` reflects only Error-severity findings.
        let mut policy = minimal_committed_policy("test-policy", 1);
        policy.enforcement.audit_mode = Some(true);
        let result = validate_committed_policy(&policy);
        assert!(result.is_valid, "{:?}", result.findings);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.code == PolicyFindingCode::AuditModeEnabled)
        );
    }

    #[test]
    fn committed_policy_with_oversized_publisher_is_invalid() {
        // Proves the committed-document path shares the exact same bound checks a
        // submitted draft is held to (item 30), not just structural JSON parseability.
        let mut policy = minimal_committed_policy("test-policy", 1);
        policy.metadata.publisher = "x".repeat(129);
        let result = validate_committed_policy(&policy);
        assert!(!result.is_valid);
    }
}
