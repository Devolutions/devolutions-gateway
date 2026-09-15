#![cfg(windows)]

use now_package_broker::installer_policy_migration::convert_document;
use rstest::rstest;

const LEGACY: &str = r#"{
    "$schema":"https://devolutions.net/schemas/now-policy.schema.1.0.json",
    "PolicyVersion":"1.0.0",
    "PolicyType":"PackageBrokerPolicy",
    "Metadata":{"Id":"policy-a","Publisher":"Test\u0020Publisher","Revision":17,"PublishedAt":"2026-01-01T09:00:00.000+09:00","ValidFrom":"2025-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z"},
    "Enforcement":{"DefaultDecision":"Deny","RulePrecedence":"PriorityThenDeny"},
    "Rules":[{"Id":"z","Priority":2,"Decision":"Deny","Match":{"Managers":["Winget"]}},{"Id":"a","Priority":1,"Decision":"Allow","Match":{"Managers":["Winget"]}}]
}"#;

#[rstest]
#[case("1.0.0")]
#[case("1.7.3")]
#[case("1.18446744073709551615.0")]
fn preserves_version_and_raw_content(#[case] version: &str) {
    let input = LEGACY.replace("1.0.0", version);
    let output = convert_document(&input).expect("convert compatible legacy policy");
    let before: serde_json::Value = serde_json::from_str(&input).expect("parse legacy fixture");
    let after: serde_json::Value = serde_json::from_str(&output).expect("parse converted policy");
    assert!(after.get("$schema").is_none());
    assert!(after.get("PolicyVersion").is_none());
    assert_eq!(after["PolicyFormatVersion"], version);
    for field in ["PolicyType", "Metadata", "Enforcement", "Rules"] {
        assert_eq!(before[field], after[field]);
    }
    for line in input.lines().filter(|line| {
        ["\"Metadata\":", "\"Enforcement\":", "\"Rules\":"]
            .iter()
            .any(|prefix| line.trim_start().starts_with(prefix))
    }) {
        assert!(output.contains(line.trim().trim_end_matches(',')));
    }
    assert_eq!(convert_document(&output).expect("validate current policy"), output);
}

#[rstest]
#[case("0.9.0")]
#[case("2.0.0")]
#[case("1.01.0")]
#[case("01.0.0")]
#[case("1.0")]
#[case("1.0.0-beta")]
#[case("1.0.0+build")]
#[case("1.0.0 ")]
#[case("1.18446744073709551616.0")]
fn rejects_incompatible_or_noncanonical_versions(#[case] version: &str) {
    assert!(convert_document(&LEGACY.replace("1.0.0", version)).is_err());
}

#[rstest]
#[case("\"PolicyFormatVersion\":\"1.0.0\",")]
#[case("\"PolicyVersion\":\"1.0.0\",")]
#[case("\"Policy\\u0056ersion\":\"1.0.0\",")]
#[case("\"$schema\":\"https://devolutions.net/schemas/now-policy.schema.1.0.json\",")]
#[case("\"policyVersion\":\"1.0.0\",")]
#[case("\"Id\":\"ambiguous\",")]
#[case("\"Unknown\":true,")]
fn rejects_mixed_duplicate_and_unknown_identity(#[case] extra: &str) {
    assert!(convert_document(&LEGACY.replacen('{', &format!("{{{extra}"), 1)).is_err());
}

#[rstest]
#[case("https://example.com/schema")]
#[case("https://devolutions.net/schemas/now-policy-draft.schema.1.0.json")]
fn rejects_wrong_schema(#[case] schema: &str) {
    assert!(
        convert_document(&LEGACY.replace("https://devolutions.net/schemas/now-policy.schema.1.0.json", schema))
            .is_err()
    );
}

#[rstest]
#[case("\"Revision\":17", "\"Revision\":0")]
#[case("\"Revision\":17", "\"Revision\":17,\"Revision\":18")]
#[case("\"Publisher\":", "\"Unknown\":true,\"Publisher\":")]
#[case("\"Id\":\"a\"", "\"Id\":\"z\"")]
#[case("\"ValidUntil\":\"2027", "\"ValidUntil\":\"2024")]
#[case("\"PublishedAt\":\"2026", "\"PublishedAt\":\"invalid")]
#[case("\"Priority\":2", "\"Priority\":2,\"Priority\":3")]
#[case("\"Priority\":2", "\"Priority\":2147483648")]
#[case("\"DefaultDecision\":", "\"Unknown\":true,\"DefaultDecision\":")]
fn rejects_malformed_and_semantically_invalid_content(#[case] from: &str, #[case] to: &str) {
    assert!(convert_document(&LEGACY.replace(from, to)).is_err());
}

#[rstest]
#[case("\"PolicyFormatVersion\":\"1.7.3\",")]
#[case("\"PolicyFormat\\u0056ersion\":\"1.0.0\",")]
#[case("\"PolicyVersion\":\"1.0.0\",")]
#[case("\"$schema\":\"https://devolutions.net/schemas/now-policy.schema.1.0.json\",")]
fn current_documents_do_not_accept_ambiguous_identity(#[case] extra: &str) {
    let current = convert_document(LEGACY).expect("convert legacy fixture");
    assert!(convert_document(&current.replacen('{', &format!("{{{extra}"), 1)).is_err());
}

#[test]
fn rejects_non_json_and_oversized_documents() {
    for input in [
        "PolicyVersion: 1.0.0".to_owned(),
        format!("{LEGACY} {{}}"),
        LEGACY.replacen('{', "{/* comment */", 1),
        LEGACY.replace("\"Rules\":", "'Rules':"),
        " ".repeat(1024 * 1024 + 1),
    ] {
        assert!(convert_document(&input).is_err());
    }
}
