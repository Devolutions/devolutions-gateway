//! Policy model and sample validation tests.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use unigetui_broker_policy::PolicyDocument;

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/samples")
}

fn load_policy(path: &Path) -> PolicyDocument {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "yaml" | "yml" => serde_yaml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to deserialize YAML policy {}: {e}", path.display())),
        _ => serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to deserialize policy {}: {e}", path.display())),
    }
}

#[test]
fn all_sample_policies_deserialize() {
    let dir = samples_dir();

    let policy_files = [
        "corporate-allowlist.policy.json",
        "corporate-allowlist.policy.yaml",
        "deny-risky-options.policy.json",
        "powershell-advanced.policy.json",
        "powershell-current-user.policy.json",
        "scenario-coverage.policy.json",
    ];

    for file in &policy_files {
        let path = dir.join(file);
        let _policy = load_policy(&path);
    }
}

#[test]
fn invalid_policy_unknown_field_fails_deserialization() {
    let value = serde_json::json!({
        "$schema": "https://aka.ms/unigetui/package-policy.schema.1.0.json",
        "PolicyVersion": "1.0.0",
        "PolicyType": "PackageBrokerPolicy",
        "Metadata": {
            "Id": "test",
            "Publisher": "Test",
            "Revision": 1,
            "PublishedAt": "2026-01-01T00:00:00Z"
        },
        "Enforcement": {
            "DefaultDecision": "Deny",
            "RulePrecedence": "PriorityThenDeny",
            "UnknownField": true
        },
        "Rules": []
    });

    let result: Result<PolicyDocument, _> = serde_json::from_value(value);
    assert!(result.is_err(), "policy with unknown field should fail deserialization");
}

#[test]
fn invalid_policy_fixture_fails_deserialization() {
    let path = samples_dir().join("invalid/policies/invalid-failure-decision.policy.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let result: Result<PolicyDocument, _> = serde_json::from_str(&content);
    assert!(result.is_err(), "invalid policy fixture should fail deserialization");
}

#[test]
fn policy_schema_generates_valid_json() {
    let schema = unigetui_broker_policy::schema::policy_schema_json();
    assert!(schema.is_object());
    let obj = schema.as_object().unwrap();
    assert!(
        obj.contains_key("definitions") || obj.contains_key("$defs"),
        "schema should have type definitions"
    );
}
