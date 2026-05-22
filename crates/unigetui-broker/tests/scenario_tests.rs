//! Integration tests using UniGetUI sample policies, requests, and scenarios.
//!
//! These tests load the JSON fixtures from the UniGetUI repository and verify
//! that the Rust evaluator produces the exact same decisions as documented in
//! the scenario files.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use serde::Deserialize;
use unigetui_broker::evaluator;
use unigetui_broker::models::{Decision, PackageRequest, PolicyDocument};
use unigetui_broker::schema::SchemaValidators;

/// Root directory for UniGetUI policy samples (relative to this crate's manifest dir).
fn samples_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // d:\devolutions-gateway\crates\unigetui-broker -> d:\UniGetUI\policies\samples
    let candidate = manifest_dir
        .parent() // crates/
        .unwrap()
        .parent() // devolutions-gateway/
        .unwrap()
        .parent() // d:\
        .unwrap()
        .join("UniGetUI")
        .join("policies")
        .join("samples");

    if candidate.exists() {
        return candidate;
    }

    // Fallback: try sibling directory pattern (CI might place repos side by side).
    let alt = manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("..") // one level up from devolutions-gateway
        .join("UniGetUI")
        .join("policies")
        .join("samples");

    assert!(
        alt.exists(),
        "UniGetUI samples not found at {} or {}",
        candidate.display(),
        alt.display()
    );
    alt
}

// ─── Scenario file structures ────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScenarioSet {
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Scenario {
    id: String,
    policy: String,
    request: String,
    expected_decision: String,
    expected_rule_id: String,
}

// ─── Helper functions ────────────────────────────────────────────────────────

fn load_json_file(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

fn load_policy(path: &Path) -> PolicyDocument {
    let value = load_json_file(path);
    serde_json::from_value(value).unwrap_or_else(|e| panic!("failed to deserialize policy {}: {e}", path.display()))
}

fn load_request(path: &Path) -> PackageRequest {
    let value = load_json_file(path);
    serde_json::from_value(value).unwrap_or_else(|e| panic!("failed to deserialize request {}: {e}", path.display()))
}

// ─── Schema validation tests ─────────────────────────────────────────────────

#[test]
fn all_sample_policies_pass_schema_validation() {
    let validators = SchemaValidators::new();
    let dir = samples_dir();

    let policy_files = [
        "corporate-allowlist.policy.json",
        "deny-risky-options.policy.json",
        "powershell-advanced.policy.json",
        "powershell-current-user.policy.json",
        "scenario-coverage.policy.json",
    ];

    for file in &policy_files {
        let path = dir.join(file);
        let value = load_json_file(&path);
        validators
            .validate_policy(&value)
            .unwrap_or_else(|e| panic!("policy {file} failed schema validation: {e}"));
    }
}

#[test]
fn all_sample_policies_deserialize() {
    let dir = samples_dir();

    let policy_files = [
        "corporate-allowlist.policy.json",
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
fn all_sample_requests_pass_schema_validation() {
    let validators = SchemaValidators::new();
    let dir = samples_dir().join("requests");

    let request_files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read dir {}: {e}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".request.json") {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();

    assert!(!request_files.is_empty(), "no request files found in {}", dir.display());

    for path in &request_files {
        let value = load_json_file(path);
        validators.validate_request(&value).unwrap_or_else(|e| {
            panic!(
                "request {} failed schema validation: {e}",
                path.file_name().unwrap().to_string_lossy()
            )
        });
    }
}

#[test]
fn all_sample_requests_deserialize() {
    let dir = samples_dir().join("requests");

    let request_files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".request.json") {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();

    for path in &request_files {
        let _request: PackageRequest = load_request(&path);
    }
}

// ─── Invalid samples ─────────────────────────────────────────────────────────

#[test]
fn invalid_request_missing_package_id_fails_schema_validation() {
    let validators = SchemaValidators::new();
    let path = samples_dir().join("invalid/requests/missing-package-id.request.json");
    let value = load_json_file(&path);
    assert!(
        validators.validate_request(&value).is_err(),
        "request with missing package.id should fail schema validation"
    );
}

#[test]
fn invalid_policy_bad_failure_decision_fails_deserialization() {
    let path = samples_dir().join("invalid/policies/invalid-failure-decision.policy.json");
    let value = load_json_file(&path);
    // "failureDecision": "allow" is not a valid variant (only "deny" is accepted).
    let result: Result<PolicyDocument, _> = serde_json::from_value(value);
    assert!(
        result.is_err(),
        "policy with failureDecision='allow' should fail deserialization"
    );
}

// ─── Scenario-driven evaluation tests ────────────────────────────────────────

fn run_scenarios(scenario_file: &str) {
    let dir = samples_dir();
    let scenarios_path = dir.join("scenarios").join(scenario_file);
    let content = std::fs::read_to_string(&scenarios_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", scenarios_path.display()));
    let scenario_set: ScenarioSet =
        serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse scenarios: {e}"));

    let validators = SchemaValidators::new();
    let mut failures: Vec<String> = Vec::new();

    for scenario in &scenario_set.scenarios {
        // Skip YAML scenarios (we don't support YAML).
        if scenario.policy.ends_with(".yaml") || scenario.request.ends_with(".yaml") {
            continue;
        }

        // Validation-failure scenarios: test that schema/deser rejects the input.
        if scenario.expected_rule_id == "<validation-failure>" {
            let handled = handle_validation_failure_scenario(&validators, &dir, scenario);
            if !handled {
                failures.push(format!("{}: expected validation failure but got success", scenario.id));
            }
            continue;
        }

        // Load policy.
        let policy_path = dir.join(&scenario.policy);
        let policy = match std::panic::catch_unwind(|| load_policy(&policy_path)) {
            Ok(p) => p,
            Err(_) => {
                failures.push(format!("{}: failed to load policy {}", scenario.id, scenario.policy));
                continue;
            }
        };

        // Load request.
        let request_path = dir.join(&scenario.request);
        let request = match std::panic::catch_unwind(|| load_request(&request_path)) {
            Ok(r) => r,
            Err(_) => {
                failures.push(format!("{}: failed to load request {}", scenario.id, scenario.request));
                continue;
            }
        };

        // Evaluate.
        let decision = match evaluator::evaluate(&policy, &request) {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("{}: evaluator error: {e}", scenario.id));
                continue;
            }
        };

        let expected_decision = match scenario.expected_decision.as_str() {
            "allow" => Decision::Allow,
            "deny" => Decision::Deny,
            other => {
                failures.push(format!("{}: unknown expectedDecision '{other}'", scenario.id));
                continue;
            }
        };

        if decision.decision != expected_decision {
            failures.push(format!(
                "{}: expected decision '{}' but got '{}' (rule: {})",
                scenario.id, scenario.expected_decision, decision.decision, decision.rule_id
            ));
            continue;
        }

        if decision.rule_id != scenario.expected_rule_id {
            failures.push(format!(
                "{}: expected rule_id '{}' but got '{}'",
                scenario.id, scenario.expected_rule_id, decision.rule_id
            ));
        }
    }

    if !failures.is_empty() {
        panic!("{} scenario(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    }
}

/// Handle a scenario that expects validation failure.
/// Returns true if the scenario correctly fails validation.
fn handle_validation_failure_scenario(validators: &SchemaValidators, dir: &Path, scenario: &Scenario) -> bool {
    // Try policy validation failure first.
    let policy_path = dir.join(&scenario.policy);
    let policy_value = load_json_file(&policy_path);
    if validators.validate_policy(&policy_value).is_err() {
        return true;
    }
    // If policy validates OK, check if it fails deserialization.
    if serde_json::from_value::<PolicyDocument>(policy_value).is_err() {
        return true;
    }

    // Try request validation failure.
    let request_path = dir.join(&scenario.request);
    let request_value = load_json_file(&request_path);
    if validators.validate_request(&request_value).is_err() {
        return true;
    }
    if serde_json::from_value::<PackageRequest>(request_value).is_err() {
        return true;
    }

    false
}

#[test]
fn baseline_scenarios() {
    run_scenarios("baseline.scenarios.json");
}

#[test]
fn extended_scenarios() {
    run_scenarios("extended.scenarios.json");
}

// ─── Response format tests ───────────────────────────────────────────────────

#[test]
fn sample_responses_deserialize() {
    let dir = samples_dir().join("responses");

    if !dir.exists() {
        return; // Responses dir may not exist in all checkouts.
    }

    let response_files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".response.json") {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();

    for path in &response_files {
        let value = load_json_file(path);
        // Verify the response JSON has the expected structure
        // (we don't fully deserialize since the simulator might produce slightly different fields).
        let obj = value.as_object().unwrap_or_else(|| {
            panic!(
                "response {} is not an object",
                path.file_name().unwrap().to_string_lossy()
            )
        });
        assert!(obj.contains_key("decision"), "response missing 'decision' field");
        assert!(obj.contains_key("ruleId"), "response missing 'ruleId' field");
        assert!(
            obj.contains_key("wouldExecute"),
            "response missing 'wouldExecute' field"
        );
    }
}
