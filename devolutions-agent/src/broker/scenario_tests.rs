//! High-level scenario tests using sample policies and requests.
//!
//! These tests keep broad end-to-end coverage for the broker policy concepts.
//! Detailed rule matching and constraint behavior is covered by lower-level unit tests.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use now_policy::PolicyDocument;
use now_policy_api::PackageRequest;
use serde::Deserialize;

use super::evaluator;

/// Local samples directory bundled inside the crate.
fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/broker/assets/samples")
}

// ─── Scenario file structures ────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ScenarioSet {
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
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
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "yaml" | "yml" => serde_yaml::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to deserialize YAML policy {}: {e}", path.display())),
        _ => serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("failed to deserialize policy {}: {e}", path.display())),
    }
}

fn load_request(path: &Path) -> PackageRequest {
    let value = load_json_file(path);
    serde_json::from_value(value).unwrap_or_else(|e| panic!("failed to deserialize request {}: {e}", path.display()))
}

// ─── Scenario-driven evaluation tests ────────────────────────────────────────

fn run_scenarios(scenario_file: &str) {
    let dir = samples_dir();
    let scenarios_path = dir.join("scenarios").join(scenario_file);
    let content = std::fs::read_to_string(&scenarios_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", scenarios_path.display()));
    let scenario_set: ScenarioSet =
        serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse scenarios: {e}"));

    let mut failures: Vec<String> = Vec::new();

    for scenario in &scenario_set.scenarios {
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
        let decision = evaluator::evaluate(&policy, &request);

        let expected_decision = match scenario.expected_decision.as_str() {
            "Allow" => now_policy::Decision::Allow,
            "Deny" => now_policy::Decision::Deny,
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

#[test]
fn core_policy_scenarios() {
    run_scenarios("baseline.scenarios.json");
}
