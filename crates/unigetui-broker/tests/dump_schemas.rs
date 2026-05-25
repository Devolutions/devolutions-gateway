//! Schema export and sample validation tests.
//!
//! Validates that the local sample documents successfully
//! deserialize into our typed structs (which perform full validation).

#![allow(clippy::unwrap_used, clippy::print_stderr)]

use std::path::PathBuf;

use schemars::schema_for;
use unigetui_broker::model::{BrokerResponse, PackageRequest, PolicyDocument};

/// Local samples directory bundled inside the crate.
fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/samples")
}

#[test]
fn dump_request_schema() {
    let schema = schema_for!(PackageRequest);
    let json = serde_json::to_string_pretty(&schema).unwrap();
    std::fs::write("../../output/generated-request-schema.json", &json).unwrap();
}

#[test]
fn dump_policy_schema() {
    let schema = schema_for!(PolicyDocument);
    let json = serde_json::to_string_pretty(&schema).unwrap();
    std::fs::write("../../output/generated-policy-schema.json", &json).unwrap();
}

#[test]
fn dump_response_schema() {
    let schema = schema_for!(BrokerResponse);
    let json = serde_json::to_string_pretty(&schema).unwrap();
    std::fs::write("../../output/generated-response-schema.json", &json).unwrap();
}

#[test]
fn sample_requests_pass_deserialization() {
    let requests_dir = samples_dir().join("requests");
    let dir = std::fs::read_dir(&requests_dir).unwrap_or_else(|e| panic!("failed to read {requests_dir:?}: {e}"));

    let mut tested = 0;
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let content = std::fs::read_to_string(&path).unwrap();
            let _request: PackageRequest = serde_json::from_str(&content).unwrap_or_else(|e| {
                panic!(
                    "Request sample {:?} failed deserialization: {e}",
                    path.file_name().unwrap()
                );
            });
            tested += 1;
        }
    }
    assert!(tested > 0, "No request samples found");
    eprintln!("Validated {tested} request samples.");
}

#[test]
fn sample_policies_pass_deserialization() {
    let dir = std::fs::read_dir(samples_dir()).unwrap_or_else(|e| panic!("failed to read samples dir: {e}"));

    let mut tested = 0;
    for entry in dir.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
        let name = path.to_str().unwrap_or_default();

        if name.contains(".policy.") {
            let content = std::fs::read_to_string(&path).unwrap();
            match ext {
                "json" => {
                    let _policy: PolicyDocument = serde_json::from_str(&content).unwrap_or_else(|e| {
                        panic!(
                            "Policy sample {:?} failed deserialization: {e}",
                            path.file_name().unwrap()
                        );
                    });
                }
                "yaml" | "yml" => {
                    let _policy: PolicyDocument = serde_yaml::from_str(&content).unwrap_or_else(|e| {
                        panic!(
                            "YAML policy sample {:?} failed deserialization: {e}",
                            path.file_name().unwrap()
                        );
                    });
                }
                _ => continue,
            }
            tested += 1;
        }
    }
    assert!(tested > 0, "No policy samples found");
    eprintln!("Validated {tested} policy samples.");
}

#[test]
fn sample_responses_pass_deserialization() {
    let responses_dir = samples_dir().join("responses");
    let dir = std::fs::read_dir(&responses_dir).unwrap_or_else(|e| panic!("failed to read {responses_dir:?}: {e}"));

    let mut tested = 0;
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let content = std::fs::read_to_string(&path).unwrap();
            let value: serde_json::Value = serde_json::from_str(&content).unwrap();

            let _response: BrokerResponse = serde_json::from_value(value).unwrap_or_else(|e| {
                panic!(
                    "Response sample {:?} failed deserialization: {e}",
                    path.file_name().unwrap()
                );
            });
            tested += 1;
        }
    }
    assert!(tested > 0, "No response samples found");
    eprintln!("Validated {tested} response samples.");
}
