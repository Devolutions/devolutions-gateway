//! Schema export and sample validation tests.
//!
//! Validates that the local sample documents successfully
//! deserialize into our typed structs (which perform full validation).

#![allow(clippy::unwrap_used, clippy::print_stderr)]

use std::path::PathBuf;

use schemars::schema_for;
use unigetui_broker::model::{BrokerResponse, PackageRequest, PolicyDocument, StatusRequest, StatusResponse};

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
            let filename = path.file_name().unwrap().to_str().unwrap_or_default();
            // Status requests have their own test.
            if filename.starts_with("status-") {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap();
            let _request: PackageRequest = serde_json::from_str(&content).unwrap_or_else(|e| {
                panic!("Request sample {filename:?} failed deserialization: {e}");
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
            let filename = path.file_name().unwrap().to_str().unwrap_or_default();
            // Status responses have their own test.
            if filename.starts_with("status-") {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap();
            let value: serde_json::Value = serde_json::from_str(&content).unwrap();

            let _response: BrokerResponse = serde_json::from_value(value).unwrap_or_else(|e| {
                panic!("Response sample {filename:?} failed deserialization: {e}");
            });
            tested += 1;
        }
    }
    assert!(tested > 0, "No response samples found");
    eprintln!("Validated {tested} response samples.");
}

#[test]
fn sample_status_requests_pass_deserialization() {
    let requests_dir = samples_dir().join("requests");
    let dir = std::fs::read_dir(&requests_dir).unwrap_or_else(|e| panic!("failed to read {requests_dir:?}: {e}"));

    let mut tested = 0;
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let filename = path.file_name().unwrap().to_str().unwrap_or_default();
            if !filename.starts_with("status-") {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap();
            let _request: StatusRequest = serde_json::from_str(&content).unwrap_or_else(|e| {
                panic!("Status request sample {filename:?} failed deserialization: {e}");
            });
            tested += 1;
        }
    }
    assert!(tested > 0, "No status request samples found");
    eprintln!("Validated {tested} status request samples.");
}

#[test]
fn sample_status_responses_pass_deserialization() {
    let responses_dir = samples_dir().join("responses");
    let dir = std::fs::read_dir(&responses_dir).unwrap_or_else(|e| panic!("failed to read {responses_dir:?}: {e}"));

    let mut tested = 0;
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let filename = path.file_name().unwrap().to_str().unwrap_or_default();
            if !filename.starts_with("status-") {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap();
            let _response: StatusResponse = serde_json::from_str(&content).unwrap_or_else(|e| {
                panic!("Status response sample {filename:?} failed deserialization: {e}");
            });
            tested += 1;
        }
    }
    assert!(tested > 0, "No status response samples found");
    eprintln!("Validated {tested} status response samples.");
}

#[test]
fn status_request_roundtrip() {
    let content = std::fs::read_to_string(samples_dir().join("requests/status-query-running.request.json")).unwrap();
    let request: StatusRequest = serde_json::from_str(&content).unwrap();

    assert_eq!(&*request.request_id, "req-winget-vscode-install");
    assert_eq!(&*request.request_version, "1.0.0");
    assert_eq!(&request.broker.effective_user, "CONTOSO\\alice");

    // Roundtrip: serialize and re-parse.
    let json = serde_json::to_string_pretty(&request).unwrap();
    let reparsed: StatusRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(&*reparsed.request_id, &*request.request_id);
}

#[test]
fn status_response_roundtrip_completed() {
    let content = std::fs::read_to_string(samples_dir().join("responses/status-completed.response.json")).unwrap();
    let response: StatusResponse = serde_json::from_str(&content).unwrap();

    assert_eq!(&*response.request_id, "req-winget-vscode-install");
    assert_eq!(response.status, unigetui_broker::model::OperationStatus::Completed);
    assert_eq!(response.exit_code, Some(0));
    assert!(response.started_at.is_some());
    assert!(response.completed_at.is_some());

    let json = serde_json::to_string_pretty(&response).unwrap();
    let reparsed: StatusResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(reparsed.status, response.status);
    assert_eq!(reparsed.exit_code, response.exit_code);
}

#[test]
fn status_response_roundtrip_failed() {
    let content = std::fs::read_to_string(samples_dir().join("responses/status-failed.response.json")).unwrap();
    let response: StatusResponse = serde_json::from_str(&content).unwrap();

    assert_eq!(response.status, unigetui_broker::model::OperationStatus::Failed);
    assert_eq!(response.exit_code, Some(1));
    assert!(response.note.as_deref().unwrap().contains("code 1"));
}

#[test]
fn status_response_roundtrip_timeout() {
    let content = std::fs::read_to_string(samples_dir().join("responses/status-timeout.response.json")).unwrap();
    let response: StatusResponse = serde_json::from_str(&content).unwrap();

    assert_eq!(response.status, unigetui_broker::model::OperationStatus::Failed);
    assert_eq!(response.exit_code, None);
    assert!(response.note.as_deref().unwrap().contains("timed out"));
}

#[test]
fn status_request_rejects_wrong_request_type() {
    let json = r#"{
        "$schema": "https://aka.ms/unigetui/package-operation-status-request.schema.1.0.json",
        "RequestVersion": "1.0.0",
        "RequestType": "PackageOperation",
        "RequestId": "req-123",
        "Broker": { "RequestedElevation": "Elevated", "EffectiveUser": "USER" }
    }"#;
    let result = serde_json::from_str::<StatusRequest>(json);
    assert!(result.is_err(), "should reject wrong requestType");
}

#[test]
fn status_request_rejects_wrong_schema_uri() {
    let json = r#"{
        "$schema": "https://aka.ms/unigetui/package-request.schema.1.0.json",
        "RequestVersion": "1.0.0",
        "RequestType": "PackageOperationStatus",
        "RequestId": "req-123",
        "Broker": { "RequestedElevation": "Elevated", "EffectiveUser": "USER" }
    }"#;
    let result = serde_json::from_str::<StatusRequest>(json);
    assert!(result.is_err(), "should reject wrong schema URI");
}

#[test]
fn status_request_rejects_unknown_fields() {
    let json = r#"{
        "$schema": "https://aka.ms/unigetui/package-operation-status-request.schema.1.0.json",
        "RequestVersion": "1.0.0",
        "RequestType": "PackageOperationStatus",
        "RequestId": "req-123",
        "Broker": { "RequestedElevation": "Elevated", "EffectiveUser": "USER" },
        "ExtraField": true
    }"#;
    let result = serde_json::from_str::<StatusRequest>(json);
    assert!(result.is_err(), "should reject unknown fields");
}
