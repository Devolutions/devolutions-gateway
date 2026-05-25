//! Schema generation using `schemars`.
//!
//! Generates JSON schemas from the Rust type definitions for export and diagnostics.
//! Runtime validation is performed by the type system itself during deserialization.

use schemars::schema_for;

use crate::models::{BrokerResponse, PackageRequest, PolicyDocument};

/// Get the generated policy schema as a JSON value (for diagnostics/export).
pub fn policy_schema_json() -> serde_json::Value {
    let schema = schema_for!(PolicyDocument);
    serde_json::to_value(&schema).expect("BUG: schema serialization failed")
}

/// Get the generated request schema as a JSON value (for diagnostics/export).
pub fn request_schema_json() -> serde_json::Value {
    let schema = schema_for!(PackageRequest);
    serde_json::to_value(&schema).expect("BUG: schema serialization failed")
}

/// Get the generated response schema as a JSON value (for diagnostics/export).
pub fn response_schema_json() -> serde_json::Value {
    let schema = schema_for!(BrokerResponse);
    serde_json::to_value(&schema).expect("BUG: schema serialization failed")
}

/// Validate a policy document by deserializing from a JSON value.
///
/// Returns the typed struct on success, or a descriptive error on failure.
pub fn parse_policy(value: serde_json::Value) -> Result<PolicyDocument, String> {
    serde_json::from_value(value).map_err(|e| e.to_string())
}

/// Validate a request by deserializing from a JSON value.
///
/// Returns the typed struct on success, or a descriptive error on failure.
pub fn parse_request(value: serde_json::Value) -> Result<PackageRequest, String> {
    serde_json::from_value(value).map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn policy_schema_generates_valid_json() {
        let schema = policy_schema_json();
        assert!(schema.is_object());
        let obj = schema.as_object().unwrap();
        assert!(
            obj.contains_key("definitions") || obj.contains_key("$defs"),
            "schema should have type definitions"
        );
    }

    #[test]
    fn request_schema_generates_valid_json() {
        let schema = request_schema_json();
        assert!(schema.is_object());
    }

    #[test]
    fn valid_policy_deserializes_successfully() {
        let policy_json = serde_json::json!({
            "$schema": "https://aka.ms/unigetui/package-policy.schema.1.0.json",
            "policyVersion": "1.0.0",
            "policyType": "packageBrokerPolicy",
            "metadata": {
                "id": "test-policy-1",
                "publisher": "Test Corp",
                "revision": 1,
                "publishedAt": "2025-01-01T00:00:00Z"
            },
            "enforcement": {
                "defaultDecision": "deny",
                "failureDecision": "deny",
                "rulePrecedence": "priorityThenDeny"
            },
            "rules": [{
                "id": "allow-firefox",
                "priority": 100,
                "decision": "allow",
                "match": {
                    "operations": ["install"],
                    "managers": ["Winget"],
                    "packageIdentifiers": ["Mozilla.Firefox"]
                }
            }]
        });

        parse_policy(policy_json).unwrap();
    }

    #[test]
    fn invalid_policy_fails_deserialization() {
        // Missing required fields.
        let bad_policy = serde_json::json!({
            "policyVersion": "1.0.0"
        });

        let result = parse_policy(bad_policy);
        assert!(result.is_err());
    }

    #[test]
    fn valid_request_deserializes_successfully() {
        let request_json = serde_json::json!({
            "$schema": "https://aka.ms/unigetui/package-request.schema.1.0.json",
            "requestVersion": "1.0.0",
            "requestType": "packageOperation",
            "requestId": "req-001",
            "createdAt": "2025-01-01T00:00:00Z",
            "operation": "install",
            "manager": {
                "name": "Winget",
                "displayName": "WinGet",
                "executableFriendlyName": "winget"
            },
            "source": {
                "name": "winget"
            },
            "package": {
                "id": "Mozilla.Firefox",
                "name": "Firefox"
            },
            "options": {
                "interactive": false,
                "runAsAdministrator": false,
                "skipHashCheck": false,
                "preRelease": false
            },
            "broker": {
                "requestedElevation": "elevated",
                "effectiveUser": "DOMAIN\\user"
            }
        });

        parse_request(request_json).unwrap();
    }

    #[test]
    fn invalid_request_missing_package_id_fails() {
        let bad_request = serde_json::json!({
            "requestVersion": "1.0.0",
            "requestType": "packageOperation",
            "requestId": "req-001",
            "createdAt": "2025-01-01T00:00:00Z",
            "operation": "install",
            "manager": {
                "name": "Winget",
                "displayName": "WinGet",
                "executableFriendlyName": "winget"
            },
            "source": { "name": "winget" },
            "package": { "id": "", "name": "X" },
            "options": {
                "interactive": false,
                "runAsAdministrator": false,
                "skipHashCheck": false,
                "preRelease": false
            },
            "broker": {
                "requestedElevation": "elevated",
                "effectiveUser": "user"
            }
        });

        let result = parse_request(bad_request);
        assert!(result.is_err(), "empty package ID should fail validation");
    }

    #[test]
    fn invalid_semver_fails_deserialization() {
        let bad_request = serde_json::json!({
            "requestVersion": "not-a-version",
            "requestType": "packageOperation",
            "requestId": "req-001",
            "createdAt": "2025-01-01T00:00:00Z",
            "operation": "install",
            "manager": {
                "name": "Winget",
                "displayName": "WinGet",
                "executableFriendlyName": "winget"
            },
            "source": { "name": "winget" },
            "package": { "id": "X.Y", "name": "X" },
            "options": {
                "interactive": false,
                "runAsAdministrator": false,
                "skipHashCheck": false,
                "preRelease": false
            },
            "broker": {
                "requestedElevation": "elevated",
                "effectiveUser": "user"
            }
        });

        let result = parse_request(bad_request);
        assert!(result.is_err(), "invalid semver should fail");
    }

    #[test]
    fn invalid_operation_enum_fails_deserialization() {
        let bad_request = serde_json::json!({
            "requestVersion": "1.0.0",
            "requestType": "packageOperation",
            "requestId": "req-001",
            "createdAt": "2025-01-01T00:00:00Z",
            "operation": "destroy",
            "manager": {
                "name": "Winget",
                "displayName": "WinGet",
                "executableFriendlyName": "winget"
            },
            "source": { "name": "winget" },
            "package": { "id": "X.Y", "name": "X" },
            "options": {
                "interactive": false,
                "runAsAdministrator": false,
                "skipHashCheck": false,
                "preRelease": false
            },
            "broker": {
                "requestedElevation": "elevated",
                "effectiveUser": "user"
            }
        });

        let result = parse_request(bad_request);
        assert!(result.is_err(), "invalid operation enum should fail");
    }
}
