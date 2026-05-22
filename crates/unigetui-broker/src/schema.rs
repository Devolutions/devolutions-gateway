//! Schema generation and validation using `schemars` + `jsonschema`.
//!
//! Generates JSON schemas from the Rust type definitions and uses them to validate
//! incoming policy documents and requests at runtime. This ensures validation logic
//! stays in sync with the type definitions automatically.

use jsonschema::Validator;
use schemars::schema_for;

use crate::models::{PackageRequest, PolicyDocument};

/// Compiled schema validators, built once at startup.
pub struct SchemaValidators {
    policy_validator: Validator,
    request_validator: Validator,
}

/// Error from schema validation.
#[derive(Debug, thiserror::Error)]
#[error("schema validation failed: {message}")]
pub struct ValidationError {
    pub message: String,
    pub errors: Vec<String>,
}

impl SchemaValidators {
    /// Build validators from the schemars-generated schemas.
    ///
    /// # Panics
    ///
    /// Panics if the generated schemas are not valid JSON Schema (programming bug).
    pub fn new() -> Self {
        let policy_schema = schema_for!(PolicyDocument);
        let policy_json =
            serde_json::to_value(&policy_schema).expect("BUG: generated policy schema is not serializable");
        let policy_validator =
            Validator::new(&policy_json).expect("BUG: generated policy schema is not a valid JSON Schema");

        let request_schema = schema_for!(PackageRequest);
        let request_json =
            serde_json::to_value(&request_schema).expect("BUG: generated request schema is not serializable");
        let request_validator =
            Validator::new(&request_json).expect("BUG: generated request schema is not a valid JSON Schema");

        Self {
            policy_validator,
            request_validator,
        }
    }

    /// Validate a policy document JSON value against the policy schema.
    pub fn validate_policy(&self, value: &serde_json::Value) -> Result<(), ValidationError> {
        validate_with(&self.policy_validator, value, "policy")
    }

    /// Validate a request JSON value against the request schema.
    pub fn validate_request(&self, value: &serde_json::Value) -> Result<(), ValidationError> {
        validate_with(&self.request_validator, value, "request")
    }

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
}

impl Default for SchemaValidators {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_with(validator: &Validator, value: &serde_json::Value, context: &str) -> Result<(), ValidationError> {
    if let Err(error) = validator.validate(value) {
        let message = format!("{context} validation failed: {error}");
        return Err(ValidationError {
            message,
            errors: vec![error.to_string()],
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn schema_validators_build_successfully() {
        let _validators = SchemaValidators::new();
    }

    #[test]
    fn policy_schema_generates_valid_json() {
        let schema = SchemaValidators::policy_schema_json();
        assert!(schema.is_object());
        // Should have a definitions or $defs section since we have nested types.
        let obj = schema.as_object().unwrap();
        assert!(
            obj.contains_key("definitions") || obj.contains_key("$defs"),
            "schema should have type definitions"
        );
    }

    #[test]
    fn request_schema_generates_valid_json() {
        let schema = SchemaValidators::request_schema_json();
        assert!(schema.is_object());
    }

    #[test]
    fn valid_policy_passes_validation() {
        let validators = SchemaValidators::new();
        let policy_json = serde_json::json!({
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

        validators.validate_policy(&policy_json).unwrap();
    }

    #[test]
    fn invalid_policy_fails_validation() {
        let validators = SchemaValidators::new();
        // Missing required fields.
        let bad_policy = serde_json::json!({
            "policyVersion": "1.0.0"
        });

        let result = validators.validate_policy(&bad_policy);
        assert!(result.is_err());
    }

    #[test]
    fn valid_request_passes_validation() {
        let validators = SchemaValidators::new();
        let request_json = serde_json::json!({
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

        validators.validate_request(&request_json).unwrap();
    }

    #[test]
    fn invalid_request_fails_validation() {
        let validators = SchemaValidators::new();
        // Invalid operation enum value.
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
            "package": { "id": "X", "name": "X" },
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

        let result = validators.validate_request(&bad_request);
        assert!(result.is_err());
    }
}
