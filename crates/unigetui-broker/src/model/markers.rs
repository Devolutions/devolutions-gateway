//! Marker types — zero-size structs that serialize to a fixed string constant.

use schemars::JsonSchema;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════════
// PackageOperation
// ═══════════════════════════════════════════════════════════════════════════════

/// Marker type for request type: serializes to `"packageOperation"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageOperation;

impl Serialize for PackageOperation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("packageOperation")
    }
}

impl<'de> Deserialize<'de> for PackageOperation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "packageOperation" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"packageOperation\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PackageOperation {
    fn schema_name() -> String {
        "packageOperation".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String("packageOperation".to_owned())]),
            ..Default::default()
        }
        .into()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PackageBrokerPolicy
// ═══════════════════════════════════════════════════════════════════════════════

/// Marker type for policy type: serializes to `"packageBrokerPolicy"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageBrokerPolicy;

impl Serialize for PackageBrokerPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("packageBrokerPolicy")
    }
}

impl<'de> Deserialize<'de> for PackageBrokerPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "packageBrokerPolicy" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"packageBrokerPolicy\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PackageBrokerPolicy {
    fn schema_name() -> String {
        "packageBrokerPolicy".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String("packageBrokerPolicy".to_owned())]),
            ..Default::default()
        }
        .into()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PackageBrokerResponse
// ═══════════════════════════════════════════════════════════════════════════════

/// Marker type for response type: serializes to `"packageBrokerResponse"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageBrokerResponse;

impl Serialize for PackageBrokerResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("packageBrokerResponse")
    }
}

impl<'de> Deserialize<'de> for PackageBrokerResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "packageBrokerResponse" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"packageBrokerResponse\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PackageBrokerResponse {
    fn schema_name() -> String {
        "packageBrokerResponse".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String("packageBrokerResponse".to_owned())]),
            ..Default::default()
        }
        .into()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Schema URI markers
// ═══════════════════════════════════════════════════════════════════════════════

/// Schema URI for package request documents.
pub const REQUEST_SCHEMA_URI: &str = "https://aka.ms/unigetui/package-request.schema.1.0.json";

/// Marker type for the request `$schema` field.
/// Serializes to the canonical request schema URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestSchemaUri;

impl Serialize for RequestSchemaUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REQUEST_SCHEMA_URI)
    }
}

impl<'de> Deserialize<'de> for RequestSchemaUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == REQUEST_SCHEMA_URI {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"{REQUEST_SCHEMA_URI}\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for RequestSchemaUri {
    fn schema_name() -> String {
        "requestSchemaUri".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String(REQUEST_SCHEMA_URI.to_owned())]),
            ..Default::default()
        }
        .into()
    }
}

/// Schema URI for package broker response documents.
pub const RESPONSE_SCHEMA_URI: &str = "https://aka.ms/unigetui/package-broker-response.schema.1.0.json";

/// Marker type for the response `$schema` field.
/// Serializes to the canonical response schema URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseSchemaUri;

impl Serialize for ResponseSchemaUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(RESPONSE_SCHEMA_URI)
    }
}

impl<'de> Deserialize<'de> for ResponseSchemaUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == RESPONSE_SCHEMA_URI {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"{RESPONSE_SCHEMA_URI}\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for ResponseSchemaUri {
    fn schema_name() -> String {
        "responseSchemaUri".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String(RESPONSE_SCHEMA_URI.to_owned())]),
            ..Default::default()
        }
        .into()
    }
}

/// Schema URI for package policy documents.
pub const POLICY_SCHEMA_URI: &str = "https://aka.ms/unigetui/package-policy.schema.1.0.json";

/// Marker type for the policy `$schema` field.
/// Serializes to the canonical policy schema URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySchemaUri;

impl Serialize for PolicySchemaUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(POLICY_SCHEMA_URI)
    }
}

impl<'de> Deserialize<'de> for PolicySchemaUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == POLICY_SCHEMA_URI {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"{POLICY_SCHEMA_URI}\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PolicySchemaUri {
    fn schema_name() -> String {
        "policySchemaUri".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String(POLICY_SCHEMA_URI.to_owned())]),
            ..Default::default()
        }
        .into()
    }
}
