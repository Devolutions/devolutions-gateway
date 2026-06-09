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
        serializer.serialize_str("PackageOperation")
    }
}

impl<'de> Deserialize<'de> for PackageOperation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "PackageOperation" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"PackageOperation\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PackageOperation {
    fn schema_name() -> String {
        "PackageOperation".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String("PackageOperation".to_owned())]),
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
        serializer.serialize_str("PackageBrokerPolicy")
    }
}

impl<'de> Deserialize<'de> for PackageBrokerPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "PackageBrokerPolicy" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"PackageBrokerPolicy\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PackageBrokerPolicy {
    fn schema_name() -> String {
        "PackageBrokerPolicy".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String("PackageBrokerPolicy".to_owned())]),
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
        serializer.serialize_str("PackageBrokerResponse")
    }
}

impl<'de> Deserialize<'de> for PackageBrokerResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "PackageBrokerResponse" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"PackageBrokerResponse\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PackageBrokerResponse {
    fn schema_name() -> String {
        "PackageBrokerResponse".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String("PackageBrokerResponse".to_owned())]),
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
        "RequestSchemaUri".to_owned()
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
        "ResponseSchemaUri".to_owned()
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
        "PolicySchemaUri".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// PackageOperationStatus (request type marker)
// ═══════════════════════════════════════════════════════════════════════════════

/// Marker type for status query request type: serializes to `"packageOperationStatus"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageOperationStatusType;

impl Serialize for PackageOperationStatusType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("PackageOperationStatus")
    }
}

impl<'de> Deserialize<'de> for PackageOperationStatusType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "PackageOperationStatus" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"PackageOperationStatus\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PackageOperationStatusType {
    fn schema_name() -> String {
        "PackageOperationStatus".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String("PackageOperationStatus".to_owned())]),
            ..Default::default()
        }
        .into()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PackageOperationStatusResponse (response type marker)
// ═══════════════════════════════════════════════════════════════════════════════

/// Marker type for status response type: serializes to `"packageOperationStatusResponse"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageOperationStatusResponse;

impl Serialize for PackageOperationStatusResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("PackageOperationStatusResponse")
    }
}

impl<'de> Deserialize<'de> for PackageOperationStatusResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "PackageOperationStatusResponse" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"PackageOperationStatusResponse\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for PackageOperationStatusResponse {
    fn schema_name() -> String {
        "PackageOperationStatusResponse".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String(
                "PackageOperationStatusResponse".to_owned(),
            )]),
            ..Default::default()
        }
        .into()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Status Schema URI markers
// ═══════════════════════════════════════════════════════════════════════════════

/// Schema URI for status request documents.
pub const STATUS_REQUEST_SCHEMA_URI: &str = "https://aka.ms/unigetui/package-operation-status-request.schema.1.0.json";

/// Marker type for the status request `$schema` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusRequestSchemaUri;

impl Serialize for StatusRequestSchemaUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(STATUS_REQUEST_SCHEMA_URI)
    }
}

impl<'de> Deserialize<'de> for StatusRequestSchemaUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == STATUS_REQUEST_SCHEMA_URI {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"{STATUS_REQUEST_SCHEMA_URI}\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for StatusRequestSchemaUri {
    fn schema_name() -> String {
        "StatusRequestSchemaUri".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String(STATUS_REQUEST_SCHEMA_URI.to_owned())]),
            ..Default::default()
        }
        .into()
    }
}

/// Schema URI for status response documents.
pub const STATUS_RESPONSE_SCHEMA_URI: &str =
    "https://aka.ms/unigetui/package-operation-status-response.schema.1.0.json";

/// Marker type for the status response `$schema` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusResponseSchemaUri;

impl Serialize for StatusResponseSchemaUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(STATUS_RESPONSE_SCHEMA_URI)
    }
}

impl<'de> Deserialize<'de> for StatusResponseSchemaUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == STATUS_RESPONSE_SCHEMA_URI {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"{STATUS_RESPONSE_SCHEMA_URI}\", got \"{s}\""
            )))
        }
    }
}

impl JsonSchema for StatusResponseSchemaUri {
    fn schema_name() -> String {
        "StatusResponseSchemaUri".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            enum_values: Some(vec![serde_json::Value::String(STATUS_RESPONSE_SCHEMA_URI.to_owned())]),
            ..Default::default()
        }
        .into()
    }
}
