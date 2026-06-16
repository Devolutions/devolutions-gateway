//! Marker types -- zero-size structs that serialize to a fixed string constant.

use schemars::JsonSchema;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec};
use serde::{Deserialize, Serialize};

/// Marker type for policy type: serializes to `"PackageBrokerPolicy"`.
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
