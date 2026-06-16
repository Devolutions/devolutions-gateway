//! Marker types -- zero-size structs that serialize to a fixed string constant.

use schemars::JsonSchema;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec};
use serde::{Deserialize, Serialize};

macro_rules! fixed_string_marker {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident => $value:expr;
    ) => {
        $(#[$attr])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis struct $name;

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str($value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                if value == $value {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(format_args!(
                        "expected {:?}, got {:?}",
                        $value, value
                    )))
                }
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> String {
                stringify!($name).to_owned()
            }

            fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
                SchemaObject {
                    instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
                    enum_values: Some(vec![serde_json::Value::String($value.to_owned())]),
                    ..Default::default()
                }
                .into()
            }
        }
    };
}

fixed_string_marker! {
    /// Marker type for policy type: serializes to `"PackageBrokerPolicy"`.
    pub struct PackageBrokerPolicy => "PackageBrokerPolicy";
}

/// Schema URI for package policy documents.
pub const POLICY_SCHEMA_URI: &str = "https://aka.ms/unigetui/package-policy.schema.1.0.json";

fixed_string_marker! {
    /// Marker type for the policy `$schema` field.
    /// Serializes to the canonical policy schema URI.
    pub struct PolicySchemaUri => POLICY_SCHEMA_URI;
}
