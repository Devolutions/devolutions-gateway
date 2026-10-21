//! Parses agent request bodies, rejecting a member name repeated at any depth ([CONTRACT.agent-identity.md][contract], "1. Protocol conventions").
//! `serde_json::Value` keeps the last of repeated members, so it can't detect them alone.
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#1-protocol-conventions

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Parses `body` as JSON, failing on syntax errors and on a repeated member name in any object.
pub(crate) fn parse_unique_members(body: &[u8]) -> serde_json::Result<Value> {
    serde_json::from_slice::<UniqueMembers>(body).map(|parsed| parsed.0)
}

struct UniqueMembers(Value);

impl<'de> de::Deserialize<'de> for UniqueMembers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueMembersVisitor).map(UniqueMembers)
    }
}

struct UniqueMembersVisitor;

impl<'de> Visitor<'de> for UniqueMembersVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(UniqueMembers(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            let UniqueMembers(value) = map.next_value()?;
            if members.contains_key(&name) {
                return Err(de::Error::custom(format_args!("repeated member name {name:?}")));
            }
            members.insert(name, value);
        }
        Ok(Value::Object(members))
    }
}
