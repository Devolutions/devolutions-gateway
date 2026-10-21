//! Parses agent request bodies, rejecting a member name repeated at any depth, more than [`MAX_NESTING`] nested
//! objects and arrays, and a string that is not valid Unicode ([CONTRACT.agent-identity.md][contract], "1. Protocol
//! conventions").
//! `serde_json::Value` keeps the last of repeated members, so it can't detect them alone, and its own nesting limit is
//! 128, but serde_json refuses invalid Unicode itself, whether raw or escaped as a lone surrogate.
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#1-protocol-conventions

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// The most objects and arrays a body may nest, counting the top-level one.
const MAX_NESTING: usize = 64;

/// Parses `body` as JSON, failing on syntax errors, on a string that is not valid Unicode, on a repeated member name in
/// any object, and on more than [`MAX_NESTING`] nested objects and arrays.
pub(crate) fn parse_request_body(body: &[u8]) -> serde_json::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = ValueSeed { enclosing: 0 }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// Deserializes one value that `enclosing` objects and arrays contain.
#[derive(Clone, Copy)]
struct ValueSeed {
    enclosing: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl ValueSeed {
    /// Returns the seed for the values inside the object or array that this seed's value opens.
    ///
    /// An object or array calls it on opening, before reading any member, because an empty one is nested too.
    fn nested<E: de::Error>(self) -> Result<Self, E> {
        let enclosing = self.enclosing + 1;
        if MAX_NESTING < enclosing {
            return Err(E::custom(format_args!(
                "more than {MAX_NESTING} nested objects and arrays"
            )));
        }
        Ok(Self { enclosing })
    }
}

impl<'de> Visitor<'de> for ValueSeed {
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
        let element = self.nested()?;
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(element)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let member = self.nested()?;
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            let value = map.next_value_seed(member)?;
            if members.contains_key(&name) {
                return Err(de::Error::custom(format_args!("repeated member name {name:?}")));
            }
            members.insert(name, value);
        }
        Ok(Value::Object(members))
    }
}
