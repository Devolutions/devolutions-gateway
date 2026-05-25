//! Data models for UniGetUI package broker protocol.
//!
//! These types are designed so that:
//! 1. They serialize/deserialize from/to JSON matching the wire protocol
//! 2. Deserialization performs full validation (length, pattern, URL/semver parsing)
//! 3. `schemars::JsonSchema` generates schemas close to the hand-authored ones in UniGetUI
//!
//! Reference schemas:
//! - `unigetui.package-request.schema.1.0.json`
//! - `unigetui.package-broker-response.schema.1.0.json`
//! - `unigetui.package-policy.schema.1.0.json`

// False positive: lint fires on schemars `schema_with = "fn_name"` attribute strings.
#![allow(unused_qualifications)]

pub mod enums;
pub mod markers;
pub mod newtypes;
pub mod policy;
pub mod request;
pub mod response;

/// Error returned when a newtype fails deserialization validation.
#[derive(Debug, thiserror::Error)]
pub enum ModelValidationError {
    #[error("{type_name}: {reason}")]
    Invalid { type_name: &'static str, reason: String },
}

// Re-export all public types at module root for convenience.
pub use enums::*;
pub use markers::*;
pub use newtypes::*;
pub use policy::*;
pub use request::*;
pub use response::*;
