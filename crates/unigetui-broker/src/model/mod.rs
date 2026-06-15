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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub mod api;
pub mod enums;
pub mod markers;
pub mod policy;
pub mod request;
pub mod response;
pub mod status;

/// Error returned when a newtype fails deserialization validation.
#[derive(Debug, thiserror::Error)]
pub enum ModelValidationError {
    #[error("{type_name}: {reason}")]
    Invalid { type_name: &'static str, reason: String },
}

// Re-export all public types at module root for convenience.
pub use api::*;
pub use enums::*;
pub use markers::*;
pub use policy::*;
pub use request::*;
pub use response::*;
pub use status::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Schema-validated string newtypes
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Shared validation helper ────────────────────────────────────────────────

/// Validate a string's length is within [min, max].
fn validate_bounded_string(
    s: &str,
    min: usize,
    max: usize,
    type_name: &'static str,
) -> Result<(), ModelValidationError> {
    if s.len() < min {
        return Err(ModelValidationError::Invalid {
            type_name,
            reason: format!("length {} is below minimum {min}", s.len()),
        });
    }
    if s.len() > max {
        return Err(ModelValidationError::Invalid {
            type_name,
            reason: format!("length {} exceeds maximum {max}", s.len()),
        });
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// SemanticVersion
// ═══════════════════════════════════════════════════════════════════════════════

/// Semantic version string (SemVer 2.0.0).
///
/// Validated at deserialization time using the `semver` crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct SemanticVersion(
    #[schemars(
        length(max = 128),
        regex(
            pattern = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
        )
    )]
    pub String,
);

impl SemanticVersion {
    /// Parse and validate a semantic version string.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        if s.len() > 128 {
            return Err(ModelValidationError::Invalid {
                type_name: "SemanticVersion",
                reason: format!("length {} exceeds maximum 128", s.len()),
            });
        }
        // Validate using the semver crate.
        semver::Version::parse(s).map_err(|e| ModelValidationError::Invalid {
            type_name: "SemanticVersion",
            reason: e.to_string(),
        })?;
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for SemanticVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for SemanticVersion {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for SemanticVersion {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SemanticVersion {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ResourceId
// ═══════════════════════════════════════════════════════════════════════════════

/// Resource identifier (policy IDs, rule IDs, request IDs, audit IDs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct ResourceId(
    #[schemars(length(max = 128), regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$"))] pub String,
);

impl ResourceId {
    /// Parse and validate a resource identifier.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        if s.len() > 128 {
            return Err(ModelValidationError::Invalid {
                type_name: "ResourceId",
                reason: format!("length {} exceeds maximum 128", s.len()),
            });
        }
        if !is_valid_resource_id(s) {
            return Err(ModelValidationError::Invalid {
                type_name: "ResourceId",
                reason:
                    "must start with an alphanumeric character and contain only letters, digits, '.', '_', ':' or '-'"
                        .to_owned(),
            });
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for ResourceId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Check if a string matches the resource ID pattern without regex.
fn is_valid_resource_id(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b':' || b == b'-')
}

impl std::ops::Deref for ResourceId {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ResourceId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ResourceId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RuleId
// ═══════════════════════════════════════════════════════════════════════════════

/// Rule ID in responses — includes special sentinel values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct RuleId(
    #[schemars(
        length(max = 128),
        regex(pattern = r"^(<default>|<validation-failure>|[A-Za-z0-9][A-Za-z0-9._:\-]{0,127})$")
    )]
    pub String,
);

impl RuleId {
    /// Parse and validate a rule ID.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        if s.len() > 128 {
            return Err(ModelValidationError::Invalid {
                type_name: "RuleId",
                reason: format!("length {} exceeds maximum 128", s.len()),
            });
        }
        if s == "<default>" || s == "<validation-failure>" || is_valid_resource_id(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(ModelValidationError::Invalid {
                type_name: "RuleId",
                reason: "must be '<default>', '<validation-failure>', or start with an alphanumeric character \
                         and contain only letters, digits, '.', '_', ':' or '-'"
                    .to_owned(),
            })
        }
    }
}

impl<'de> Deserialize<'de> for RuleId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for RuleId {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for RuleId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HttpUrl
// ═══════════════════════════════════════════════════════════════════════════════

/// HTTP(S) URL string.
///
/// Validated at deserialization time using the `url` crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct HttpUrl(
    #[schemars(length(max = 2048), regex(pattern = r"^([Hh][Tt][Tt][Pp][Ss]?)://.+$"))]
    pub String,
);

impl HttpUrl {
    /// Parse and validate an HTTP(S) URL.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        if s.len() > 2048 {
            return Err(ModelValidationError::Invalid {
                type_name: "HttpUrl",
                reason: format!("length {} exceeds maximum 2048", s.len()),
            });
        }
        let parsed = url::Url::parse(s).map_err(|e| ModelValidationError::Invalid {
            type_name: "HttpUrl",
            reason: e.to_string(),
        })?;
        match parsed.scheme() {
            "http" | "https" => Ok(Self(s.to_owned())),
            other => Err(ModelValidationError::Invalid {
                type_name: "HttpUrl",
                reason: format!("scheme must be http or https, got {other}"),
            }),
        }
    }
}

impl<'de> Deserialize<'de> for HttpUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for HttpUrl {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for HttpUrl {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PackageIdentifier
// ═══════════════════════════════════════════════════════════════════════════════

/// Package identifier string.
///
/// Must not contain `\/:*?"<>|` or control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct PackageIdentifier(
    #[schemars(length(min = 1, max = 256), regex(pattern = r#"^[^\/:*?"<>|\x01-\x1f]+$"#))] pub String,
);

impl PackageIdentifier {
    /// Parse and validate a package identifier.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        if s.is_empty() {
            return Err(ModelValidationError::Invalid {
                type_name: "PackageIdentifier",
                reason: "must not be empty".to_owned(),
            });
        }
        if s.len() > 256 {
            return Err(ModelValidationError::Invalid {
                type_name: "PackageIdentifier",
                reason: format!("length {} exceeds maximum 256", s.len()),
            });
        }
        if s.bytes().any(|b| {
            b == b'\\'
                || b == b'/'
                || b == b':'
                || b == b'*'
                || b == b'?'
                || b == b'"'
                || b == b'<'
                || b == b'>'
                || b == b'|'
                || (0x01..=0x1f).contains(&b)
        }) {
            return Err(ModelValidationError::Invalid {
                type_name: "PackageIdentifier",
                reason: "contains forbidden characters".to_owned(),
            });
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for PackageIdentifier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for PackageIdentifier {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PackageIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PackageIdentifier {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// StringPattern
// ═══════════════════════════════════════════════════════════════════════════════

/// Case-insensitive exact value or wildcard pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct StringPattern(#[schemars(length(min = 1, max = 256))] pub String);

impl StringPattern {
    /// Parse and validate a string pattern.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        validate_bounded_string(s, 1, 256, "StringPattern")?;
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for StringPattern {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for StringPattern {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for StringPattern {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StringPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ProtocolVersion
// ═══════════════════════════════════════════════════════════════════════════════

/// Protocol version string (e.g. "1.0").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ProtocolVersion(#[schemars(regex(pattern = r"^[0-9]+\.[0-9]+$"))] pub String);

impl ProtocolVersion {
    /// Parse and validate a protocol version string.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        if !is_valid_protocol_version(s) {
            return Err(ModelValidationError::Invalid {
                type_name: "ProtocolVersion",
                reason: "must be in the form '<major>.<minor>' with digits only (e.g. '1.0')".to_owned(),
            });
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Check if a string matches "digits.digits" without regex.
fn is_valid_protocol_version(s: &str) -> bool {
    let Some((major, minor)) = s.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
}

impl std::ops::Deref for ProtocolVersion {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ProtocolVersion {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VersionString
// ═══════════════════════════════════════════════════════════════════════════════

/// A short constrained string for version values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct VersionString(#[schemars(length(min = 1, max = 128))] pub String);

impl VersionString {
    /// Parse and validate a version string.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        validate_bounded_string(s, 1, 128, "VersionString")?;
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for VersionString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for VersionString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for VersionString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CustomParameterString
// ═══════════════════════════════════════════════════════════════════════════════

/// A custom parameter string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct CustomParameterString(#[schemars(length(min = 1, max = 512))] pub String);

impl CustomParameterString {
    /// Parse and validate a custom parameter string.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        validate_bounded_string(s, 1, 512, "CustomParameterString")?;
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for CustomParameterString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for CustomParameterString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CustomParameterString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ProcessName
// ═══════════════════════════════════════════════════════════════════════════════

/// A process name string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct ProcessName(#[schemars(length(min = 1, max = 128))] pub String);

impl ProcessName {
    /// Parse and validate a process name.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        validate_bounded_string(s, 1, 128, "ProcessName")?;
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for ProcessName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for ProcessName {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CommandString
// ═══════════════════════════════════════════════════════════════════════════════

/// A command string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CommandString(#[schemars(length(min = 1, max = 2048))] pub String);

impl CommandString {
    /// Parse and validate a command string.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        validate_bounded_string(s, 1, 2048, "CommandString")?;
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for CommandString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for CommandString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}
