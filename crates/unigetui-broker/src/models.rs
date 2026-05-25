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

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec, StringValidation};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════════
// Validation error
// ═══════════════════════════════════════════════════════════════════════════════

/// Error returned when a newtype fails deserialization validation.
#[derive(Debug, thiserror::Error)]
pub enum ModelValidationError {
    #[error("{type_name}: {reason}")]
    Invalid { type_name: &'static str, reason: String },
}

// ═══════════════════════════════════════════════════════════════════════════════
// Schema-validated string newtypes
// ═══════════════════════════════════════════════════════════════════════════════

/// Semantic version string (SemVer 2.0.0).
///
/// Validated at deserialization time using the `semver` crate.
/// Max length: 128
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SemanticVersion(pub String);

/// Regex pattern for SemVer 2.0.0 (used in JSON Schema generation only).
pub const SEMVER_PATTERN: &str = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$";

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

impl JsonSchema for SemanticVersion {
    fn schema_name() -> String {
        "SemanticVersion".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(128),
                min_length: None,
                pattern: Some(SEMVER_PATTERN.to_owned()),
            })),
            ..Default::default()
        }
        .into()
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

/// Resource identifier (policy IDs, rule IDs, request IDs, audit IDs).
///
/// Pattern: `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`
/// Max length: 128
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ResourceId(pub String);

pub const RESOURCE_ID_PATTERN: &str = r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$";

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
                reason: format!("does not match pattern {RESOURCE_ID_PATTERN}"),
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

impl JsonSchema for ResourceId {
    fn schema_name() -> String {
        "ResourceId".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(128),
                min_length: None,
                pattern: Some(RESOURCE_ID_PATTERN.to_owned()),
            })),
            ..Default::default()
        }
        .into()
    }
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

/// Rule ID in responses — includes special sentinel values.
///
/// Pattern: `^(<default>|<validation-failure>|[A-Za-z0-9][A-Za-z0-9._:-]{0,127})$`
/// Max length: 128
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RuleId(pub String);

pub const RULE_ID_PATTERN: &str = r"^(<default>|<validation-failure>|[A-Za-z0-9][A-Za-z0-9._:\-]{0,127})$";

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
                reason: format!("does not match pattern {RULE_ID_PATTERN}"),
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

impl JsonSchema for RuleId {
    fn schema_name() -> String {
        "RuleId".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(128),
                min_length: None,
                pattern: Some(RULE_ID_PATTERN.to_owned()),
            })),
            ..Default::default()
        }
        .into()
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

/// HTTP(S) URL string.
///
/// Validated at deserialization time using the `url` crate.
/// Max length: 2048
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HttpUrl(pub String);

pub const HTTP_URL_PATTERN: &str = r"^([Hh][Tt][Tt][Pp][Ss]?)://.+$";

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

impl JsonSchema for HttpUrl {
    fn schema_name() -> String {
        "HttpUrl".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(2048),
                min_length: None,
                pattern: Some(HTTP_URL_PATTERN.to_owned()),
            })),
            ..Default::default()
        }
        .into()
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

/// Package identifier string.
///
/// Must not contain `\/:*?"<>|` or control characters.
/// Min length: 1, Max length: 256
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct PackageIdentifier(pub String);

pub const PACKAGE_ID_PATTERN: &str = r#"^[^\/:*?"<>|\x01-\x1f]+$"#;

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

impl JsonSchema for PackageIdentifier {
    fn schema_name() -> String {
        "PackageIdentifier".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(256),
                min_length: Some(1),
                pattern: Some(PACKAGE_ID_PATTERN.to_owned()),
            })),
            ..Default::default()
        }
        .into()
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

/// Case-insensitive exact value or wildcard pattern.
///
/// Min length: 1, Max length: 256
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct StringPattern(pub String);

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

impl JsonSchema for StringPattern {
    fn schema_name() -> String {
        "StringPattern".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(256),
                min_length: Some(1),
                pattern: None,
            })),
            ..Default::default()
        }
        .into()
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

/// Protocol version string (e.g. "1.0").
///
/// Pattern: `^[0-9]+\.[0-9]+$`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ProtocolVersion(pub String);

pub const PROTOCOL_VERSION_PATTERN: &str = r"^[0-9]+\.[0-9]+$";

impl ProtocolVersion {
    /// Parse and validate a protocol version string.
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        if !is_valid_protocol_version(s) {
            return Err(ModelValidationError::Invalid {
                type_name: "ProtocolVersion",
                reason: format!("does not match pattern {PROTOCOL_VERSION_PATTERN}"),
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

impl JsonSchema for ProtocolVersion {
    fn schema_name() -> String {
        "ProtocolVersion".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: None,
                min_length: None,
                pattern: Some(PROTOCOL_VERSION_PATTERN.to_owned()),
            })),
            ..Default::default()
        }
        .into()
    }
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

/// A short constrained string for version values (max 128 chars).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct VersionString(pub String);

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

impl JsonSchema for VersionString {
    fn schema_name() -> String {
        "VersionString".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(128),
                min_length: Some(1),
                pattern: None,
            })),
            ..Default::default()
        }
        .into()
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

/// A custom parameter string (max 512 chars).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CustomParameterString(pub String);

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

impl JsonSchema for CustomParameterString {
    fn schema_name() -> String {
        "CustomParameterString".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(512),
                min_length: Some(1),
                pattern: None,
            })),
            ..Default::default()
        }
        .into()
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

/// A process name string (max 128 chars).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ProcessName(pub String);

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

impl JsonSchema for ProcessName {
    fn schema_name() -> String {
        "ProcessName".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(128),
                min_length: Some(1),
                pattern: None,
            })),
            ..Default::default()
        }
        .into()
    }
}

impl std::ops::Deref for ProcessName {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// A command string (max 2048 chars).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CommandString(pub String);

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

// ═══════════════════════════════════════════════════════════════════════════════
// Shared validation helper
// ═══════════════════════════════════════════════════════════════════════════════

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

impl JsonSchema for CommandString {
    fn schema_name() -> String {
        "CommandString".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                max_length: Some(2048),
                min_length: Some(1),
                pattern: None,
            })),
            ..Default::default()
        }
        .into()
    }
}

impl std::ops::Deref for CommandString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared enumerations
// ═══════════════════════════════════════════════════════════════════════════════

/// Package operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Install,
    Update,
    Uninstall,
}

/// Package installation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Machine,
}

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86,
    X64,
    Arm32,
    Arm64,
    Neutral,
}

/// Supported package manager names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub enum ManagerName {
    Winget,
    PowerShell,
}

/// Policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

/// Requested elevation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Elevation {
    Standard,
    Elevated,
}

/// Broker transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    HttpNamedPipe,
    HttpLoopbackSimulator,
}

/// Execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    SimulatedElevated,
    Elevated,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Marker types — zero-size structs that serialize to a fixed string constant
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
        "PackageOperation".to_owned()
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
        "PackageBrokerPolicy".to_owned()
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
        "PackageBrokerResponse".to_owned()
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
// Request models
// ═══════════════════════════════════════════════════════════════════════════════

/// Canonical request sent by an unelevated UniGetUI process to the elevated broker.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PackageRequest {
    /// Request schema URI constant.
    #[serde(rename = "$schema")]
    pub schema: RequestSchemaUri,

    /// The request syntax version (semver).
    pub request_version: SemanticVersion,

    /// Must be `"packageOperation"`.
    pub request_type: PackageOperation,

    /// Unique client-generated request id for audit correlation.
    pub request_id: ResourceId,

    /// UTC timestamp when the client created the request (RFC 3339).
    pub created_at: DateTime<Utc>,

    /// The package operation to perform.
    pub operation: Operation,

    /// Package manager information.
    pub manager: RequestManager,

    /// Source/repository information.
    pub source: RequestSource,

    /// Package information.
    pub package: RequestPackage,

    /// Operation options.
    pub options: RequestOptions,

    /// Broker context from the client.
    pub broker: BrokerContext,
}

/// Package manager metadata from the request.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestManager {
    /// Package manager name.
    pub name: ManagerName,

    /// Human-readable display name.
    #[schemars(length(min = 1, max = 128))]
    pub display_name: String,

    /// Friendly name of the manager executable.
    #[schemars(length(min = 1, max = 128))]
    pub executable_friendly_name: String,
}

/// Source/repository metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestSource {
    /// Source name (e.g., "winget", "msstore").
    #[schemars(length(min = 1, max = 128))]
    pub name: String,

    /// Source URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<HttpUrl>,

    /// Whether this is a virtual manager source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_virtual_manager: Option<bool>,
}

/// Package identification.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestPackage {
    /// Package identifier (e.g., "Publisher.Package" for WinGet).
    pub id: PackageIdentifier,

    /// Human-readable package name.
    #[schemars(length(min = 1, max = 256))]
    pub name: String,

    /// Currently installed version (for update/uninstall).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<SemanticVersion>,

    /// Target version (for update operations).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_version: Option<SemanticVersion>,

    /// Release channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 16))]
    pub channel: Option<String>,
}

/// Options controlling the package operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestOptions {
    /// Installation scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,

    /// Target architecture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<Architecture>,

    /// Requested install version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<SemanticVersion>,

    /// Run interactively (show installer UI).
    pub interactive: bool,

    /// Run the process as administrator.
    pub run_as_administrator: bool,

    /// Skip package hash verification.
    pub skip_hash_check: bool,

    /// Allow pre-release versions.
    pub pre_release: bool,

    /// Custom install directory path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub custom_install_location: Option<String>,

    /// Additional command-line parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub custom_parameters: Vec<CustomParameterString>,

    /// Command to execute before the package operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub pre_operation_command: Option<String>,

    /// Command to execute after the package operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub post_operation_command: Option<String>,

    /// Processes to kill before running the operation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub kill_before_operation: Vec<ProcessName>,
}

/// Broker context provided by the client.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerContext {
    /// Elevation level requested.
    pub requested_elevation: Elevation,

    /// Windows identity of the calling user.
    #[schemars(length(min = 1, max = 256))]
    pub effective_user: String,

    /// Version of the UniGetUI client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub client_version: Option<String>,

    /// File path of the client process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub client_process_path: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Response models
// ═══════════════════════════════════════════════════════════════════════════════

/// Canonical response returned by the broker after evaluating a request.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerResponse {
    /// Response schema URI constant.
    #[serde(rename = "$schema")]
    pub schema: ResponseSchemaUri,

    /// Response syntax version (semver).
    pub response_version: SemanticVersion,

    /// Must be `"packageBrokerResponse"`.
    pub response_type: PackageBrokerResponse,

    /// Broker identity and capabilities.
    pub broker: BrokerInfo,

    /// Server-generated audit identifier.
    pub audit_id: ResourceId,

    /// Echoed request id.
    pub request_id: ResourceId,

    /// UTC timestamp when broker received the request (RFC 3339).
    pub received_at: DateTime<Utc>,

    /// UTC timestamp when broker completed evaluation (RFC 3339).
    pub completed_at: DateTime<Utc>,

    /// Manager name from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    pub manager: Option<String>,

    /// Source name from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    pub source: Option<String>,

    /// Package identifier from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_id: Option<PackageIdentifier>,

    /// Operation from the request (null if not parsed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,

    /// The evaluation decision.
    pub decision: Decision,

    /// The rule that produced the decision.
    pub rule_id: RuleId,

    /// Human-readable reason for the decision.
    #[schemars(length(min = 1, max = 2048))]
    pub reason: String,

    /// Whether the broker would execute a command for this decision.
    pub would_execute: bool,

    /// Summary of the policy used.
    pub policy: ResponsePolicyInfo,

    /// Execution details.
    pub execution: ExecutionInfo,
}

/// Broker identity information in responses.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BrokerInfo {
    /// Broker display name.
    #[schemars(length(min = 1, max = 128))]
    pub name: String,

    /// Protocol version (e.g., "1.0").
    pub protocol_version: ProtocolVersion,

    /// Transport mechanism.
    pub transport: Transport,

    /// Named pipe path (when transport is http-named-pipe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    pub pipe_name: Option<String>,

    /// Whether the broker is running in simulated elevation mode.
    pub elevated_simulation: bool,
}

/// Summary of policy used for the decision.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ResponsePolicyInfo {
    /// Policy document identifier.
    pub id: ResourceId,

    /// Policy revision number.
    #[schemars(range(min = 1, max = 2147483647))]
    pub revision: u32,

    /// Policy syntax version.
    pub policy_version: SemanticVersion,
}

/// Execution outcome details.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ExecutionInfo {
    /// Execution mode.
    pub mode: ExecutionMode,

    /// Command that was or would be executed.
    #[schemars(length(max = 256))]
    pub command: Vec<CommandString>,

    /// Additional note about execution.
    #[schemars(length(min = 1, max = 2048))]
    pub note: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Policy models
// ═══════════════════════════════════════════════════════════════════════════════

/// A policy document governing which package operations are allowed or denied.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Policy schema URI constant.
    #[serde(rename = "$schema")]
    pub schema: PolicySchemaUri,

    /// Policy syntax version (semver).
    pub policy_version: SemanticVersion,

    /// Must be `"packageBrokerPolicy"`.
    pub policy_type: PackageBrokerPolicy,

    /// Policy metadata.
    pub metadata: PolicyMetadata,

    /// Enforcement configuration.
    pub enforcement: PolicyEnforcement,

    /// Ordered list of policy rules (may be empty; enforcement defaults apply).
    #[schemars(length(max = 1024))]
    pub rules: Vec<PolicyRule>,
}

/// Policy metadata.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyMetadata {
    /// Unique policy identifier.
    pub id: ResourceId,

    /// Organization that published the policy.
    #[schemars(length(min = 1, max = 128))]
    pub publisher: String,

    /// Monotonically increasing revision number.
    #[schemars(range(min = 1, max = 2147483647))]
    pub revision: u32,

    /// ISO 8601 publication timestamp (RFC 3339).
    pub published_at: DateTime<Utc>,

    /// Policy becomes active at this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,

    /// Policy expires at this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 512))]
    pub description: Option<String>,

    /// URL for support or documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_url: Option<HttpUrl>,
}

/// Enforcement configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyEnforcement {
    /// Decision when no rule matches.
    pub default_decision: Decision,

    /// Decision on validation/parsing failure (must be "deny").
    pub failure_decision: FailureDecision,

    /// Rule precedence strategy (must be "priorityThenDeny").
    pub rule_precedence: RulePrecedence,

    /// When true, broker logs decisions but does not enforce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_mode: Option<bool>,
}

/// Failure decision — always deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum FailureDecision {
    #[serde(rename = "deny")]
    Deny,
}

/// Rule precedence strategy — always priorityThenDeny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum RulePrecedence {
    #[serde(rename = "priorityThenDeny")]
    PriorityThenDeny,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Unique rule identifier.
    pub id: ResourceId,

    /// Whether the rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Priority (lower = higher precedence).
    #[schemars(range(min = 0, max = 2147483647))]
    pub priority: u32,

    /// Decision if this rule matches.
    pub decision: Decision,

    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 512))]
    pub description: Option<String>,

    /// Reason reported to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 512))]
    pub reason: Option<String>,

    /// Match criteria — request must satisfy all specified fields.
    /// At least one criterion must be present.
    #[serde(rename = "match", deserialize_with = "deserialize_non_empty_match")]
    pub match_criteria: PolicyMatch,

    /// Additional constraints applied after matching.
    /// When absent, no constraints are enforced beyond the match criteria.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<PolicyConstraints>,
}

fn default_true() -> bool {
    true
}

/// Custom deserializer that rejects an empty match block.
fn deserialize_non_empty_match<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<PolicyMatch, D::Error> {
    let m = PolicyMatch::deserialize(deserializer)?;
    if m.is_empty() {
        return Err(serde::de::Error::custom("match must contain at least one criterion"));
    }
    Ok(m)
}

/// Match criteria for a policy rule. All specified fields must match.
/// At least one field must be present.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyMatch {
    /// Allowed operations.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 3))]
    pub operations: BTreeSet<Operation>,

    /// Allowed managers.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 16))]
    pub managers: BTreeSet<ManagerName>,

    /// Source patterns (wildcard).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 128))]
    pub sources: BTreeSet<StringPattern>,

    /// Package identifier patterns (wildcard).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 1024))]
    pub package_identifiers: BTreeSet<StringPattern>,

    /// Package name patterns (wildcard).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 1024))]
    pub package_names: BTreeSet<StringPattern>,

    /// Exact version list.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 256))]
    pub versions: BTreeSet<VersionString>,

    /// Semantic version range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_range: Option<VersionRange>,

    /// Allowed scopes.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub scopes: BTreeSet<Scope>,

    /// Allowed architectures.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 5))]
    pub architectures: BTreeSet<Architecture>,

    /// Allowed elevation levels.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub elevation: BTreeSet<Elevation>,

    /// Allowed runAsAdministrator values.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub run_as_administrator: BTreeSet<bool>,

    /// Allowed interactive values.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub interactive: BTreeSet<bool>,

    /// Allowed skipHashCheck values.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub skip_hash_check: BTreeSet<bool>,

    /// Allowed preRelease values.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub pre_release: BTreeSet<bool>,

    /// Whether request has custom parameters.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub has_custom_parameters: BTreeSet<bool>,

    /// Whether request has custom install location.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub has_custom_install_location: BTreeSet<bool>,

    /// Whether request has pre/post operation commands.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub has_pre_post_commands: BTreeSet<bool>,

    /// Whether request has kill-before-operation entries.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(length(max = 2))]
    pub has_kill_before_operation: BTreeSet<bool>,
}

impl PolicyMatch {
    /// Returns true if no criteria are specified.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
            && self.managers.is_empty()
            && self.sources.is_empty()
            && self.package_identifiers.is_empty()
            && self.package_names.is_empty()
            && self.versions.is_empty()
            && self.version_range.is_none()
            && self.scopes.is_empty()
            && self.architectures.is_empty()
            && self.elevation.is_empty()
            && self.run_as_administrator.is_empty()
            && self.interactive.is_empty()
            && self.skip_hash_check.is_empty()
            && self.pre_release.is_empty()
            && self.has_custom_parameters.is_empty()
            && self.has_custom_install_location.is_empty()
            && self.has_pre_post_commands.is_empty()
            && self.has_kill_before_operation.is_empty()
    }
}

/// Semantic version range for matching.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    /// Minimum version (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub min_version: Option<String>,

    /// Maximum version (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub max_version: Option<String>,

    /// Whether to include pre-release versions.
    #[serde(default)]
    pub include_prerelease: bool,
}

/// Constraints applied after a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct PolicyConstraints {
    /// Allow interactive mode.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_interactive: bool,

    /// Allow running as administrator.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_run_as_administrator: bool,

    /// Allow skipping hash verification.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_skip_hash_check: bool,

    /// Allow pre-release versions.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_pre_release: bool,

    /// Allow custom install location.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_custom_install_location: bool,

    /// Glob patterns for allowed install locations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub allowed_install_location_patterns: Vec<StringPattern>,

    /// Allow custom parameters.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_custom_parameters: bool,

    /// Exact allowed custom parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 128))]
    pub allowed_custom_parameters: Vec<CustomParameterString>,

    /// Glob patterns for allowed custom parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 128))]
    pub allowed_custom_parameter_patterns: Vec<CustomParameterString>,

    /// Denied custom parameters (deny takes precedence over allow).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 128))]
    pub denied_custom_parameters: Vec<CustomParameterString>,

    /// Allow pre/post operation commands.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_pre_post_commands: bool,

    /// Allow killing processes before operation.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_kill_before_operation: bool,
}

impl Default for PolicyConstraints {
    fn default() -> Self {
        Self {
            allow_interactive: true,
            allow_run_as_administrator: true,
            allow_skip_hash_check: true,
            allow_pre_release: true,
            allow_custom_install_location: true,
            allowed_install_location_patterns: Vec::new(),
            allow_custom_parameters: true,
            allowed_custom_parameters: Vec::new(),
            allowed_custom_parameter_patterns: Vec::new(),
            denied_custom_parameters: Vec::new(),
            allow_pre_post_commands: true,
            allow_kill_before_operation: true,
        }
    }
}

impl PolicyConstraints {
    /// Returns true if all fields are at their defaults (fully permissive).
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

fn is_true(v: &bool) -> bool {
    *v
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper types for evaluation
// ═══════════════════════════════════════════════════════════════════════════════

/// Derived boolean flags from a request, used for policy matching.
pub struct RequestFlags {
    pub has_custom_parameters: bool,
    pub has_custom_install_location: bool,
    pub has_pre_post_commands: bool,
    pub has_kill_before_operation: bool,
    pub custom_parameters: Vec<CustomParameterString>,
    pub custom_install_location: String,
}

impl RequestFlags {
    pub fn from_request(request: &PackageRequest) -> Self {
        let custom_params = request.options.custom_parameters.clone();
        let custom_location = request.options.custom_install_location.clone().unwrap_or_default();
        let has_pre_post =
            request.options.pre_operation_command.is_some() || request.options.post_operation_command.is_some();
        let kill_before = &request.options.kill_before_operation;

        Self {
            has_custom_parameters: !custom_params.is_empty(),
            has_custom_install_location: !custom_location.is_empty(),
            has_pre_post_commands: has_pre_post,
            has_kill_before_operation: !kill_before.is_empty(),
            custom_parameters: custom_params,
            custom_install_location: custom_location,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Display implementations for enums (used in logging/responses)
// ═══════════════════════════════════════════════════════════════════════════════

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Install => f.write_str("install"),
            Self::Update => f.write_str("update"),
            Self::Uninstall => f.write_str("uninstall"),
        }
    }
}

impl std::fmt::Display for ManagerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Winget => f.write_str("Winget"),
            Self::PowerShell => f.write_str("PowerShell"),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => f.write_str("user"),
            Self::Machine => f.write_str("machine"),
        }
    }
}

impl std::fmt::Display for Elevation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => f.write_str("standard"),
            Self::Elevated => f.write_str("elevated"),
        }
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => f.write_str("x86"),
            Self::X64 => f.write_str("x64"),
            Self::Arm32 => f.write_str("arm32"),
            Self::Arm64 => f.write_str("arm64"),
            Self::Neutral => f.write_str("neutral"),
        }
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimulatedElevated => f.write_str("simulated-elevated"),
            Self::Elevated => f.write_str("elevated"),
        }
    }
}
