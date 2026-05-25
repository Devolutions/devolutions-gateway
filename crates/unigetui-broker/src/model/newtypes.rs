//! Schema-validated string newtypes.

use schemars::JsonSchema;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::{InstanceType, Schema, SchemaObject, SingleOrVec, StringValidation};
use serde::{Deserialize, Serialize};

use super::ModelValidationError;

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
        "semanticVersion".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// ResourceId
// ═══════════════════════════════════════════════════════════════════════════════

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
        "resourceId".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// RuleId
// ═══════════════════════════════════════════════════════════════════════════════

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
        "ruleId".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// HttpUrl
// ═══════════════════════════════════════════════════════════════════════════════

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
        "httpUrl".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// PackageIdentifier
// ═══════════════════════════════════════════════════════════════════════════════

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
        "packageIdentifier".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// StringPattern
// ═══════════════════════════════════════════════════════════════════════════════

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
        "stringPattern".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// ProtocolVersion
// ═══════════════════════════════════════════════════════════════════════════════

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
        "protocolVersion".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// VersionString
// ═══════════════════════════════════════════════════════════════════════════════

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
        "versionString".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// CustomParameterString
// ═══════════════════════════════════════════════════════════════════════════════

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
        "customParameterString".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// ProcessName
// ═══════════════════════════════════════════════════════════════════════════════

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
        "processName".to_owned()
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

// ═══════════════════════════════════════════════════════════════════════════════
// CommandString
// ═══════════════════════════════════════════════════════════════════════════════

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

impl JsonSchema for CommandString {
    fn schema_name() -> String {
        "commandString".to_owned()
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
