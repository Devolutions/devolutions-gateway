//! Schema-validated newtypes used by package broker policy documents.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Error returned when a policy newtype fails deserialization validation.
#[derive(Debug, thiserror::Error)]
pub enum ModelValidationError {
    #[error("{type_name}: {reason}")]
    Invalid { type_name: &'static str, reason: String },
}

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
    pub fn parse(s: &str) -> Result<Self, ModelValidationError> {
        if s.len() > 128 {
            return Err(ModelValidationError::Invalid {
                type_name: "SemanticVersion",
                reason: format!("length {} exceeds maximum 128", s.len()),
            });
        }

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

/// Resource identifier (policy IDs, rule IDs, request IDs, audit IDs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct ResourceId(
    #[schemars(length(max = 128), regex(pattern = r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$"))] pub String,
);

impl ResourceId {
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

/// HTTP(S) URL string.
///
/// Validated at deserialization time using the `url` crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct HttpUrl(
    #[schemars(length(max = 2048), regex(pattern = r"^([Hh][Tt][Tt][Pp][Ss]?)://.+$"))]
    pub String,
);

impl HttpUrl {
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

/// Case-insensitive exact value or wildcard pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct StringPattern(#[schemars(length(min = 1, max = 256))] pub String);

impl StringPattern {
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

/// A short constrained string for version values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct VersionString(#[schemars(length(min = 1, max = 128))] pub String);

impl VersionString {
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

/// A custom parameter string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct CustomParameterString(#[schemars(length(min = 1, max = 512))] pub String);

impl CustomParameterString {
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
