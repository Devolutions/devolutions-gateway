use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::DateVersion;

/// Old gateway-written manifest format (v2026.1.0 and prior), supported for backward compatibility.
///
/// Example V1 JSON structure:
///
/// ```json
/// {
///     "Gateway":    { "TargetVersion": "1.2.3.4" },
///     "HubService": { "TargetVersion": "latest"  }
/// }
/// ```
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateManifestV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<ProductUpdateInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_service: Option<ProductUpdateInfo>,
}

// ── Shared value types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionSpecification {
    Latest,
    #[serde(untagged)]
    Specific(DateVersion),
}

impl fmt::Display for VersionSpecification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionSpecification::Latest => write!(f, "latest"),
            VersionSpecification::Specific(version) => write!(f, "{version}"),
        }
    }
}

impl std::str::FromStr for VersionSpecification {
    type Err = crate::DateVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("latest") {
            Ok(Self::Latest)
        } else {
            Ok(Self::Specific(s.parse()?))
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProductUpdateInfo {
    /// The version of the product to update to.
    pub target_version: VersionSpecification,
}

/// Minor version of the V2 manifest format written by the current build of the agent.
///
/// Increment this value when adding new fields to [`UpdateManifestV2`] or making other
/// backwards-compatible changes that the gateway should be aware of.
pub const UPDATE_MANIFEST_V2_MINOR_VERSION: u32 = 1;

pub fn default_schedule_window_start() -> u32 {
    7_200
}

/// Auto-update schedule for the Devolutions Agent, embedded in [`UpdateManifestV2`].
///
/// Written by the gateway via `POST /jet/update/schedule` and consumed by the agent,
/// which validates the values, applies them to the running scheduling loop, and persists them
/// to `agent.json`.
///
/// Additionally, Agent writes the current scheduler recorded in `agent.json`
/// so gateway can retrieve it back via `GET /jet/update/schedule` without needing to introduce
/// knowledge of agent's configuration file format on the gateway side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateSchedule {
    /// Enable periodic Devolutions Agent self-update checks.
    pub enabled: bool,

    /// Minimum interval between update checks, in seconds.
    ///
    /// 0 value has a special meaning of "only check once at `update_window_start`.
    #[serde(default)]
    pub interval: u64,

    /// Start of the maintenance window as seconds past midnight, local time.
    #[serde(default = "default_schedule_window_start")]
    pub update_window_start: u32,

    /// End of the maintenance window as seconds past midnight, local time, exclusive.
    ///
    /// `None` means no upper bound.
    /// When end < start the window crosses midnight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_window_end: Option<u32>,

    #[serde(default)]
    /// Products for which the agent autonomously polls for new versions.
    pub products: Vec<UpdateProductKey>,
}

/// Marker type that always serializes/deserializes as the number `2`.
///
/// Embedded as the `VersionMajor` field in [`UpdateManifestV2`] so that the
/// untagged [`UpdateManifest`] enum can distinguish V2 from legacy V1 payloads:
/// if `VersionMajor` is absent or not `"2"`, `ManifestV2` deserialization fails
/// and the `Legacy` variant is tried next.  When a V3 format is introduced, a new
/// marker type and `ManifestV3` variant are added in a similar way.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VersionMajorV2;

impl Serialize for VersionMajorV2 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(2)
    }
}

impl<'de> Deserialize<'de> for VersionMajorV2 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = VersionMajorV2;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "update manifest major version 2")
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Self::Value, E> {
                if n == 2 {
                    Ok(VersionMajorV2)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Unsigned(n), &self))
                }
            }
        }
        d.deserialize_u64(V)
    }
}

/// Version 2 of the update manifest format, written by agent/gateway >=2026.2.0.
/// Includes product update list and auto-update schedule. Adding a product name should always
/// increase the minor version, to allow the gateway API caller to know supported products list.
///
/// Example (full V2 file):
/// ```json
/// {
///   "VersionMajor": 2,
///   "VersionMinor": 1,
///   "Schedule": { "Enabled": false, "Interval": 86400, "UpdateWindowStart": 7200, "UpdateWindowEnd": 14400 },
///   "Products": {
///     "Gateway": { "TargetVersion": "2026.1.0" },
///     "Agent":   { "TargetVersion": "latest"   }
///   }
/// }
/// ```
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateManifestV2 {
    /// Always `2` — the presence and value of this field let the untagged
    /// [`UpdateManifest`] distinguish V2 from legacy V1 payloads and prevent further parsing
    /// attempt of V2 structure
    pub version_major: VersionMajorV2,
    /// Feature-set version within V2.
    pub version_minor: u32,
    /// Auto-update schedule set by the gateway. Agent persists it to `agent.json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<UpdateSchedule>,
    /// Map of product name → update info. Empty when the file is a bare V2 stub.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub products: HashMap<UpdateProductKey, ProductUpdateInfo>,
}

impl Default for UpdateManifestV2 {
    fn default() -> Self {
        Self {
            version_major: VersionMajorV2,
            version_minor: UPDATE_MANIFEST_V2_MINOR_VERSION,
            schedule: None,
            products: HashMap::new(),
        }
    }
}

/// A parsed update manifest: either a V2 file or a legacy V1 file.
///
/// New agents initialise `update.json` with `{"VersionMajor": "2", "VersionMinor": 0}`;
/// old agents write `{}`. The gateway reads the existing file before writing to determine
/// which format to use.
///
/// Serde variant order is significant: `ManifestV2` is tried first; its `VersionMajor`
/// field causes deserialization to fail when absent or not `2`, allowing the untagged
/// enum to fall through to `Legacy`.  When V3 is introduced, a `ManifestV3` variant is
/// inserted before `ManifestV2`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum UpdateManifest {
    /// V2 format: contains `"VersionMajor": 2`.
    ManifestV2(UpdateManifestV2),
    /// Legacy V1 format: no `"VersionMajor"` field.
    Legacy(UpdateManifestV1),
}

pub(crate) fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data)
}

impl UpdateManifest {
    /// Parse `update.json` bytes, automatically detecting the format.
    ///
    /// Strips a UTF-8 BOM if present before parsing.
    pub fn parse(data: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(strip_bom(data))
    }

    /// Normalise the manifest into a flat product map for uniform processing.
    ///
    /// - V2 `products` is used directly.
    /// - V1 named fields are mapped to their [`UpdateProductKey`] equivalents.
    /// - V1 `other` entries are best-effort converted; entries that do not match
    ///   [`ProductUpdateInfo`]'s schema are silently dropped.
    pub fn into_products(self) -> HashMap<UpdateProductKey, ProductUpdateInfo> {
        match self {
            Self::ManifestV2(v2) => v2.products,
            Self::Legacy(v1) => {
                let mut map = HashMap::new();
                if let Some(gw) = v1.gateway {
                    map.insert(UpdateProductKey::Gateway, gw);
                }
                if let Some(hs) = v1.hub_service {
                    map.insert(UpdateProductKey::HubService, hs);
                }
                map
            }
        }
    }
}

/// Detect the `VersionMajor` of an `update.json` payload without fully parsing the manifest.
///
/// Returns `1` for legacy V1 files (no `VersionMajor` field) or the numeric major version
/// for V2+ files.  Both the numeric form and the legacy string form (written by 2026.1
/// agents) are accepted for robustness during format transitions.
///
/// Returns a [`serde_json::Error`] when `data` is not valid JSON.
pub fn detect_update_manifest_major_version(data: &[u8]) -> serde_json::Result<u32> {
    let value = serde_json::from_slice::<serde_json::Value>(strip_bom(data))?;
    let Some(v) = value.get("VersionMajor") else {
        return Ok(1);
    };
    Ok(v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(1))
}

// ── Product key ──────────────────────────────────────────────────────────────

/// Product key used in the V2 update manifest `Products` map.
///
/// Known variants correspond to products this version of the agent understands.
/// `Other` captures any product name that is not yet known and preserves it so
/// that a future agent version can act on it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpdateProductKey {
    Gateway,
    HubService,
    Agent,
    /// Any product name not recognised by this version of the agent.
    Other(String),
}

impl UpdateProductKey {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Gateway => "Gateway",
            Self::HubService => "HubService",
            Self::Agent => "Agent",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl fmt::Display for UpdateProductKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for UpdateProductKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for UpdateProductKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct KeyVisitor;

        impl serde::de::Visitor<'_> for KeyVisitor {
            type Value = UpdateProductKey;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a product name string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(match v {
                    "Gateway" => UpdateProductKey::Gateway,
                    "HubService" => UpdateProductKey::HubService,
                    "Agent" => UpdateProductKey::Agent,
                    other => UpdateProductKey::Other(other.to_owned()),
                })
            }
        }

        d.deserialize_str(KeyVisitor)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

    use super::*;

    #[test]
    fn version_specification_roundtrip() {
        let cases: &[(&'static str, VersionSpecification)] = &[
            (
                "2022.2.24.0",
                VersionSpecification::Specific("2022.2.24.0".parse().unwrap()),
            ),
            ("latest", VersionSpecification::Latest),
        ];

        for (serialized, deserialized) in cases {
            let parsed = serde_json::from_str::<VersionSpecification>(&format!("\"{serialized}\"")).unwrap();
            assert_eq!(parsed, *deserialized);

            let reserialized = serde_json::to_string(&parsed).unwrap();
            assert_eq!(reserialized, format!("\"{serialized}\""));
        }
    }

    #[test]
    fn empty_v1_parses_as_legacy() {
        let manifest = UpdateManifest::parse(b"{}").unwrap();
        assert!(matches!(manifest, UpdateManifest::Legacy(_)));
        assert!(manifest.into_products().is_empty());
    }

    #[test]
    fn empty_v2_stub_parses_as_manifest() {
        let manifest = UpdateManifest::parse(br#"{"VersionMajor":2,"VersionMinor":1}"#).unwrap();
        assert!(matches!(manifest, UpdateManifest::ManifestV2(_)));
        assert!(manifest.into_products().is_empty());
    }

    #[test]
    fn v2_with_products_roundtrip() {
        let json = r#"{"VersionMajor":2,"VersionMinor":0,"Products":{"Agent":{"TargetVersion":"latest"},"Gateway":{"TargetVersion":"2026.1.0"}}}"#;
        let manifest = UpdateManifest::parse(json.as_bytes()).unwrap();
        assert!(matches!(manifest, UpdateManifest::ManifestV2(_)));
        let products = manifest.into_products();
        assert_eq!(products.len(), 2);
        assert!(matches!(
            products[&UpdateProductKey::Agent].target_version,
            VersionSpecification::Latest
        ));
    }

    #[test]
    fn v1_with_products_into_products() {
        let json = r#"{"Gateway":{"TargetVersion":"2026.1.0"},"HubService":{"TargetVersion":"latest"}}"#;
        let manifest = UpdateManifest::parse(json.as_bytes()).unwrap();
        assert!(matches!(manifest, UpdateManifest::Legacy(_)));
        let products = manifest.into_products();
        assert_eq!(products.len(), 2);
        assert!(matches!(
            products[&UpdateProductKey::Gateway].target_version,
            VersionSpecification::Specific(_)
        ));
    }

    #[test]
    fn bom_is_stripped() {
        // UTF-8 BOM prefix
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(b"{}");
        let manifest = UpdateManifest::parse(&data).unwrap();
        assert!(matches!(manifest, UpdateManifest::Legacy(_)));
    }

    #[test]
    fn v2_stub_serialise_roundtrip() {
        let stub = UpdateManifest::ManifestV2(UpdateManifestV2::default());
        let serialized = serde_json::to_string(&stub).unwrap();
        assert_eq!(serialized, r#"{"VersionMajor":2,"VersionMinor":1}"#);
        let back = UpdateManifest::parse(serialized.as_bytes()).unwrap();
        assert!(matches!(back, UpdateManifest::ManifestV2(_)));
    }

    #[test]
    fn detect_version_legacy_no_field() {
        assert_eq!(detect_update_manifest_major_version(b"{}").unwrap(), 1);
    }

    #[test]
    fn detect_version_v2_numeric() {
        assert_eq!(
            detect_update_manifest_major_version(br#"{"VersionMajor":2}"#).unwrap(),
            2
        );
    }

    #[test]
    fn detect_version_v2_legacy_string_form() {
        // Backward compat: 2026.1 agents wrote VersionMajor as a string.
        assert_eq!(
            detect_update_manifest_major_version(br#"{"VersionMajor":"2"}"#).unwrap(),
            2
        );
    }

    #[test]
    fn detect_version_unparseable_returns_error() {
        assert!(detect_update_manifest_major_version(b"not json").is_err());
    }
}
