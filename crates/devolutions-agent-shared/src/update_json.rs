use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::DateVersion;

// ── V1 ── (keep for backward-compat; written by gateways <= 2026.1.0) ───────

/// Example V1 JSON structure:
///
/// ```json
/// {
///     "Gateway":    { "TargetVersion": "1.2.3.4" },
///     "HubService": { "TargetVersion": "latest"  },
///     "Agent":      { "TargetVersion": "latest"  }
/// }
/// ```
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<ProductUpdateInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_service: Option<ProductUpdateInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<ProductUpdateInfo>,
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

// ── V2 ── (new agents init update.json with `{"VersionMajor": "2"}`) ─────────

/// Minor version of the V2 manifest format written by this build of the agent.
///
/// The minor version tracks feature-set additions within V2 (major version):
/// a new updatable product or capability increments this value so the gateway
/// can detect what the agent supports and reject requests for unsupported features.
pub const UPDATE_MANIFEST_V2_MINOR_VERSION: u32 = 0;

/// V2 manifest content: minor version plus a map of product names to update info.
///
/// `VersionMajor` is handled by the parent [`VersionedManifest`] tag and is absent here.
///
/// Example (full V2 file):
/// ```json
/// {
///   "VersionMajor": "2",
///   "VersionMinor": 0,
///   "Products": {
///     "Gateway": { "TargetVersion": "2026.1.0" },
///     "Agent":   { "TargetVersion": "latest"   }
///   }
/// }
/// ```
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateManifestV2 {
    /// Feature-set version within V2. Defaults to `0` when the field is absent in the file.
    #[serde(default)]
    pub version_minor: u32,
    /// Map of product name → update info. Empty when the file is a bare V2 stub.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub products: HashMap<UpdateProductKey, ProductUpdateInfo>,
}

impl Default for UpdateManifestV2 {
    fn default() -> Self {
        Self {
            version_minor: UPDATE_MANIFEST_V2_MINOR_VERSION,
            products: HashMap::new(),
        }
    }
}

/// Internally-tagged versioned manifest (tag field: `"VersionMajor"`).
///
/// New agents initialise `update.json` with `{"VersionMajor": "2", "VersionMinor": 0}` to
/// signal that they can consume V2 format. The gateway reads this before writing to decide
/// which format to use.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "VersionMajor")]
pub enum VersionedManifest {
    /// V2 manifest — matched when the file contains `"VersionMajor": "2"`.
    #[serde(rename = "2")]
    V2(UpdateManifestV2),
}

// ── Unified manifest ─────────────────────────────────────────────────────────

/// A parsed update manifest: either a legacy V1 file or a versioned V2+ file.
///
/// New agents initialise `update.json` with `{"VersionMajor": "2", "VersionMinor": 0}`;
/// old agents write `{}`. The gateway reads the existing file before writing to determine
/// which format to use.
///
/// Serde variant order is significant: `Manifest` is tried first because `Legacy`
/// (using `#[serde(flatten)]`) would otherwise greedily match any object including V2.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum UpdateManifest {
    /// V2+ format: has a `"Version"` field.
    Manifest(VersionedManifest),
    /// Legacy V1 format: no `"Version"` field.
    Legacy(UpdateJson),
}

impl UpdateManifest {
    /// Parse `update.json` bytes, automatically detecting the format.
    ///
    /// Strips a UTF-8 BOM if present before parsing.
    pub fn parse(data: &[u8]) -> serde_json::Result<Self> {
        // Strip UTF-8 BOM if present (some editors add it).
        let data = if data.starts_with(&[0xEF, 0xBB, 0xBF]) { &data[3..] } else { data };
        serde_json::from_slice(data)
    }

    /// Normalise the manifest into a flat product map for uniform processing.
    ///
    /// - V2 `products` is used directly.
    /// - V1 named fields are mapped to their [`UpdateProductKey`] equivalents.
    /// - V1 `other` entries are best-effort converted; entries that do not match
    ///   [`ProductUpdateInfo`]'s schema are silently dropped.
    pub fn into_products(self) -> HashMap<UpdateProductKey, ProductUpdateInfo> {
        match self {
            Self::Manifest(VersionedManifest::V2(v2)) => v2.products,
            Self::Legacy(v1) => {
                let mut map = HashMap::new();
                if let Some(gw) = v1.gateway {
                    map.insert(UpdateProductKey::Gateway, gw);
                }
                if let Some(hs) = v1.hub_service {
                    map.insert(UpdateProductKey::HubService, hs);
                }
                if let Some(ag) = v1.agent {
                    map.insert(UpdateProductKey::Agent, ag);
                }
                map
            }
        }
    }
}

// ── V2 ── (new agents init update.json with `{"VersionMajor": "2"}`) ─────────

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
        let manifest = UpdateManifest::parse(br#"{"VersionMajor":"2"}"#).unwrap();
        assert!(matches!(manifest, UpdateManifest::Manifest(VersionedManifest::V2(_))));
        assert!(manifest.into_products().is_empty());
    }

    #[test]
    fn v2_with_products_roundtrip() {
        let json = r#"{"VersionMajor":"2","VersionMinor":0,"Products":{"Agent":{"TargetVersion":"latest"},"Gateway":{"TargetVersion":"2026.1.0"}}}"#;
        let manifest = UpdateManifest::parse(json.as_bytes()).unwrap();
        let products = manifest.into_products();
        assert_eq!(products.len(), 2);
        assert!(matches!(
            products.get(&UpdateProductKey::Agent).unwrap().target_version,
            VersionSpecification::Latest
        ));
    }

    #[test]
    fn v1_with_products_into_products() {
        let json = r#"{"Gateway":{"TargetVersion":"2026.1.0"},"Agent":{"TargetVersion":"latest"}}"#;
        let manifest = UpdateManifest::parse(json.as_bytes()).unwrap();
        assert!(matches!(manifest, UpdateManifest::Legacy(_)));
        let products = manifest.into_products();
        assert_eq!(products.len(), 2);
        assert!(matches!(
            products.get(&UpdateProductKey::Gateway).unwrap().target_version,
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
        let stub = UpdateManifest::Manifest(VersionedManifest::V2(UpdateManifestV2::default()));
        let serialized = serde_json::to_string(&stub).unwrap();
        assert_eq!(serialized, r#"{"VersionMajor":"2","VersionMinor":0}"#);
        let back = UpdateManifest::parse(serialized.as_bytes()).unwrap();
        assert!(matches!(back, UpdateManifest::Manifest(VersionedManifest::V2(_))));
    }
}
