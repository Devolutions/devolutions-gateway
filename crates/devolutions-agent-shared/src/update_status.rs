use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::update_manifest::strip_bom;
use crate::{ProductUpdateInfo, UPDATE_MANIFEST_V2_MINOR_VERSION, UpdateProductKey, UpdateSchedule, VersionMajorV2};

/// Version 2 of the agent status format, written by agent >=2026.2.0.
///
/// Uses the same major version marker ([`VersionMajorV2`]) as [`crate::UpdateManifestV2`]
/// so both files share the minor-version constant and version numbering scheme.
///
/// Example:
/// ```json
/// {
///   "VersionMajor": 2,
///   "VersionMinor": 1,
///   "Schedule": { "Enabled": true, "Interval": 86400, "UpdateWindowStart": 7200 },
///   "Products": { "Agent": { "TargetVersion": "2026.2.0" } }
/// }
/// ```
///
/// Agent runtime status written to `agent_status.json` on agent start and refreshed
/// after each updater run or auto-update schedule change.
///
/// The gateway reads this file for `GET /jet/update` and `GET /jet/update/schedule` so
/// that it can surface current agent state without needing knowledge of the agent's
/// internal `agent.json` configuration format.
///
/// Unlike [`crate::UpdateManifest`] (`update.json`), this file is **read-only** for
/// the Gateway service: its DACL grants NETWORK SERVICE read access but **no write
/// access**.  The agent is the sole writer.
///
/// Note: if the agent itself is being updated, `agent_status.json` will be
/// automatically refreshed when the agent restarts after the update completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateStatusV2 {
    /// Always `2` — reuses [`VersionMajorV2`] so the version numbering is consistent
    /// with [`crate::UpdateManifestV2`].
    pub version_major: VersionMajorV2,
    /// Feature-set version within V2.
    pub version_minor: u32,
    /// Current auto-update schedule configured for this agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<UpdateSchedule>,
    /// Map of product name → currently **installed** version.
    ///
    /// Each entry's `TargetVersion` field holds the installed version of the product,
    /// not a requested upgrade target.  Products that are not installed are omitted.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub products: HashMap<UpdateProductKey, ProductUpdateInfo>,
}

impl Default for UpdateStatusV2 {
    fn default() -> Self {
        Self {
            version_major: VersionMajorV2,
            version_minor: UPDATE_MANIFEST_V2_MINOR_VERSION,
            schedule: None,
            products: HashMap::new(),
        }
    }
}

/// A parsed agent status file: currently only V2 is defined.
///
/// Serde variant order is significant: `StatusV2` is tried first; its `VersionMajor`
/// field causes deserialization to fail when the value is not `2`, allowing the untagged
/// enum to fall through to future variants.  When V3 is introduced, a `StatusV3`
/// variant is inserted before `StatusV2`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UpdateStatus {
    /// V2 format: contains `"VersionMajor": 2`.
    StatusV2(UpdateStatusV2),
}

impl UpdateStatus {
    /// Parse `agent_status.json` bytes.
    ///
    /// Strips a UTF-8 BOM if present before parsing.
    pub fn parse(data: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(strip_bom(data))
    }

    /// Return the format version as a `"major.minor"` string (e.g. `"2.1"`).
    pub fn version_string(&self) -> String {
        match self {
            Self::StatusV2(v2) => format!("2.{}", v2.version_minor),
        }
    }

    /// Borrow the schedule from whichever version is present.
    pub fn schedule(&self) -> Option<&UpdateSchedule> {
        match self {
            Self::StatusV2(v2) => v2.schedule.as_ref(),
        }
    }

    /// Consume the status and return the product map from whichever version is present.
    pub fn into_products(self) -> HashMap<UpdateProductKey, ProductUpdateInfo> {
        match self {
            Self::StatusV2(v2) => v2.products,
        }
    }
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self::StatusV2(UpdateStatusV2::default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

    use super::*;
    use crate::VersionSpecification;

    #[test]
    fn bom_is_stripped() {
        // UTF-8 BOM prefix
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(br#"{"VersionMajor":2,"VersionMinor":1}"#);
        let status = UpdateStatus::parse(&data).unwrap();
        assert!(matches!(status, UpdateStatus::StatusV2(_)));
    }

    #[test]
    fn v2_minimal_parses() {
        let status = UpdateStatus::parse(br#"{"VersionMajor":2,"VersionMinor":1}"#).unwrap();
        assert!(matches!(status, UpdateStatus::StatusV2(_)));
        assert!(status.schedule().is_none());
        assert!(status.into_products().is_empty());
    }

    #[test]
    fn wrong_major_fails() {
        assert!(UpdateStatus::parse(br#"{"VersionMajor":1,"VersionMinor":1}"#).is_err());
        assert!(UpdateStatus::parse(br#"{"VersionMajor":3,"VersionMinor":0}"#).is_err());
    }

    #[test]
    fn v2_with_schedule_roundtrip() {
        let json = r#"{"VersionMajor":2,"VersionMinor":1,"Schedule":{"Enabled":true,"Interval":86400,"UpdateWindowStart":7200,"Products":[]}}"#;
        let status = UpdateStatus::parse(json.as_bytes()).unwrap();
        let schedule = status.schedule().unwrap();
        assert!(schedule.enabled);
        assert_eq!(schedule.interval, 86400);
        assert_eq!(schedule.update_window_start, 7200);
        let reserialized = serde_json::to_string(&status).unwrap();
        assert_eq!(reserialized, json);
    }

    #[test]
    fn v2_with_products_roundtrip() {
        let json = r#"{"VersionMajor":2,"VersionMinor":1,"Products":{"Agent":{"TargetVersion":"2026.2.0"},"Gateway":{"TargetVersion":"latest"}}}"#;
        let status = UpdateStatus::parse(json.as_bytes()).unwrap();
        let products = status.into_products();
        assert_eq!(products.len(), 2);
        assert!(matches!(
            products[&UpdateProductKey::Gateway].target_version,
            VersionSpecification::Latest
        ));
        assert!(matches!(
            products[&UpdateProductKey::Agent].target_version,
            VersionSpecification::Specific(_)
        ));
    }

    #[test]
    fn version_string_format() {
        let status = UpdateStatus::parse(br#"{"VersionMajor":2,"VersionMinor":3}"#).unwrap();
        assert_eq!(status.version_string(), "2.3");
    }

    #[test]
    fn v2_stub_serialise_roundtrip() {
        let stub = UpdateStatus::StatusV2(UpdateStatusV2::default());
        let serialized = serde_json::to_string(&stub).unwrap();
        assert_eq!(serialized, r#"{"VersionMajor":2,"VersionMinor":1}"#);
        let back = UpdateStatus::parse(serialized.as_bytes()).unwrap();
        assert!(matches!(back, UpdateStatus::StatusV2(_)));
    }
}
