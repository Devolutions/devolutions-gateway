use crate::DateVersion;
use std::fmt;

/// Example JSON structure:
///
/// ```json
/// {
///     "Gateway": {
///         "TargetVersion": "1.2.3.4"
///     }
/// }
/// ```
///
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<ProductUpdateInfo>,
}

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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProductUpdateInfo {
    /// The version of the product to update to.
    pub target_version: VersionSpecification,
}

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
}
