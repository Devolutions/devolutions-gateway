//! Devolutions product information (https://devolutions.net/productinfo.json) parser

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::warn;

use crate::updater::UpdaterError;

/// Information about a product file available for download
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductFile {
    #[serde(rename = "Arch")]
    pub arch: String,
    #[serde(rename = "Type")]
    pub file_type: String,
    #[serde(rename = "Url")]
    pub url: String,
    #[serde(rename = "Hash")]
    pub hash: String,
}

/// Product information for a specific channel (Current, Beta, Update, Stable)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ChannelData {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Date", skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(rename = "Files")]
    pub files: Vec<ProductFile>,
    // Allow unknown fields at channel level for forward compatibility.
    // New marketing fields or metadata won't break parsing.
    #[serde(flatten)]
    #[serde(skip_serializing)]
    pub _other: HashMap<String, serde_json::Value>,
}

/// Product information containing multiple channels
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ProductData {
    #[serde(rename = "Current")]
    pub current: Option<ChannelData>,
    #[serde(rename = "Beta")]
    pub beta: Option<ChannelData>,
    #[serde(rename = "Update")]
    pub update: Option<ChannelData>,
    #[serde(rename = "Stable")]
    pub stable: Option<ChannelData>,
    // Allow unknown fields at product level for forward compatibility
    #[serde(flatten)]
    #[serde(skip_serializing)]
    pub _other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ProductInfo {
    pub version: String,
    pub hash: Option<String>,
    pub url: String,
}

pub(crate) struct ProductInfoDb {
    pub records: HashMap<String, ProductInfo>,
}

/// Determine the target architecture at compile time or runtime, defaulting to x64
fn get_target_arch() -> String {
    if cfg!(target_arch = "x86_64") {
        "x64".to_owned()
    } else if cfg!(target_arch = "aarch64") {
        "arm64".to_owned()
    } else {
        // Runtime fallback: check the environment, default to x64
        match std::env::consts::ARCH {
            "x86_64" => "x64".to_owned(),
            "aarch64" => "arm64".to_owned(),
            _ => "x64".to_owned(), // Default to x64 for unknown architectures
        }
    }
}

/// Select a file from the product files matching the target architecture and type
fn select_file(files: &[ProductFile], target_arch: &str, file_type: &str) -> Option<ProductFile> {
    files
        .iter()
        .find(|f| f.arch == target_arch && f.file_type == file_type)
        .cloned()
}

impl FromStr for ProductInfoDb {
    type Err = UpdaterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse the JSON content with better error context
        let json: serde_json::Value = serde_json::from_str(s).map_err(|e| {
            warn!(%e, "Failed to parse productinfo.json as valid JSON");
            UpdaterError::ProductInfo
        })?;

        let mut records = HashMap::new();
        let target_arch = get_target_arch();

        // Iterate through products in the JSON object
        if let Some(obj) = json.as_object() {
            for (product_name, product_value) in obj {
                // Try to deserialize the product data
                let product_data: ProductData = serde_json::from_value(product_value.clone()).map_err(|e| {
                    warn!(%product_name, %e, "Failed to deserialize product data");
                    UpdaterError::ProductInfo
                })?;

                // Use Current channel for now (as specified)
                let channel = product_data.current.ok_or_else(|| {
                    warn!(%product_name, "Product is missing 'Current' channel");
                    UpdaterError::ProductInfo
                })?;

                // Validate that we have files
                if channel.files.is_empty() {
                    warn!(%product_name, "Product Current channel has no files");
                    return Err(UpdaterError::ProductInfo);
                }

                // Select the appropriate file based on architecture and type (msi)
                let selected_file = select_file(&channel.files, &target_arch, "msi").ok_or_else(|| {
                    warn!(
                        %product_name,
                        %target_arch,
                        available_archs = ?channel.files.iter().map(|f| &f.arch).collect::<Vec<_>>(),
                        "No MSI file found for target architecture"
                    );
                    UpdaterError::ProductInfo
                })?;

                // Basic validation of the selected file
                if selected_file.url.is_empty() {
                    warn!(%product_name, "Selected file has empty URL");
                    return Err(UpdaterError::ProductInfo);
                }

                if selected_file.hash.is_empty() {
                    warn!(%product_name, "Selected file has empty hash");
                    return Err(UpdaterError::ProductInfo);
                }

                let product_info = ProductInfo {
                    version: channel.version.clone(),
                    hash: Some(selected_file.hash.clone()),
                    url: selected_file.url.clone(),
                };

                records.insert(product_name.clone(), product_info);
            }
        }

        Ok(ProductInfoDb { records })
    }
}

impl ProductInfoDb {
    /// Get product information by product ID
    pub(crate) fn get(&self, product_id: &str) -> Option<&ProductInfo> {
        self.records.get(product_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_productinfo_parse() {
        let input = include_str!("../../../test_assets/test_asset_db");
        let db: ProductInfoDb = input.parse().expect("failed to parse product info database");

        assert_eq!(db.get("Gateway").expect("product not found").version, "2024.2.1.0");
        assert_eq!(
            db.get("Gateway").expect("product not found").url,
            "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.2.1.0.msi"
        );
        assert_eq!(
            db.get("Gateway").expect("product not found").hash.as_deref(),
            Some("BD2805075FCD78AC339126F4C4D9E6773DC3127CBE7DF48256D6910FA0C59C35")
        );

        assert_eq!(db.get("HubServices").expect("product not found").version, "2024.2.1.0");
        assert_eq!(
            db.get("HubServices").expect("product not found").url,
            "https://cdn.devolutions.net/download/HubServices-x86_64-2024.2.1.0.msi"
        );
        assert_eq!(
            db.get("HubServices").expect("product not found").hash.as_deref(),
            Some("72D7A836A6AF221D4E7631D27B91A358915CF985AA544CC0F7F5612B85E989AA")
        );
    }

    #[test]
    fn test_productinfo_parse_with_date_field() {
        // Test that the Date field is properly handled (ignoring or parsing it)
        let input = r#"{
            "Gateway": {
                "Current": {
                    "Version": "2025.3.2.0",
                    "Date": "2025-10-10",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2025.3.2.0.msi",
                            "Hash": "9670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B27"
                        }
                    ]
                }
            }
        }"#;

        let db: ProductInfoDb = input
            .parse()
            .expect("failed to parse product info database with Date field");

        assert_eq!(db.get("Gateway").expect("product not found").version, "2025.3.2.0");
        assert_eq!(
            db.get("Gateway").expect("product not found").url,
            "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2025.3.2.0.msi"
        );
        assert_eq!(
            db.get("Gateway").expect("product not found").hash.as_deref(),
            Some("9670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B27")
        );
    }

    #[test]
    fn test_productinfo_parse_with_unknown_fields() {
        // Test forward compatibility - new fields at product and channel level shouldn't break parsing
        let input = r#"{
            "Gateway": {
                "NewMarketingField": "some value",
                "Current": {
                    "Version": "2025.3.2.0",
                    "Date": "2025-10-10",
                    "ReleaseNotes": "https://example.com/notes",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2025.3.2.0.msi",
                            "Hash": "9670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B27"
                        }
                    ]
                }
            }
        }"#;

        let db: ProductInfoDb = input
            .parse()
            .expect("failed to parse product info database with unknown fields");

        assert_eq!(db.get("Gateway").expect("product not found").version, "2025.3.2.0");
    }

    #[test]
    fn test_productinfo_parse_validation() {
        // Test that empty URLs are rejected
        let input = r#"{
            "Gateway": {
                "Current": {
                    "Version": "2025.3.2.0",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "",
                            "Hash": "9670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B27"
                        }
                    ]
                }
            }
        }"#;

        let result: Result<ProductInfoDb, _> = input.parse();
        assert!(result.is_err(), "Should reject empty URL");

        // Test that empty hashes are rejected
        let input = r#"{
            "Gateway": {
                "Current": {
                    "Version": "2025.3.2.0",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "https://cdn.devolutions.net/download/test.msi",
                            "Hash": ""
                        }
                    ]
                }
            }
        }"#;

        let result: Result<ProductInfoDb, _> = input.parse();
        assert!(result.is_err(), "Should reject empty hash");
    }
}
