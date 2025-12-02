//! Devolutions product information (https://devolutions.net/productinfo.json) parser

use serde::Deserialize;
use std::collections::BTreeMap;
use thiserror::Error;

/// Errors that can occur when parsing the productinfo.json database.
#[derive(Debug, Error)]
pub(crate) enum ProductInfoError {
    #[error("failed to parse JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("failed to deserialize product `{product}`: {source}")]
    DeserializeProduct { product: String, source: serde_json::Error },
}

/// Information about a product file available for download.
#[derive(Debug, Clone, Deserialize)]
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

/// Product information for a specific channel (Current, Beta, Update, Stable).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ChannelData {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Files")]
    pub files: Vec<ProductFile>,
}

/// Product information containing multiple channels.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ProductData {
    #[serde(rename = "Current")]
    pub current: Option<ChannelData>,
}

/// Database of parsed product information, keyed by product name.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProductInfoDb {
    pub products: BTreeMap<String, ProductData>,
}

/// Result of parsing the productinfo.json file.
#[derive(Debug)]
pub(crate) struct ParseProductInfoResult {
    pub db: ProductInfoDb,
    pub errors: Vec<ProductInfoError>,
}

/// Information about a selected product file for download.
#[derive(Debug, Clone)]
pub(crate) struct SelectedProductFile {
    pub version: String,
    pub url: String,
    pub hash: String,
}

impl ProductInfoDb {
    /// Parses the productinfo.json content leniently.
    ///
    /// This function accumulates errors for individual products but continues parsing.
    /// Products that fail to parse are skipped, and their errors are collected.
    /// The returned `ProductInfoDb` may be empty if all products failed to parse.
    pub(crate) fn parse_product_info(s: &str) -> ParseProductInfoResult {
        let mut errors = Vec::new();
        let mut products = BTreeMap::new();

        // Parse the JSON content.
        let json: serde_json::Value = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(e) => {
                errors.push(ProductInfoError::InvalidJson(e));
                return ParseProductInfoResult {
                    db: ProductInfoDb { products },
                    errors,
                };
            }
        };

        // Iterate through products in the JSON object.
        if let Some(obj) = json.as_object() {
            for (product_name, product_value) in obj {
                // Try to deserialize the product data.
                match serde_json::from_value::<ProductData>(product_value.clone()) {
                    Ok(product_data) => {
                        products.insert(product_name.clone(), product_data);
                    }
                    Err(e) => {
                        errors.push(ProductInfoError::DeserializeProduct {
                            product: product_name.clone(),
                            source: e,
                        });
                    }
                }
            }
        }

        ParseProductInfoResult {
            db: ProductInfoDb { products },
            errors,
        }
    }

    /// Look up a product file for the given product, architecture, and file type.
    ///
    /// Uses the "Current" channel for the product lookup.
    pub(crate) fn lookup_current_file(
        &self,
        product_id: &str,
        arch: &str,
        file_type: &str,
    ) -> Option<SelectedProductFile> {
        // Get the product data.
        let product_data = self.products.get(product_id)?;

        // Get the Current channel.
        let channel = product_data.current.as_ref()?;

        // Find the file matching arch and type.
        let file = channel
            .files
            .iter()
            .find(|f| f.arch == arch && f.file_type == file_type)?;

        Some(SelectedProductFile {
            version: channel.version.clone(),
            url: file.url.clone(),
            hash: file.hash.clone(),
        })
    }

    /// Look up a product file for the given product using the target architecture.
    ///
    /// Uses the "Current" channel and looks for an "msi" file type.
    /// If the lookup fails, logs all parsing errors as warnings for investigation.
    pub(crate) fn lookup_current_msi_for_target_arch(&self, product_id: &str) -> Option<SelectedProductFile> {
        let target_arch = get_target_arch();
        self.lookup_current_file(product_id, target_arch, "msi")
    }
}

/// Determine the target architecture at compile time or runtime, defaulting to x64.
pub(crate) fn get_target_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        // Runtime fallback: check the environment, default to x64.
        match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            _ => "x64", // Default to x64 for unknown architectures.
        }
    }
}

#[cfg(test)]
mod tests {
    use expect_test::expect;

    use super::*;

    #[test]
    fn test_productinfo_parse() {
        let input = include_str!("../../../test_assets/test_asset_db");
        let result = ProductInfoDb::parse_product_info(input);

        assert!(result.errors.is_empty(), "should have no errors: {:?}", result.errors);

        let file = result
            .db
            .lookup_current_file("Gateway", "x64", "msi")
            .expect("should find Gateway x64 msi");
        expect![[r#"
            SelectedProductFile {
                version: "2024.2.1.0",
                url: "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.2.1.0.msi",
                hash: "BD2805075FCD78AC339126F4C4D9E6773DC3127CBE7DF48256D6910FA0C59C35",
            }
        "#]]
        .assert_debug_eq(&file);

        let file = result
            .db
            .lookup_current_file("HubServices", "x64", "msi")
            .expect("should find HubServices x64 msi");
        expect![[r#"
            SelectedProductFile {
                version: "2024.2.1.0",
                url: "https://cdn.devolutions.net/download/HubServices-x86_64-2024.2.1.0.msi",
                hash: "72D7A836A6AF221D4E7631D27B91A358915CF985AA544CC0F7F5612B85E989AA",
            }
        "#]]
        .assert_debug_eq(&file);
    }

    /// Test parsing with the Date field present, matching the live productinfo.json format.
    #[test]
    fn test_productinfo_parse_with_date_field() {
        // This matches the structure of https://devolutions.net/productinfo.json
        // which includes a Date field in each channel.
        let input = r#"{
            "Gateway": {
                "Current": {
                    "Version": "2025.3.2.0",
                    "Date": "2025-11-27",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2025.3.2.0.msi",
                            "Hash": "9670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B27"
                        },
                        {
                            "Arch": "arm64",
                            "Type": "msi",
                            "Url": "https://cdn.devolutions.net/download/DevolutionsGateway-aarch64-2025.3.2.0.msi",
                            "Hash": "A670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B28"
                        }
                    ]
                },
                "Stable": {
                    "Version": "2025.2.0.0",
                    "Date": "2025-10-15",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2025.2.0.0.msi",
                            "Hash": "8670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B26"
                        }
                    ]
                }
            },
            "HubServices": {
                "Current": {
                    "Version": "2025.3.1.0",
                    "Date": "2025-11-20",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "https://cdn.devolutions.net/download/HubServices-x86_64-2025.3.1.0.msi",
                            "Hash": "72D7A836A6AF221D4E7631D27B91A358915CF985AA544CC0F7F5612B85E989AB"
                        }
                    ]
                }
            }
        }"#;

        let result = ProductInfoDb::parse_product_info(input);
        assert!(result.errors.is_empty(), "should have no errors: {:?}", result.errors);

        let file = result
            .db
            .lookup_current_file("Gateway", "x64", "msi")
            .expect("should find Gateway x64 msi");
        expect![[r#"
            SelectedProductFile {
                version: "2025.3.2.0",
                url: "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2025.3.2.0.msi",
                hash: "9670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B27",
            }
        "#]]
        .assert_debug_eq(&file);

        let file = result
            .db
            .lookup_current_file("HubServices", "x64", "msi")
            .expect("should find HubServices x64 msi");
        expect![[r#"
            SelectedProductFile {
                version: "2025.3.1.0",
                url: "https://cdn.devolutions.net/download/HubServices-x86_64-2025.3.1.0.msi",
                hash: "72D7A836A6AF221D4E7631D27B91A358915CF985AA544CC0F7F5612B85E989AB",
            }
        "#]]
        .assert_debug_eq(&file);
    }

    /// Test that parsing continues even when one product fails to parse.
    #[test]
    fn test_productinfo_lenient_parsing() {
        // Gateway has a valid structure, BadProduct has an invalid structure.
        let input = r#"{
            "Gateway": {
                "Current": {
                    "Version": "2025.3.2.0",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "https://example.com/test.msi",
                            "Hash": "ABCD1234"
                        }
                    ]
                }
            },
            "BadProduct": {
                "Current": {
                    "Version": "1.0.0"
                }
            }
        }"#;

        let result = ProductInfoDb::parse_product_info(input);

        // Should have one error for BadProduct.
        expect![[r#"
            ParseProductInfoResult {
                db: ProductInfoDb {
                    products: {
                        "Gateway": ProductData {
                            current: Some(
                                ChannelData {
                                    version: "2025.3.2.0",
                                    files: [
                                        ProductFile {
                                            arch: "x64",
                                            file_type: "msi",
                                            url: "https://example.com/test.msi",
                                            hash: "ABCD1234",
                                        },
                                    ],
                                },
                            ),
                        },
                    },
                },
                errors: [
                    DeserializeProduct {
                        product: "BadProduct",
                        source: Error("missing field `Files`", line: 0, column: 0),
                    },
                ],
            }
        "#]]
        .assert_debug_eq(&result);

        // Gateway should still be available.
        let file = result
            .db
            .lookup_current_file("Gateway", "x64", "msi")
            .expect("should find Gateway even though BadProduct failed");
        expect![[r#"
            SelectedProductFile {
                version: "2025.3.2.0",
                url: "https://example.com/test.msi",
                hash: "ABCD1234",
            }
        "#]]
        .assert_debug_eq(&file);
    }

    /// Test that missing Current channel doesn't cause an error during parsing.
    #[test]
    fn test_productinfo_missing_current_channel() {
        let input = r#"{
            "Gateway": {
                "Stable": {
                    "Version": "2025.2.0.0",
                    "Files": [
                        {
                            "Arch": "x64",
                            "Type": "msi",
                            "Url": "https://example.com/test.msi",
                            "Hash": "ABCD1234"
                        }
                    ]
                }
            }
        }"#;

        let result = ProductInfoDb::parse_product_info(input);

        // Parsing should succeed (no errors), but lookup will return None.
        assert!(result.errors.is_empty(), "should have no errors: {:?}", result.errors);
        assert!(
            result.db.products.contains_key("Gateway"),
            "Gateway should be in products"
        );

        // Lookup should return None because there's no Current channel.
        let file = result.db.lookup_current_file("Gateway", "x64", "msi");
        assert!(file.is_none(), "should not find file without Current channel");
    }

    /// Test that missing architecture returns None without error.
    #[test]
    fn test_productinfo_missing_arch() {
        let input = r#"{
            "Gateway": {
                "Current": {
                    "Version": "2025.3.2.0",
                    "Files": [
                        {
                            "Arch": "arm64",
                            "Type": "msi",
                            "Url": "https://example.com/test.msi",
                            "Hash": "ABCD1234"
                        }
                    ]
                }
            }
        }"#;

        let result = ProductInfoDb::parse_product_info(input);
        assert!(result.errors.is_empty(), "should have no errors: {:?}", result.errors);

        // Lookup for x64 should return None.
        let file = result.db.lookup_current_file("Gateway", "x64", "msi");
        assert!(file.is_none(), "should not find x64 file when only arm64 is available");

        // Lookup for arm64 should succeed.
        let file = result
            .db
            .lookup_current_file("Gateway", "arm64", "msi")
            .expect("should find arm64 msi");
        expect![[r#"
            SelectedProductFile {
                version: "2025.3.2.0",
                url: "https://example.com/test.msi",
                hash: "ABCD1234",
            }
        "#]]
        .assert_debug_eq(&file);
    }

    #[test]
    fn test_productinfo_error_invalid_json() {
        let input = "{ invalid json }";

        let result = ProductInfoDb::parse_product_info(input);

        assert_eq!(result.errors.len(), 1, "should have exactly one error");
        expect![[r#"
            ParseProductInfoResult {
                db: ProductInfoDb {
                    products: {},
                },
                errors: [
                    InvalidJson(
                        Error("key must be a string", line: 1, column: 3),
                    ),
                ],
            }
        "#]]
        .assert_debug_eq(&result);
    }

    #[test]
    fn test_productinfo_error_deserialize_product() {
        // Missing required "Files" field in Current channel.
        let input = r#"{
            "Gateway": {
                "Current": {
                    "Version": "2025.3.2.0"
                }
            }
        }"#;

        let result = ProductInfoDb::parse_product_info(input);

        assert_eq!(result.errors.len(), 1, "should have exactly one error");
        expect![[r#"
            ParseProductInfoResult {
                db: ProductInfoDb {
                    products: {},
                },
                errors: [
                    DeserializeProduct {
                        product: "Gateway",
                        source: Error("missing field `Files`", line: 0, column: 0),
                    },
                ],
            }
        "#]]
        .assert_debug_eq(&result);
    }

    /// Test parsing the live productinfo.json format based on the sample provided.
    #[test]
    fn test_productinfo_live_format() {
        // Simplified version of the live productinfo.json structure.
        let input = r#"{
            "RDMWindows": {
                "Current": {
                    "Version": "2025.3.25.0",
                    "Date": "2025-11-27",
                    "Files": [
                        {
                            "Arch": "Any",
                            "Type": "exe",
                            "Url": "https://cdn.devolutions.net/download/Setup.RemoteDesktopManager.2025.3.25.0.exe",
                            "Hash": "67F5281A8EBC1662E61C216F5887115A8B68F56C46FEE58A32E24D0CE82EB1B2"
                        },
                        {
                            "Arch": "Any",
                            "Type": "msi",
                            "Url": "https://cdn.devolutions.net/download/Setup.RemoteDesktopManager.2025.3.25.0.msi",
                            "Hash": "99E0A49F6CFFE5C0B489D9B969945BDAA690E61E27D3EEA47A83741C98D1096E"
                        },
                        {
                            "Arch": "arm64",
                            "Type": "exe",
                            "Url": "https://cdn.devolutions.net/download/Setup.RemoteDesktopManager.win-arm64.2025.3.25.0.exe",
                            "Hash": "2D73BD97C98F91850566E2DF50759761CD68B49B074A4A60C3D284D42146A756"
                        }
                    ]
                }
            },
            "Gateway": {
                "Current": {
                    "Version": "2025.3.2.0",
                    "Date": "2025-11-27",
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

        let result = ProductInfoDb::parse_product_info(input);

        expect![[r#"
            ParseProductInfoResult {
                db: ProductInfoDb {
                    products: {
                        "Gateway": ProductData {
                            current: Some(
                                ChannelData {
                                    version: "2025.3.2.0",
                                    files: [
                                        ProductFile {
                                            arch: "x64",
                                            file_type: "msi",
                                            url: "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2025.3.2.0.msi",
                                            hash: "9670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B27",
                                        },
                                    ],
                                },
                            ),
                        },
                        "RDMWindows": ProductData {
                            current: Some(
                                ChannelData {
                                    version: "2025.3.25.0",
                                    files: [
                                        ProductFile {
                                            arch: "Any",
                                            file_type: "exe",
                                            url: "https://cdn.devolutions.net/download/Setup.RemoteDesktopManager.2025.3.25.0.exe",
                                            hash: "67F5281A8EBC1662E61C216F5887115A8B68F56C46FEE58A32E24D0CE82EB1B2",
                                        },
                                        ProductFile {
                                            arch: "Any",
                                            file_type: "msi",
                                            url: "https://cdn.devolutions.net/download/Setup.RemoteDesktopManager.2025.3.25.0.msi",
                                            hash: "99E0A49F6CFFE5C0B489D9B969945BDAA690E61E27D3EEA47A83741C98D1096E",
                                        },
                                        ProductFile {
                                            arch: "arm64",
                                            file_type: "exe",
                                            url: "https://cdn.devolutions.net/download/Setup.RemoteDesktopManager.win-arm64.2025.3.25.0.exe",
                                            hash: "2D73BD97C98F91850566E2DF50759761CD68B49B074A4A60C3D284D42146A756",
                                        },
                                    ],
                                },
                            ),
                        },
                    },
                },
                errors: [],
            }
        "#]]
        .assert_debug_eq(&result);

        // RDMWindows should be parsed but we can't find x64 msi.
        let file = result.db.lookup_current_file("RDMWindows", "x64", "msi");
        assert!(file.is_none(), "RDMWindows doesn't have x64 msi");

        // RDMWindows has "Any" arch msi.
        let file = result
            .db
            .lookup_current_file("RDMWindows", "Any", "msi")
            .expect("should find RDMWindows Any msi");
        expect![[r#"
            SelectedProductFile {
                version: "2025.3.25.0",
                url: "https://cdn.devolutions.net/download/Setup.RemoteDesktopManager.2025.3.25.0.msi",
                hash: "99E0A49F6CFFE5C0B489D9B969945BDAA690E61E27D3EEA47A83741C98D1096E",
            }
        "#]]
        .assert_debug_eq(&file);

        // Gateway should have x64 msi.
        let file = result
            .db
            .lookup_current_file("Gateway", "x64", "msi")
            .expect("should find Gateway x64 msi");
        expect![[r#"
            SelectedProductFile {
                version: "2025.3.2.0",
                url: "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2025.3.2.0.msi",
                hash: "9670B9B7D8B4D145708EE5F7F1F7053111E620541D67CFA04CF711065C4C3B27",
            }
        "#]]
        .assert_debug_eq(&file);
    }
}
