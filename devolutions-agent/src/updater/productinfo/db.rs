//! Devolutions product information (https://devolutions.net/productinfo.htm) parser

use std::collections::HashMap;
use std::str::FromStr;

use crate::updater::UpdaterError;

#[derive(Debug, Clone, Default)]
pub(crate) struct ProductInfo {
    pub version: String,
    pub hash: Option<String>,
    pub url: String,
}

pub(crate) struct ProductInfoDb {
    pub records: HashMap<String, ProductInfo>,
}

impl FromStr for ProductInfoDb {
    type Err = UpdaterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut records = HashMap::new();

        for line in s.lines() {
            if line.is_empty() {
                continue;
            }

            let (key, value) = line.split_once('=').ok_or(UpdaterError::ProductInfo)?;
            let (product_id, property) = key.split_once('.').ok_or(UpdaterError::ProductInfo)?;

            let entry = records
                .entry(product_id.to_owned())
                .or_insert_with(ProductInfo::default);

            match property {
                "Version" => entry.version = value.to_owned(),
                "Url" => entry.url = value.to_owned(),
                "hash" => entry.hash = Some(value.to_owned()),
                _ => {
                    trace!(%product_id, %property, "Unknown productinfo property");
                    continue;
                }
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

        assert_eq!(db.get("Gatewaybin").expect("product not found").version, "2024.2.1.0");
        assert_eq!(
            db.get("Gatewaybin").expect("product not found").url,
            "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.2.1.0.msi"
        );
        assert_eq!(
            db.get("Gatewaybin").expect("product not found").hash.as_deref(),
            Some("BD2805075FCD78AC339126F4C4D9E6773DC3127CBE7DF48256D6910FA0C59C35")
        );

        assert_eq!(
            db.get("GatewaybinBeta").expect("product not found").version,
            "2024.2.1.0"
        );
        assert_eq!(
            db.get("GatewaybinBeta").expect("product not found").url,
            "https://cdn.devolutions.net/download/DevolutionsGateway-x86_64-2024.2.1.0.msi"
        );
        assert_eq!(
            db.get("GatewaybinBeta").expect("product not found").hash.as_deref(),
            Some("BD2805075FCD78AC339126F4C4D9E6773DC3127CBE7DF48256D6910FA0C59C35")
        );

        assert_eq!(
            db.get("GatewaybinDebX64").expect("product not found").version,
            "2024.2.1.0"
        );
        assert_eq!(
            db.get("GatewaybinDebX64").expect("product not found").url,
            "https://cdn.devolutions.net/download/devolutions-gateway_2024.2.1.0_amd64.deb"
        );
        assert_eq!(
            db.get("GatewaybinDebX64").expect("product not found").hash.as_deref(),
            Some("72D7A836A6AF221D4E7631D27B91A358915CF985AA544CC0F7F5612B85E989AA")
        );

        assert_eq!(
            db.get("GatewaybinDebX64Beta").expect("product not found").version,
            "2024.2.1.0"
        );
        assert_eq!(
            db.get("GatewaybinDebX64Beta").expect("product not found").url,
            "https://cdn.devolutions.net/download/devolutions-gateway_2024.2.1.0_amd64.deb"
        );
        assert_eq!(
            db.get("GatewaybinDebX64Beta")
                .expect("product not found")
                .hash
                .as_deref(),
            Some("72D7A836A6AF221D4E7631D27B91A358915CF985AA544CC0F7F5612B85E989AA")
        );

        assert_eq!(db.get("DevoCLIbin").expect("product not found").version, "2023.3.0.0");
        assert_eq!(
            db.get("DevoCLIbin").expect("product not found").url,
            "https://cdn.devolutions.net/download/DevoCLI.2023.3.0.0.zip"
        );
        assert_eq!(db.get("DevoCLIbin").expect("product not found").hash, None);
    }
}
