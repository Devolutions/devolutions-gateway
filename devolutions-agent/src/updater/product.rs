use std::fmt;
use std::str::FromStr;

use devolutions_agent_shared::{ProductUpdateInfo, UpdateJson};

use crate::updater::productinfo::GATEWAY_PRODUCT_ID;

/// Product IDs to track updates for
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Gateway,
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Product::Gateway => write!(f, "Gateway"),
        }
    }
}

impl FromStr for Product {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Gateway" => Ok(Product::Gateway),
            _ => Err(()),
        }
    }
}

impl Product {
    pub fn get_update_info(self, update_json: &UpdateJson) -> Option<ProductUpdateInfo> {
        match self {
            Product::Gateway => update_json.gateway.clone(),
        }
    }

    pub const fn get_productinfo_id(self) -> &'static str {
        match self {
            Product::Gateway => GATEWAY_PRODUCT_ID,
        }
    }

    pub const fn get_package_extension(self) -> &'static str {
        match self {
            Product::Gateway => "msi",
        }
    }
}
