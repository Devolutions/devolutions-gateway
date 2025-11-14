use std::fmt;
use std::str::FromStr;

use devolutions_agent_shared::{ProductUpdateInfo, UpdateJson};

use crate::updater::productinfo::{GATEWAY_PRODUCT_ID, HUB_SERVICE_PRODUCT_ID};

/// Product IDs to track updates for
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Product {
    Gateway,
    HubService,
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Product::Gateway => write!(f, "Gateway"),
            Product::HubService => write!(f, "HubService"),
        }
    }
}

impl FromStr for Product {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Gateway" => Ok(Product::Gateway),
            "HubService" => Ok(Product::HubService),
            _ => Err(()),
        }
    }
}

impl Product {
    pub(crate) fn get_update_info(self, update_json: &UpdateJson) -> Option<ProductUpdateInfo> {
        match self {
            Product::Gateway => update_json.gateway.clone(),
            Product::HubService => update_json.hub_service.clone(),
        }
    }

    pub(crate) const fn get_productinfo_id(self) -> &'static str {
        match self {
            Product::Gateway => GATEWAY_PRODUCT_ID,
            Product::HubService => HUB_SERVICE_PRODUCT_ID,
        }
    }

    pub(crate) const fn get_package_extension(self) -> &'static str {
        match self {
            Product::Gateway => "msi",
            Product::HubService => "msi",
        }
    }
}
