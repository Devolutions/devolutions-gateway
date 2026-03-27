use std::fmt;
use std::str::FromStr;

use devolutions_agent_shared::UpdateProductKey;

use crate::updater::productinfo::{AGENT_PRODUCT_ID, GATEWAY_PRODUCT_ID, HUB_SERVICE_PRODUCT_ID};

/// Product IDs to track updates for
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Product {
    /// Devolutions Gateway service
    Gateway,
    /// Devolutions Hub Service
    HubService,
    /// Devolutions Agent service (self-update)
    Agent,
}

impl fmt::Display for Product {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Product::Gateway => write!(f, "Gateway"),
            Product::HubService => write!(f, "HubService"),
            Product::Agent => write!(f, "Agent"),
        }
    }
}

impl FromStr for Product {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Gateway" => Ok(Product::Gateway),
            "HubService" => Ok(Product::HubService),
            "Agent" => Ok(Product::Agent),
            _ => Err(()),
        }
    }
}

impl Product {
    /// Convert to the corresponding [`UpdateProductKey`] for looking up update info in a products map.
    pub(crate) fn as_update_product_key(self) -> UpdateProductKey {
        match self {
            Product::Gateway => UpdateProductKey::Gateway,
            Product::HubService => UpdateProductKey::HubService,
            Product::Agent => UpdateProductKey::Agent,
        }
    }

    pub(crate) const fn get_productinfo_id(self) -> &'static str {
        match self {
            Product::Gateway => GATEWAY_PRODUCT_ID,
            Product::HubService => HUB_SERVICE_PRODUCT_ID,
            Product::Agent => AGENT_PRODUCT_ID,
        }
    }

    pub(crate) const fn get_package_extension(self) -> &'static str {
        match self {
            Product::Gateway | Product::HubService | Product::Agent => "msi",
        }
    }
}
