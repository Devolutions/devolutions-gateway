mod db;

pub(crate) const DEVOLUTIONS_PRODUCTINFO_URL: &str = "https://devolutions.net/productinfo.htm";

#[cfg(windows)]
pub(crate) const GATEWAY_PRODUCT_ID: &str = "Gatewaybin";
#[cfg(not(windows))]
pub(crate) const GATEWAY_PRODUCT_ID: &str = "GatewaybinDebX64";

pub(crate) use db::ProductInfoDb;
