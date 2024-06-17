mod db;

pub const DEVOLUTIONS_PRODUCTINFO_URL: &str = "https://devolutions.net/productinfo.htm";

#[cfg(windows)]
pub const GATEWAY_PRODUCT_ID: &str = "Gatewaybin";
#[cfg(not(windows))]
pub const GATEWAY_PRODUCT_ID: &str = "GatewaybinDebX64";

pub use db::ProductInfoDb;
