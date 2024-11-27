mod uuid;

pub mod registry;

pub use uuid::UuidError;

/// MSI upgrade code for the Devolutions Gateway.
pub const GATEWAY_UPDATE_CODE: &str = "{db3903d6-c451-4393-bd80-eb9f45b90214}";
/// MSI upgrade code for the Devolutions Agent.
pub const AGENT_UPDATE_CODE: &str = "{c3d81328-f118-4d5d-9a82-b7c31b076755}";
