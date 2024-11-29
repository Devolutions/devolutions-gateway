mod reversed_hex_uuid;

pub mod registry;

use uuid::{uuid, Uuid};

pub use reversed_hex_uuid::InvalidReversedHexUuid;

/// MSI upgrade code for the Devolutions Gateway.
///
/// MSI update code is same for all versions of the product, while product code is different for
/// each version. We are using the update code to find installed product version or its product
/// code in the Windows registry.
pub const GATEWAY_UPDATE_CODE: Uuid = uuid!("{db3903d6-c451-4393-bd80-eb9f45b90214}");
/// MSI upgrade code for the Devolutions Agent.
///
/// See [`GATEWAY_UPDATE_CODE`] for more information on update codes.
pub const AGENT_UPDATE_CODE: Uuid = uuid!("{82318d3c-811f-4d5d-9a82-b7c31b076755}");
