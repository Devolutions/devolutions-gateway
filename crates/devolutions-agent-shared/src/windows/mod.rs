mod reversed_hex_uuid;

pub mod registry;

use uuid::{Uuid, uuid};

#[rustfmt::skip]
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

/// MSI upgrade code for the Devolutions Hub Service.
///
/// See [`GATEWAY_UPDATE_CODE`] for more information on update codes.
pub const HUB_SERVICE_UPDATE_CODE: Uuid = uuid!("{f437046e-8e13-430a-8c8f-29fcb9023b59}");

/// MSI upgrade code for the Remote Desktop Manager.
///
/// See [`GATEWAY_UPDATE_CODE`] for more information on update codes.
pub const RDM_UPDATE_CODE: Uuid = uuid!("{2707F3BF-4D7B-40C2-882F-14B0ED869EE8}");
