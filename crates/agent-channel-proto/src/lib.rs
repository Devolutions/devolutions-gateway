//! Protobuf and gRPC definitions for the agent channel.
//!
//! The schema is `proto/channel.proto`, defined by `docs/agent-identity/CONTRACT.agent-identity.md` §7.1.

#[allow(
    unused_qualifications,
    clippy::clone_on_ref_ptr,
    clippy::pedantic,
    reason = "generated code; the set of triggered lints depends on the proto"
)]
mod generated {
    tonic::include_proto!("devolutions.agent.channel.v1");
}

pub use generated::*;

/// Full gRPC service name of the channel.
pub const SERVICE_NAME: &str = "devolutions.agent.channel.v1.AgentChannel";

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::*;

    const USER: &str = "01234567-89ab-4cde-8fab-0123456789ab";
    const EPOCH: &str = "12345678-9abc-4def-8abc-123456789abc";

    fn text_field(number: u8, value: &str) -> Vec<u8> {
        let mut bytes = vec![
            (number << 3) | 2,
            u8::try_from(value.len()).expect("test value fits in one byte"),
        ];
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §channel
    #[test]
    fn requests_and_unavailable_reports_encode_opaque_targets() {
        let sync = SyncInventory {
            target_user_uuid: USER.to_owned(),
            registry_epoch: EPOCH.to_owned(),
        };
        assert_eq!(
            sync.encode_to_vec(),
            [text_field(2, USER), text_field(3, EPOCH)].concat()
        );

        let unavailable = InventoryUnavailable {
            target_user_uuid: USER.to_owned(),
            registry_epoch: EPOCH.to_owned(),
            ..Default::default()
        };
        assert_eq!(
            unavailable.encode_to_vec(),
            [text_field(3, USER), text_field(4, EPOCH)].concat()
        );

        let operation = PackageOperationRequest {
            target_user_uuid: USER.to_owned(),
            registry_epoch: EPOCH.to_owned(),
            ..Default::default()
        };
        assert_eq!(
            operation.encode_to_vec(),
            [text_field(9, USER), text_field(10, EPOCH)].concat()
        );
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn operation_reported_scope_distinguishes_empty_from_absent() {
        let mut operation = PackageOperationRequest::default();
        assert!(operation.encode_to_vec().is_empty());

        operation.reported_scope = Some(String::new());
        assert_eq!(operation.encode_to_vec(), [0x5a, 0]);

        operation.reported_scope = Some("machine".to_owned());
        assert_eq!(operation.encode_to_vec(), text_field(11, "machine"));
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §channel
    #[test]
    fn discovery_and_inventory_encode_epochs_and_scan_times() {
        let instance = UniGetUiInstance {
            user_uuid: USER.to_owned(),
            ..Default::default()
        };
        let instances = UniGetUiInstances {
            instances: vec![instance],
            registry_epoch: EPOCH.to_owned(),
        };
        let inner = text_field(5, USER);
        let mut expected = vec![0x0a, u8::try_from(inner.len()).expect("test message fits in one byte")];
        expected.extend(inner);
        expected.extend(text_field(2, EPOCH));
        assert_eq!(instances.encode_to_vec(), expected);

        let timestamp = prost_types::Timestamp { seconds: 1, nanos: 2 };
        let inventory = InventoryReport {
            target_user_uuid: USER.to_owned(),
            registry_epoch: EPOCH.to_owned(),
            scan_completed_at: Some(timestamp),
            update_scan_completed_at: Some(timestamp),
            ..Default::default()
        };
        let expected = [
            text_field(9, USER),
            text_field(10, EPOCH),
            vec![0x5a, 4, 8, 1, 16, 2],
            vec![0x62, 4, 8, 1, 16, 2],
        ]
        .concat();
        assert_eq!(inventory.encode_to_vec(), expected);
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §operations
    #[test]
    fn execution_started_preserves_false_and_absent() {
        let mut result = PackageOperationResult::default();
        assert!(result.encode_to_vec().is_empty());
        result.execution_started = Some(false);
        assert_eq!(result.encode_to_vec(), [0x28, 0]);
        result.execution_started = Some(true);
        assert_eq!(result.encode_to_vec(), [0x28, 1]);
    }
}
