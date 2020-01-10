use super::*;

const DRDYNVC_WITH_CAPS_REQUEST_PACKET: [u8; 20] = [
    0x0C, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x58, 0x00, 0x02, 0x00, 0x33, 0x33, 0x11, 0x11, 0x3d, 0x0a, 0xa7,
    0x04,
];
const DRDYNVC_WITH_CAPS_RESPONSE_PACKET: [u8; 12] =
    [0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x50, 0x00, 0x02, 0x00];

const DRDYNVC_WITH_CREATE_RESPONSE_PACKET: [u8; 14] = [
    0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00,
];
const DRDYNVC_WITH_CREATE_REQUEST_PACKET: [u8; 19] = [
    0x0B, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x03, 0x74, 0x65, 0x73, 0x74, 0x64, 0x76, 0x63, 0x31, 0x00,
];
const DRDYNVC_WITH_DATA_FIRST_PACKET: [u8; 57] = [
    0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x03, 0x5C, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
];
const DRDYNVC_WITH_DATA_LAST_PACKET: [u8; 56] = [
    0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x34, 0x03, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
];
const DRDYNVC_WITH_COMPLETE_DATA_PACKET: [u8; 56] = [
    0x30, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x34, 0x03, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
    0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
];
const DRDYNVC_WITH_CLOSE_PACKET: [u8; 10] = [0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x40, 0x03];
const RAW_UNFRAGMENTED_DATA_BUFFER: [u8; 46] = [0x71; 46];
const RAW_FRAGMENTED_DATA_BUFFER: [u8; 92] = [0x71; 92];

const DRDYNVC_WITH_FAILED_CREATION_STATUS_PACKET: [u8; 14] = [
    0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x03, 0x01, 0x00, 0x00, 0x00,
];
const VC_PACKET_WITH_INVALID_TOTAL_DATA_LENGTH: [u8; 9] = [0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00];

const CHANNEL_NAME: &str = "testdvc1";
const CHANNEL_ID: u32 = 0x03;

#[test]
fn dvc_manager_reads_dvc_caps_request_packet_without_error() {
    let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
    let result_message = dvc_manager
        .process(PduSource::Server, DRDYNVC_WITH_CAPS_REQUEST_PACKET.as_ref())
        .unwrap();

    assert_eq!(None, result_message);
}

#[test]
fn dvc_manager_reads_dvc_caps_response_packet_without_error() {
    let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
    let result_message = dvc_manager
        .process(PduSource::Client, DRDYNVC_WITH_CAPS_RESPONSE_PACKET.as_ref())
        .unwrap();

    assert_eq!(None, result_message);
}

#[test]
fn dvc_manager_reads_dvc_create_response_packet_without_error() {
    let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
    let result_message = dvc_manager
        .process(PduSource::Client, DRDYNVC_WITH_CREATE_RESPONSE_PACKET.as_ref())
        .unwrap();

    assert_eq!(None, result_message);
}

#[test]
fn dvc_manager_reads_dvc_close_request_packet_without_error() {
    let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
    let result_message = dvc_manager
        .process(PduSource::Server, DRDYNVC_WITH_CLOSE_PACKET.as_ref())
        .unwrap();

    assert_eq!(None, result_message);
}

#[test]
fn dvc_manager_fails_reading_vc_packet_with_invalid_data_length() {
    let mut dvc_manager = DvcManager::with_allowed_channels(Vec::new());
    match dvc_manager.process(PduSource::Client, VC_PACKET_WITH_INVALID_TOTAL_DATA_LENGTH.as_ref()) {
        Err(vc::ChannelError::InvalidChannelTotalDataLength) => (),
        res => panic!(
            "Expected ChannelError::InvalidChannelTotalDataLength error, got: {:?}",
            res
        ),
    }
}

#[test]
fn dvc_manager_creates_dv_channel() {
    let mut dvc_manager = get_dvc_manager_with_got_create_request_pdu();
    let result_message = dvc_manager
        .process(PduSource::Client, DRDYNVC_WITH_CREATE_RESPONSE_PACKET.as_ref())
        .unwrap();

    assert_eq!(None, result_message);

    let channel_name = dvc_manager.dynamic_channels.get(&CHANNEL_ID).unwrap().name.clone();
    assert_eq!(CHANNEL_NAME, channel_name);

    let channel = dvc_manager.pending_dynamic_channels.get(&CHANNEL_ID);
    assert!(channel.is_none());
}

#[test]
fn dvc_manager_removes_channel_during_create_response() {
    let mut dvc_manager = get_dvc_manager_with_got_create_request_pdu();
    let result_message = dvc_manager
        .process(PduSource::Client, DRDYNVC_WITH_FAILED_CREATION_STATUS_PACKET.as_ref())
        .unwrap();

    assert_eq!(None, result_message);

    let channel = dvc_manager.pending_dynamic_channels.get(&CHANNEL_ID);
    assert!(channel.is_none());

    assert!(dvc_manager.dynamic_channels.is_empty());
}

#[test]
fn dvc_manager_does_not_remove_channel_during_create_response() {
    let mut dvc_manager = get_dvc_manager_with_created_channel();
    let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
    assert!(channel.is_some());

    let result_message = dvc_manager
        .process(PduSource::Client, DRDYNVC_WITH_CREATE_RESPONSE_PACKET.as_ref())
        .unwrap();

    assert_eq!(None, result_message);

    let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
    assert!(channel.is_some());
}

#[test]
fn dvc_manager_removes_dv_channel() {
    let mut dvc_manager = get_dvc_manager_with_created_channel();
    let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
    assert!(channel.is_some());

    let result_message = dvc_manager
        .process(PduSource::Client, DRDYNVC_WITH_CLOSE_PACKET.as_ref())
        .unwrap();

    assert_eq!(None, result_message);

    let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
    assert!(channel.is_none());
}

#[test]
fn dvc_manager_reads_complete_message() {
    let mut dvc_manager = get_dvc_manager_with_created_channel();
    let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
    assert!(channel.is_some());

    let result_message = dvc_manager
        .process(PduSource::Client, DRDYNVC_WITH_COMPLETE_DATA_PACKET.as_ref())
        .unwrap();

    assert_eq!(
        RAW_UNFRAGMENTED_DATA_BUFFER.as_ref(),
        result_message.unwrap().as_slice()
    );
}

#[test]
fn dvc_manager_reads_fragmented_message() {
    let mut dvc_manager = get_dvc_manager_with_created_channel();
    let channel = dvc_manager.dynamic_channels.get(&CHANNEL_ID);
    assert!(channel.is_some());

    let result_message = dvc_manager
        .process(PduSource::Server, DRDYNVC_WITH_DATA_FIRST_PACKET.as_ref())
        .unwrap();
    assert_eq!(None, result_message);

    let result_message = dvc_manager
        .process(PduSource::Server, DRDYNVC_WITH_DATA_LAST_PACKET.as_ref())
        .unwrap();

    assert_eq!(RAW_FRAGMENTED_DATA_BUFFER.as_ref(), result_message.unwrap().as_slice());
}

fn get_dvc_manager_with_created_channel() -> DvcManager {
    let mut dvc_manager = DvcManager::with_allowed_channels(vec![CHANNEL_NAME.to_string()]);
    dvc_manager
        .process(PduSource::Server, DRDYNVC_WITH_CREATE_REQUEST_PACKET.as_ref())
        .unwrap();

    dvc_manager
        .process(PduSource::Client, DRDYNVC_WITH_CREATE_RESPONSE_PACKET.as_ref())
        .unwrap();

    dvc_manager
}

fn get_dvc_manager_with_got_create_request_pdu() -> DvcManager {
    let mut dvc_manager = DvcManager::with_allowed_channels(vec![CHANNEL_NAME.to_string()]);
    dvc_manager
        .process(PduSource::Server, DRDYNVC_WITH_CREATE_REQUEST_PACKET.as_ref())
        .unwrap();

    let channel = dvc_manager.pending_dynamic_channels.get(&CHANNEL_ID).unwrap();
    assert_eq!(CHANNEL_NAME, channel.name);

    assert!(dvc_manager.dynamic_channels.is_empty());

    dvc_manager
}
