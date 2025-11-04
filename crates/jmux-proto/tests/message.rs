#![expect(clippy::unwrap_used, reason = "test code can panic on errors")]

use bytes::{Bytes, BytesMut};
use jmux_proto::*;

fn check_encode_decode(sample_msg: Message, raw_msg: &[u8]) {
    let mut encoded = BytesMut::new();
    sample_msg.encode(&mut encoded).unwrap();
    assert_eq!(raw_msg.to_vec(), encoded.to_vec());

    let decoded = Message::decode(Bytes::copy_from_slice(raw_msg)).unwrap();
    assert_eq!(sample_msg, decoded);
}

#[test]
fn message_type_try_from() {
    let msg_type = MessageType::try_from(100).unwrap();
    assert_eq!(MessageType::Open, msg_type);

    let msg_type = MessageType::try_from(103).unwrap();
    assert_eq!(MessageType::WindowAdjust, msg_type);

    let msg_type = MessageType::try_from(106).unwrap();
    assert_eq!(MessageType::Close, msg_type);
}

#[test]
fn message_type_try_err_on_invalid_bytes() {
    let msg_type_res = MessageType::try_from(99);
    assert!(msg_type_res.is_err());

    let msg_type_res = MessageType::try_from(107);
    assert!(msg_type_res.is_err());
}

#[test]
fn header_decode_buffer_too_short_err() {
    let err = Header::decode(Bytes::from_static(&[])).err().unwrap();
    assert_eq!(
        "not enough bytes provided to decode HEADER: received 0 bytes, expected 4 bytes",
        err.to_string()
    );
}

#[test]
fn header_decode() {
    let msg = Header::decode(Bytes::from_static(&[102, 7, 16, 0])).unwrap();
    assert_eq!(
        Header {
            ty: MessageType::OpenFailure,
            size: 1808,
            flags: 0,
        },
        msg
    );
}

#[test]
fn header_encode() {
    let header = Header {
        ty: MessageType::OpenSuccess,
        size: 512,
        flags: 0,
    };
    let mut buf = BytesMut::new();
    header.encode(&mut buf);
    assert_eq!(vec![101, 2, 0, 0], buf);
}

#[test]
fn channel_open() {
    let raw_msg = &[
        100, // msg type
        0, 34, // msg size
        0,  // msg flags
        0, 0, 0, 1, // sender channel id
        0, 0, 4, 0, // initial window size
        4, 0, // maximum packet size
        116, 99, 112, 58, 47, 47, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 58, 52, 52,
        51, // destination url: tcp://google.com:443
    ];

    let mut msg_sample = ChannelOpen::new(
        LocalChannelId::from(1),
        4096,
        DestinationUrl::parse_str("tcp://google.com:443").unwrap(),
    );
    msg_sample.initial_window_size = 1024;
    msg_sample.maximum_packet_size = 1024;

    check_encode_decode(Message::Open(msg_sample), raw_msg);
}

#[test]
pub fn channel_open_success() {
    let raw_msg = &[
        101, // msg type
        0, 18, // msg size
        0,  // msg flags
        0, 0, 0, 1, // recipient channel id
        0, 0, 0, 2, // sender channel id
        0, 0, 4, 0, // initial window size
        127, 255, // maximum packet size
    ];

    let msg = ChannelOpenSuccess {
        initial_window_size: 1024,
        sender_channel_id: 2,
        maximum_packet_size: 32767,
        recipient_channel_id: 1,
    };

    check_encode_decode(Message::OpenSuccess(msg), raw_msg);
}

#[test]
pub fn channel_open_failure() {
    let raw_msg = &[
        102, // msg type
        0, 17, // msg size
        0,  // msg flags
        0, 0, 0, 1, // recipient channel id
        0, 0, 0, 2, // reason code
        101, 114, 114, 111, 114, // failure description
    ];

    let msg_example = ChannelOpenFailure {
        recipient_channel_id: 1,
        reason_code: ReasonCode(2),
        description: "error".to_owned(),
    };

    check_encode_decode(Message::OpenFailure(msg_example), raw_msg);
}

#[test]
pub fn channel_window_adjust() {
    let raw_msg = &[
        103, // msg type
        0, 12, // msg size
        0,  // msg flags
        0, 0, 0, 1, // recipient channel id
        0, 0, 2, 0, // window adjustment
    ];

    let msg_example = ChannelWindowAdjust {
        recipient_channel_id: 1,
        window_adjustment: 512,
    };

    check_encode_decode(Message::WindowAdjust(msg_example), raw_msg);
}

#[test]
pub fn error_on_oversized_packet() {
    let mut buf = BytesMut::new();
    let err = Message::data(DistantChannelId::from(1), vec![0; u16::MAX as usize].into())
        .encode(&mut buf)
        .err()
        .unwrap();
    assert_eq!("packet oversized: max is 65535, got 65543", err.to_string());
}

#[test]
pub fn channel_data() {
    let raw_msg = &[
        104, // msg type
        0, 12, // msg size
        0,  // msg flags
        0, 0, 0, 1, // recipient channel id
        11, 12, 13, 14, // transfer data
    ];

    let msg_example = ChannelData {
        recipient_channel_id: 1,
        transfer_data: vec![11, 12, 13, 14].into(),
    };

    check_encode_decode(Message::Data(msg_example), raw_msg);
}

#[test]
pub fn channel_eof() {
    let raw_msg = &[
        105, // msg type
        0, 8, // msg size
        0, // msg flags
        0, 0, 0, 1, // recipient channel id
    ];

    let msg_example = ChannelEof {
        recipient_channel_id: 1,
    };

    check_encode_decode(Message::Eof(msg_example), raw_msg);
}

#[test]
pub fn channel_close() {
    let raw_msg = &[
        106, // msg type
        0, 8, // msg size
        0, // msg flags
        0, 0, 0, 1, // recipient channel id
    ];

    let msg_example = ChannelClose {
        recipient_channel_id: 1,
    };

    check_encode_decode(Message::Close(msg_example), raw_msg);
}

/// Check that the original data is equal to the result of the round-trip.
#[test]
fn lossless_round_trip() {
    use jmux_generators::*;
    use proptest::prelude::*;

    proptest!(|(
        message in any_message(),
    )| {
        let mut buf = BytesMut::new();
        message.encode(&mut buf).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let buf = buf.freeze();
        let decoded = Message::decode(buf).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(message, decoded);
    })
}
