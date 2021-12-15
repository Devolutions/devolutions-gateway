pub mod generators;

use bytes::{Bytes, BytesMut};
use jmux_proto::Message;

pub fn check_encode_decode(sample_msg: Message, raw_msg: &[u8]) {
    let mut encoded = BytesMut::new();
    sample_msg.encode(&mut encoded).unwrap();
    assert_eq!(raw_msg.to_vec(), encoded.to_vec());

    let decoded = Message::decode(Bytes::copy_from_slice(raw_msg)).unwrap();
    assert_eq!(sample_msg, decoded);
}
