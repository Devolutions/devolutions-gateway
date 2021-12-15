#![no_main]

use bytes::{Bytes, BytesMut};
use jmux_proto::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Message::decode(Bytes::copy_from_slice(data)) {
        msg.encode(&mut BytesMut::new()).unwrap();
    }
});
