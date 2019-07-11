#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rdp_proto;

use bytes::BytesMut;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(data);

    rdp_proto::decode_x224(&mut buf);
});
