#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rdp_proto;

use rdp_proto::{ConnectInitial, ConnectResponse};

use crate::rdp_proto::PduParsing;

fuzz_target!(|data: &[u8]| {
    let _ = ConnectInitial::from_buffer(data);
    let _ = ConnectResponse::from_buffer(data);
});
