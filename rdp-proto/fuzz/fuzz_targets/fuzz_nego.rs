#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rdp_proto;

use rdp_proto::X224TPDUType;

fuzz_target!(|data: &[u8]| {
    let _ = rdp_proto::parse_negotiation_request(X224TPDUType::ConnectionRequest, data);
    let _ = rdp_proto::parse_negotiation_response(X224TPDUType::ConnectionConfirm, data);
});
