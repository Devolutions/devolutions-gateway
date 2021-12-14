#![no_main]

use jet_proto::JetMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let _ = JetMessage::read_request(&mut data);
    let _ = JetMessage::read_accept_response(&mut data);
    let _ = JetMessage::read_connect_response(&mut data);
});
