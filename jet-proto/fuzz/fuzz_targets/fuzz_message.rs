#![no_main]
use libfuzzer_sys::fuzz_target;
use jet_proto::JetMessage;

fuzz_target!(|data: &[u8]| {
    let mut data_rw = data.clone();
    let _ = JetMessage::read_request(&mut data_rw);
    let _ = JetMessage::read_accept_response(&mut data_rw);
    let _ = JetMessage::read_connect_response(&mut data_rw);
});
