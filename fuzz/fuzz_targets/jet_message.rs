#![no_main]

use jet_proto::JetMessage;
use libfuzzer_sys::fuzz_target;

macro_rules! fuzz_message {
    ($data:expr, $method:ident) => {{
        let input_buf = &mut $data;
        let len_before = input_buf.len();
        if let Ok(msg) = JetMessage::$method(input_buf) {
            let len_after = input_buf.len();
            let read_len = len_before - len_after;

            let mut output_buf = Vec::new();
            msg.write_to(&mut output_buf).unwrap();

            assert_eq!(output_buf.len(), read_len);
            assert_eq!(output_buf.as_slice(), &input_buf[..read_len]);
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    fuzz_message!(data, read_request);
    fuzz_message!(data, read_accept_response);
    fuzz_message!(data, read_connect_response);
});
