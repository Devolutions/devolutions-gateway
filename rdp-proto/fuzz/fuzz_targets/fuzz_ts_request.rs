#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rdp_proto;

use rdp_proto::TsRequest;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = TsRequest::from_buffer(data) {
        let _req_len = req.buffer_len();
        let _result = req.check_error();
    }
    
    let _creds = rdp_proto::ts_request::read_ts_credentials(data);
});
