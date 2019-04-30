use std::io;

use bytes::BytesMut;
use log::debug;
use tokio::codec::{Decoder, Encoder};

use rdp_proto;

pub struct TsRequestTransport {}

impl TsRequestTransport {
    pub fn new() -> TsRequestTransport {
        TsRequestTransport {}
    }
}

impl Decoder for TsRequestTransport {
    type Item = rdp_proto::TsRequest;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let ts_request = io_try!(rdp_proto::TsRequest::from_buffer(buf.as_ref()));
        debug!("Got TSRequest: {:x?}", ts_request);
        buf.split_to(ts_request.buffer_len() as usize);

        Ok(Some(ts_request))
    }
}

impl Encoder for TsRequestTransport {
    type Item = rdp_proto::TsRequest;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Send TSRequest: {:x?}", item);
        let len = item.buffer_len();
        buf.resize(len as usize, 0x00);

        item.encode_ts_request(buf.as_mut())?;

        Ok(())
    }
}
