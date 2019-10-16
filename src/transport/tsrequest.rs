use std::io;

use bytes::BytesMut;
use sspi::internal::credssp::TsRequest;
use tokio::codec::{Decoder, Encoder};

use crate::io_try;

#[derive(Default)]
pub struct TsRequestTransport {}

impl Decoder for TsRequestTransport {
    type Item = TsRequest;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let ts_request = io_try!(TsRequest::from_buffer(buf.as_ref()));
        buf.split_to(ts_request.buffer_len() as usize);

        Ok(Some(ts_request))
    }
}

impl Encoder for TsRequestTransport {
    type Item = TsRequest;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let item_len = item.buffer_len() as usize;
        let len = buf.len();
        buf.resize(len + item_len, 0);

        item.encode_ts_request(&mut buf[len..])
    }
}
