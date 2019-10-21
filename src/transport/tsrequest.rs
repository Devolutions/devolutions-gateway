use std::io;

use bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};

use crate::io_try;

#[derive(Default)]
pub struct TsRequestTransport {}

impl Decoder for TsRequestTransport {
    type Item = sspi::TsRequest;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let ts_request = io_try!(sspi::TsRequest::from_buffer(buf.as_ref()));
        buf.split_to(ts_request.buffer_len() as usize);

        Ok(Some(ts_request))
    }
}

impl Encoder for TsRequestTransport {
    type Item = sspi::TsRequest;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let len = item.buffer_len();
        buf.resize(len as usize, 0x00);

        item.encode_ts_request(buf.as_mut())?;

        Ok(())
    }
}
