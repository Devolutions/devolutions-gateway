use std::io;

use bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};

#[derive(Default)]
pub struct X224Transport {}

impl X224Transport {
    pub fn new() -> X224Transport {
        X224Transport {}
    }
}

impl Decoder for X224Transport {
    type Item = (ironrdp::X224TPDUType, BytesMut);
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (code, tpdu) = io_try!(ironrdp::decode_x224(buf));

        Ok(Some((code, tpdu)))
    }
}

impl Encoder for X224Transport {
    type Item = (ironrdp::X224TPDUType, BytesMut);
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let (code, data) = item;

        let tpdu_header_len = ironrdp::tpdu_header_length(code);

        let length = tpdu_header_len + data.len();
        buf.reserve(length);
        buf.resize(tpdu_header_len, 0);

        ironrdp::encode_x224(code, data, buf)?;

        Ok(())
    }
}
