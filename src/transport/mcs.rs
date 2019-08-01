use std::io;

use bytes::BytesMut;
use ironrdp::PduParsing;
use tokio::codec::{Decoder, Encoder};

use crate::transport::x224;

#[derive(Default)]
pub struct McsTransport {
    x224_transport: x224::X224Transport,
}

impl Decoder for McsTransport {
    type Item = ironrdp::McsPdu;
    type Error = io::Error;

    fn decode(&mut self, mut buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (code, mcs_pdu_buffer) = codec_try!(self.x224_transport.decode(&mut buf));
        if code == ironrdp::X224TPDUType::Data {
            Ok(Some(ironrdp::McsPdu::from_buffer(mcs_pdu_buffer.as_ref())?))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Got invalid X224 TPDU type: {:?}", code),
            ))
        }
    }
}

impl Encoder for McsTransport {
    type Item = ironrdp::McsPdu;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, mut buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut data = BytesMut::new();
        data.resize(item.buffer_length(), 0);
        item.to_buffer(data.as_mut())?;

        self.x224_transport
            .encode((ironrdp::X224TPDUType::Data, data), &mut buf)
    }
}
