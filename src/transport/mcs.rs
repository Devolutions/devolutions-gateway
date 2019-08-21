use std::io;

use bytes::BytesMut;
use ironrdp::{McsPdu, PduParsing};
use tokio::codec::{Decoder, Encoder};

use crate::transport::x224;

#[derive(Default)]
pub struct McsTransport {
    x224_transport: x224::DataTransport,
}

impl Decoder for McsTransport {
    type Item = ironrdp::McsPdu;
    type Error = io::Error;

    fn decode(&mut self, mut buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(data) = self.x224_transport.decode(&mut buf)? {
            Ok(Some(McsPdu::from_buffer(data.as_ref())?))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for McsTransport {
    type Item = ironrdp::McsPdu;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, mut buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut item_buffer = BytesMut::with_capacity(item.buffer_length());
        item_buffer.resize(item.buffer_length(), 0x00);
        item.to_buffer(item_buffer.as_mut())?;

        self.x224_transport.encode(item_buffer, &mut buf)
    }
}
