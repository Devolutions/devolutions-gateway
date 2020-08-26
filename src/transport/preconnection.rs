use std::io;

use bytes::BytesMut;
use ironrdp::{PduBufferParsing, PreconnectionPdu, PreconnectionPduError};
use tokio::codec::{Decoder, Encoder};
#[derive(Default)]
pub struct PreconnectionPduTransport;

impl Decoder for PreconnectionPduTransport {
    type Item = PreconnectionPdu;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut parsing_buffer = buf.as_ref();
        match PreconnectionPdu::from_buffer_consume(&mut parsing_buffer) {
            Ok(preconnection_pdu) => {
                buf.split_at(preconnection_pdu.buffer_length());
                Ok(Some(preconnection_pdu))
            }
            Err(PreconnectionPduError::IoError(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse Preconnection PDU: {}", e),
            )),
        }
    }
}

impl Encoder for PreconnectionPduTransport {
    type Item = PreconnectionPdu;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let required_buffer_size = item.buffer_length();
        let mut buffer = vec![0u8; required_buffer_size];
        item.to_buffer_consume(&mut buffer.as_mut_slice()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to serialize Preconnection PDU: {}", e),
            )
        })?;
        buf.extend_from_slice(&buffer);

        Ok(())
    }
}
