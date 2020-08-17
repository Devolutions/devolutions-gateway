use std::io;

use bytes::BytesMut;
use ironrdp::{PreconnectionPdu, PreconnectionPduError, PduBufferParsing};
use tokio::codec::{Decoder, Encoder};

#[derive(Default)]
pub struct PreconnectionPduTransport;

impl Decoder for PreconnectionPduTransport {
    type Item = PreconnectionPdu;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut packet = buf.as_ref();

        match PreconnectionPdu::from_buffer_consume(&mut packet) {
            Ok(preconnection_pdu) => {
                let bytes_to_consume = buf.len() - packet.len();
                buf.split_at(bytes_to_consume);
                Ok(Some(preconnection_pdu))
            },
            Err(PreconnectionPduError::InvalidDataLength { .. }) => Ok(None),
            Err(PreconnectionPduError::IoError(e)) => Err(e),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}", e))),
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
                format!("Failed to serialize Preconnection PDU: {}", e)
            )
        })?;
        buf.extend_from_slice(&buffer);

        Ok(())
    }
}
