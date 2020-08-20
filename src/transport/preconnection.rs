use std::io;

use bytes::BytesMut;
use ironrdp::{PreconnectionPdu, PreconnectionPduError, PduBufferParsing};
use tokio::codec::{Decoder, Encoder};
use slog_scope::debug;

#[derive(Default)]
pub struct PreconnectionPduTransport;

pub enum PreconnectionPduFutureResult {
    PreconnectionPduDetected(PreconnectionPdu),
    DifferentProtocolDetected
}

impl Decoder for PreconnectionPduTransport {
    type Item = PreconnectionPduFutureResult;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut parsing_buffer = buf.as_ref();
        match PreconnectionPdu::from_buffer_consume(&mut parsing_buffer) {
            Ok(preconnection_pdu) => {
                buf.split_at(preconnection_pdu.buffer_length());
                Ok(Some(PreconnectionPduFutureResult::PreconnectionPduDetected(preconnection_pdu)))
            },
            Err(PreconnectionPduError::IoError(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Need more data
                Ok(None)
            },
            Err(e) => {
                debug!("Preconnection PDU was not detected: {}", e);
                Ok(Some(PreconnectionPduFutureResult::DifferentProtocolDetected))
            },
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
