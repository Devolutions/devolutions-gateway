use std::io;

use bytes::BytesMut;
use ironrdp::{nego::Request as NegotiationRequest, PreconnectionPdu, PduBufferParsing};

use tokio::codec::{Decoder, Encoder};
use slog_scope::debug;

use crate::transport::{
    preconnection::PreconnectionPduTransport,
    x224::NegotiationWithClientTransport,
};

pub enum ConnectionAcceptTransportResult {
    PreconnectionPdu(PreconnectionPdu, BytesMut),
    NegotiationWithClient(NegotiationRequest),
}

#[derive(Default)]
pub struct ConnectionAcceptTransport  {
    preconnection_transport: PreconnectionPduTransport,
    negotiation_transport: NegotiationWithClientTransport,
}

impl ConnectionAcceptTransport {
    pub fn new() -> Self {
        Self {
            preconnection_transport: PreconnectionPduTransport::default(),
            negotiation_transport: NegotiationWithClientTransport::default(),
        }
    }
}

impl Decoder for ConnectionAcceptTransport {
    type Item = ConnectionAcceptTransportResult;
    type Error = io::Error;

    fn decode(&mut self, mut buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.negotiation_transport.decode(&mut buf) {
            Ok(Some(data)) => {
                Ok(Some(ConnectionAcceptTransportResult::NegotiationWithClient(data)))
            },
            Ok(None) => Ok(None),
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(_) => {
                if let Some(data) = self.preconnection_transport.decode(&mut buf)? {
                    let buff = buf.split_off(data.buffer_length());
                    debug!("Size BUF: {}", buff.len());
                    Ok(Some(ConnectionAcceptTransportResult::PreconnectionPdu(data, buff)))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

impl Encoder for ConnectionAcceptTransport {
    type Item = ();
    type Error = io::Error;

    fn encode(&mut self, _: (), _: &mut BytesMut) -> Result<(), Self::Error> {
        Ok(())
    }
}
