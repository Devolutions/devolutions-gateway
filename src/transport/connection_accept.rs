use std::io;

use bytes::BytesMut;
use ironrdp::{nego::Request as NegotiationRequest, PduBufferParsing, PreconnectionPdu};

use slog_scope::error;
use tokio::codec::{Decoder, Encoder};

use crate::transport::{preconnection::PreconnectionPduTransport, x224::NegotiationWithClientTransport};

pub enum ConnectionAcceptTransportResult {
    PreconnectionPdu {
        pdu: PreconnectionPdu,
        leftover_request: BytesMut,
    },
    NegotiationWithClient(NegotiationRequest),
}

#[derive(Default)]
pub struct ConnectionAcceptTransport {
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
            Ok(Some(data)) => Ok(Some(ConnectionAcceptTransportResult::NegotiationWithClient(data))),
            Ok(None) => Ok(None),
            Err(negotiate_error) => self
                .preconnection_transport
                .decode(&mut buf)
                .map(|parsing_result| {
                    parsing_result.map(|pdu| {
                        let leftover_request = buf.split_off(pdu.buffer_length());
                        ConnectionAcceptTransportResult::PreconnectionPdu { pdu, leftover_request }
                    })
                })
                .map_err(|preconnection_pdu_error| {
                    error!("NegotiationWithClient transport failed: {}", negotiate_error);
                    error!("PreconnectionPdu transport failed: {}", preconnection_pdu_error);
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid connection sequence start")
                }),
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
