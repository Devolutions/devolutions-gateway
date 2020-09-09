use crate::{rdp::preconnection_pdu::decode_preconnection_pdu, transport::x224::NegotiationWithClientTransport};
use bytes::BytesMut;
use futures::{try_ready, Async, Future, Poll};
use ironrdp::{nego, PduBufferParsing, PreconnectionPdu};
use slog_scope::error;
use std::io;
use tokio::{codec::Decoder, io::AsyncRead, net::tcp::TcpStream};

const MAX_CONNECTION_PACKET_SIZE: usize = 4096;

pub enum ClientConnectionPacket {
    PreconnectionPdu {
        pdu: PreconnectionPdu,
        leftover_request: BytesMut,
    },
    NegotiationWithClient(nego::Request),
}

pub struct AcceptConnectionFuture {
    nego_transport: NegotiationWithClientTransport,
    client: Option<TcpStream>,
    buffer: BytesMut,
}

impl AcceptConnectionFuture {
    pub fn new(client: TcpStream) -> Self {
        Self {
            nego_transport: NegotiationWithClientTransport::default(),
            client: Some(client),
            buffer: BytesMut::default(),
        }
    }
}

impl Future for AcceptConnectionFuture {
    type Item = (TcpStream, ClientConnectionPacket);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Read more data to parse
        let mut received = [0u8; MAX_CONNECTION_PACKET_SIZE];

        let read_bytes = try_ready!(self
            .client
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid state, TCP stream is missing"))?
            .poll_read(&mut received));

        self.buffer.extend_from_slice(&received[..read_bytes]);

        // Detect first packet
        match self.nego_transport.decode(&mut self.buffer) {
            Ok(Some(request)) => Ok(Async::Ready((
                self.client.take().unwrap(),
                ClientConnectionPacket::NegotiationWithClient(request),
            ))),
            Ok(None) => Ok(Async::NotReady),
            Err(negotiate_error) => match decode_preconnection_pdu(&mut self.buffer) {
                Ok(Some(pdu)) => {
                    let leftover_request = self.buffer.split_off(pdu.buffer_length());
                    Ok(Async::Ready((
                        self.client.take().unwrap(),
                        ClientConnectionPacket::PreconnectionPdu { pdu, leftover_request },
                    )))
                }
                Ok(None) => Ok(Async::NotReady),
                Err(preconnection_pdu_error) => {
                    error!("NegotiationWithClient transport failed: {}", negotiate_error);
                    error!("PreconnectionPdu transport failed: {}", preconnection_pdu_error);
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid connection sequence start",
                    ))
                }
            },
        }
    }
}
