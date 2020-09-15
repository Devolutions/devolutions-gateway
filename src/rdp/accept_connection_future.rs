use crate::{rdp::preconnection_pdu::decode_preconnection_pdu, transport::x224::NegotiationWithClientTransport};
use bytes::BytesMut;
use futures::{try_ready, Async, Future, Poll};
use ironrdp::{nego, PduBufferParsing, PreconnectionPdu};
use std::io;
use tokio::{codec::Decoder, io::AsyncRead, net::tcp::TcpStream};

const MAX_CONNECTION_PACKET_SIZE: usize = 4096;

pub struct AcceptConnectionFuture {
    nego_transport: NegotiationWithClientTransport,
    client: Option<TcpStream>,
    buffer: BytesMut,
    pdu: Option<PreconnectionPdu>,
}

impl AcceptConnectionFuture {
    pub fn new(client: TcpStream) -> Self {
        Self {
            nego_transport: NegotiationWithClientTransport::default(),
            client: Some(client),
            buffer: BytesMut::default(),
            pdu: None,
        }
    }
}

impl Future for AcceptConnectionFuture {
    type Item = (TcpStream, PreconnectionPdu, nego::Request);
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

        loop {
            match self.pdu.take() {
                None => match decode_preconnection_pdu(&mut self.buffer) {
                    Ok(Some(pdu)) => {
                        let leftover_request = self.buffer.split_off(pdu.buffer_length());
                        self.buffer = leftover_request;
                        self.pdu = Some(pdu);
                    }
                    Ok(None) => return Ok(Async::NotReady),
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Invalid connection sequence start,\
                                 expected PreconnectionPdu but got something else: {}",
                                e
                            ),
                        ))
                    }
                },
                Some(pdu) => match self.nego_transport.decode(&mut self.buffer) {
                    Ok(Some(request)) => {
                        return Ok(Async::Ready((self.client.take().unwrap(), pdu, request)));
                    }
                    Ok(None) => {
                        self.pdu = Some(pdu);
                        return Ok(Async::NotReady);
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Invalid connection sequence start,\
                                 expected negotiation Request but got something else: {}",
                                e
                            ),
                        ))
                    }
                },
            }
        }
    }
}
