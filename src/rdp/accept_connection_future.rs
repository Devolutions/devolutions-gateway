use crate::{
    config::Config,
    rdp::{
        preconnection_pdu::{decode_preconnection_pdu, TokenRoutingMode},
        RdpIdentity,
    },
    transport::x224::NegotiationWithClientTransport,
};
use bytes::BytesMut;
use futures::{try_ready, Async, Future, Poll};
use ironrdp::{nego, PduBufferParsing};
use std::{io, sync::Arc};
use tokio::{codec::Decoder, io::AsyncRead, net::tcp::TcpStream};
use url::Url;

const READ_BUFFER_SIZE: usize = 4 * 1024;
const MAX_FUTURE_BUFFER_SIZE: usize = 64 * 1024;

pub enum AcceptConnectionMode {
    RdpTcp {
        url: Url,
        leftover_request: BytesMut,
    },
    RdpTls {
        identity: RdpIdentity,
        request: nego::Request,
    },
}

pub struct AcceptConnectionFuture {
    nego_transport: NegotiationWithClientTransport,
    client: Option<TcpStream>,
    buffer: BytesMut,
    rdp_identity: Option<RdpIdentity>,
    config: Arc<Config>,
}

impl AcceptConnectionFuture {
    pub fn new(client: TcpStream, config: Arc<Config>) -> Self {
        Self {
            nego_transport: NegotiationWithClientTransport::default(),
            client: Some(client),
            buffer: BytesMut::default(),
            rdp_identity: None,
            config,
        }
    }

    fn read_bytes_into_buffer(&mut self) -> Result<futures::Async<()>, io::Error> {
        let mut received = [0u8; READ_BUFFER_SIZE];
        let read_bytes = try_ready!(self
            .client
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid state, TCP stream is missing"))?
            .poll_read(&mut received));

        self.buffer.extend_from_slice(&received[..read_bytes]);

        if self.buffer.len() > MAX_FUTURE_BUFFER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Connection sequence is too long".to_string(),
            ));
        }

        Ok(futures::Async::Ready(()))
    }
}

impl Future for AcceptConnectionFuture {
    type Item = (TcpStream, AcceptConnectionMode);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut more_data_required = true;
        loop {
            if more_data_required {
                try_ready!(self.read_bytes_into_buffer());
            }

            match self.rdp_identity.take() {
                None => match decode_preconnection_pdu(&mut self.buffer) {
                    Ok(Some(pdu)) => {
                        let leftover_request = self.buffer.split_off(pdu.buffer_length());
                        let mode = crate::rdp::preconnection_pdu::resolve_routing_mode(&pdu, &self.config)?;
                        match mode {
                            TokenRoutingMode::RdpTcp(url) => {
                                return Ok(Async::Ready((
                                    self.client.take().unwrap(),
                                    AcceptConnectionMode::RdpTcp { url, leftover_request },
                                )));
                            }
                            TokenRoutingMode::RdpTls(identity) => {
                                self.buffer = leftover_request;
                                self.rdp_identity = Some(identity);
                                // assume that we received connection request in the same buffer
                                // as preconnection_pdu
                                more_data_required = false;
                            }
                        }
                    }
                    Ok(None) => {
                        more_data_required = true;
                    }
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
                Some(identity) => {
                    match self.nego_transport.decode(&mut self.buffer) {
                        Ok(Some(request)) => {
                            return Ok(Async::Ready((
                                self.client.take().unwrap(),
                                AcceptConnectionMode::RdpTls { identity, request },
                            )));
                        }
                        Ok(None) => {
                            // Read more data, keep the same state
                            self.rdp_identity = Some(identity);
                            more_data_required = true;
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
                    }
                }
            }
        }
    }
}
