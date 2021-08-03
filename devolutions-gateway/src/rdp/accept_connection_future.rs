use crate::config::Config;
use crate::rdp::preconnection_pdu::{self, decode_preconnection_pdu, TokenRoutingMode};
use crate::rdp::RdpIdentity;
use crate::transport::x224::NegotiationWithClientTransport;
use bytes::BytesMut;
use futures::ready;
use ironrdp::{nego, PduBufferParsing};
use jet_proto::token::JetAssociationTokenClaims;
use std::future::Future;
use std::io;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::codec::Decoder;
use url::Url;
use uuid::Uuid;

const READ_BUFFER_SIZE: usize = 4 * 1024;
const MAX_FUTURE_BUFFER_SIZE: usize = 64 * 1024;

pub enum AcceptConnectionMode {
    RdpTcp {
        url: Url,
        leftover_request: BytesMut,
    },
    RdpTcpRendezvous {
        association_id: Uuid,
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
    rdp_identity: Option<(RdpIdentity, JetAssociationTokenClaims)>,
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

    fn read_bytes_into_buffer(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let mut received = [0u8; READ_BUFFER_SIZE];
        let pinned_client = Pin::new(
            self.client
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid state, TCP stream is missing"))?,
        );

        let mut read_buf = ReadBuf::new(&mut received);
        ready!(pinned_client.poll_read(cx, &mut read_buf))?;

        let read_bytes = read_buf.filled().len();

        if read_bytes == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "No data to read, EOF has been reached.",
            )));
        }

        self.buffer.extend_from_slice(&received[..read_bytes]);

        if self.buffer.len() > MAX_FUTURE_BUFFER_SIZE {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Connection sequence is too long".to_string(),
            )));
        }

        Poll::Ready(Ok(()))
    }
}

impl Future for AcceptConnectionFuture {
    type Output = Result<(TcpStream, AcceptConnectionMode, JetAssociationTokenClaims), io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut more_data_required = true;
        loop {
            if more_data_required {
                ready!(self.as_mut().read_bytes_into_buffer(cx))?;
            }

            match self.rdp_identity.take() {
                None => match decode_preconnection_pdu(&mut self.buffer) {
                    Ok(Some(pdu)) => {
                        let leftover_request = self.buffer.split_off(pdu.buffer_length());
                        let routing_claims = preconnection_pdu::extract_routing_claims(&pdu, &self.config)?;
                        let mode = preconnection_pdu::resolve_routing_mode(&routing_claims)?;
                        match mode {
                            TokenRoutingMode::RdpTcp(url) => {
                                return Poll::Ready(Ok((
                                    self.client.take().unwrap(),
                                    AcceptConnectionMode::RdpTcp { url, leftover_request },
                                    routing_claims.into(),
                                )));
                            }
                            TokenRoutingMode::RdpTcpRendezvous(association_id) => {
                                return Poll::Ready(Ok((
                                    self.client.take().unwrap(),
                                    AcceptConnectionMode::RdpTcpRendezvous {
                                        association_id,
                                        leftover_request,
                                    },
                                    routing_claims.into(),
                                )));
                            }
                            TokenRoutingMode::RdpTls(identity) => {
                                self.buffer = leftover_request;
                                self.rdp_identity = Some((identity, routing_claims.into()));
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
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Invalid connection sequence start,\
                                 expected PreconnectionPdu but got something else: {}",
                                e
                            ),
                        )));
                    }
                },
                Some((identity, claims)) => {
                    let Self {
                        nego_transport,
                        buffer,
                        client,
                        rdp_identity,
                        ..
                    } = self.deref_mut();
                    match nego_transport.decode(buffer) {
                        Ok(Some(request)) => {
                            return Poll::Ready(Ok((
                                client.take().unwrap(),
                                AcceptConnectionMode::RdpTls { identity, request },
                                claims,
                            )));
                        }
                        Ok(None) => {
                            // Read more data, keep the same state
                            *rdp_identity = Some((identity, claims));
                            more_data_required = true;
                        }
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "Invalid connection sequence start,\
                                expected negotiation Request but got something else: {}",
                                    e
                                ),
                            )));
                        }
                    }
                }
            }
        }
    }
}
