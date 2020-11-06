use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    ops::DerefMut,
};
use bytes::BytesMut;
use futures::ready;
use ironrdp::{nego, PduBufferParsing};
use std::{io, sync::Arc};
use tokio::{
    io::{
        ReadBuf,
        AsyncRead,
    },
    net::TcpStream
};
use tokio_util::codec::Decoder;
use url::Url;
use crate::{
    config::Config,
    rdp::{
        preconnection_pdu::{decode_preconnection_pdu, TokenRoutingMode},
        RdpIdentity,
    },
    transport::x224::NegotiationWithClientTransport,
};

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

    fn read_bytes_into_buffer(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let mut received = [0u8; READ_BUFFER_SIZE];
        let pinned_client = Pin::new(self
            .client
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid state, TCP stream is missing"))?);

        let mut read_buf = ReadBuf::new(&mut received);
        ready!(pinned_client.poll_read(cx, &mut read_buf))?;

        let read_bytes = read_buf.filled().len();
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
    type Output = Result<(TcpStream, AcceptConnectionMode), io::Error>;

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
                        let mode = crate::rdp::preconnection_pdu::resolve_routing_mode(&pdu, &self.config)?;
                        match mode {
                            TokenRoutingMode::RdpTcp(url) => {
                                return Poll::Ready(Ok((
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
                Some(identity) => {
                    let (nego_transport, mut buffer, client, mut rdp_identity) = match self.deref_mut() {
                        Self { nego_transport,buffer, client, rdp_identity, ..} => {
                            (nego_transport, buffer, client, rdp_identity)
                        }
                    };

                    match nego_transport.decode(&mut buffer) {
                        Ok(Some(request)) => {
                            return Poll::Ready(Ok((
                                client.take().unwrap(),
                                AcceptConnectionMode::RdpTls { identity, request },
                            )));
                        }
                        Ok(None) => {
                            // Read more data, keep the same state
                            *rdp_identity = Some(identity);
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
