mod accept_connection_future;
mod connection_sequence_future;
mod dvc_manager;
mod filter;
mod identities_proxy;
mod preconnection_pdu;
mod sequence_future;

pub use self::{
    dvc_manager::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME},
    identities_proxy::{IdentitiesProxy, RdpIdentity},
};

use std::{io, sync::Arc};

use bytes::IntoBuf;
use futures::{Future, IntoFuture};
use slog_scope::{debug, error, info};
use tokio::{io::AsyncWrite, net::tcp::TcpStream};
use tokio_rustls::TlsAcceptor;
use url::Url;

use self::{
    accept_connection_future::AcceptConnectionFuture, connection_sequence_future::ConnectionSequenceFuture,
    sequence_future::create_downgrade_dvc_capabilities_future,
};

use crate::rdp::accept_connection_future::ClientConnectionPacket;
use crate::{
    config::Config,
    interceptor::rdp::RdpMessageReader,
    rdp::connection_sequence_future::RdpProxyConnection,
    transport::{tcp::TcpTransport, Transport},
    utils, Proxy,
};

pub const GLOBAL_CHANNEL_NAME: &str = "GLOBAL";
pub const USER_CHANNEL_NAME: &str = "USER";
pub const DR_DYN_VC_CHANNEL_NAME: &str = "drdynvc";

#[allow(unused)]
pub struct RdpClient {
    routing_url: Url,
    config: Arc<Config>,
    tls_public_key: Vec<u8>,
    tls_acceptor: TlsAcceptor,
}

impl RdpClient {
    pub fn new(routing_url: Url, config: Arc<Config>, tls_public_key: Vec<u8>, tls_acceptor: TlsAcceptor) -> Self {
        Self {
            routing_url,
            config,
            tls_public_key,
            tls_acceptor,
        }
    }

    pub fn serve(self, client: TcpStream) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let config = self.config.clone();
        let tls_acceptor = self.tls_acceptor;
        let tls_public_key = self.tls_public_key;
        let identities_proxy = if let Some(rdp_identities) = self.config.rdp_identities() {
            rdp_identities.clone()
        } else {
            error!("Identities file is not present");

            return Box::new(futures::future::err(io::Error::new(
                io::ErrorKind::Other,
                "identities file is not present",
            )));
        };

        Box::new(
            AcceptConnectionFuture::new(client)
                .map_err(|e| {
                    error!("Accept connection failed: {}", e);
                    e
                })
                .and_then(|(client, accept_connection_result)| match accept_connection_result {
                    ClientConnectionPacket::PreconnectionPdu { pdu, leftover_request } => {
                        let future = preconnection_pdu::resolve_route(&pdu, config.clone())
                            .into_future()
                            .and_then(|route| {
                                let server_conn = TcpTransport::connect(&route.dest_host);
                                let client_transport = TcpTransport::new(client);

                                debug!("Starting Tcp redirection specified by JWT token inside preconnection PDU");

                                let mut leftover_request = leftover_request.into_buf();
                                server_conn
                                    .and_then(move |mut server_transport| {
                                        server_transport
                                            .write_buf(&mut leftover_request)
                                            .and_then(|_| Ok(server_transport))
                                    })
                                    .and_then(move |server_transport| {
                                        Proxy::new(config.clone()).build_with_message_reader(
                                            server_transport,
                                            client_transport,
                                            None,
                                        )
                                    })
                            });
                        let boxed_future: Box<dyn Future<Item = (), Error = io::Error> + Send> = Box::new(future);
                        boxed_future
                    }
                    ClientConnectionPacket::NegotiationWithClient(request) => {
                        let future = ConnectionSequenceFuture::new(
                            client,
                            request,
                            tls_public_key,
                            tls_acceptor,
                            identities_proxy,
                        )
                        .map_err(move |e| {
                            error!("RDP Connection Sequence failed: {}", e);

                            io::Error::new(io::ErrorKind::Other, e)
                        })
                        .and_then(
                            |RdpProxyConnection {
                                 client: client_transport,
                                 server: server_transport,
                                 channels: joined_static_channels,
                             }| {
                                info!("RDP Connection Sequence finished");
                                futures::lazy(move || {
                                    let joined_static_channels = utils::swap_hashmap_kv(joined_static_channels);

                                    let drdynvc_channel_id =
                                        *joined_static_channels.get(DR_DYN_VC_CHANNEL_NAME).ok_or_else(|| {
                                            io::Error::new(io::ErrorKind::Other, "DVC channel was not joined")
                                        })?;

                                    Ok((joined_static_channels, drdynvc_channel_id))
                                })
                                .and_then(move |(joined_static_channels, drdynvc_channel_id)| {
                                    create_downgrade_dvc_capabilities_future(
                                        client_transport,
                                        server_transport,
                                        drdynvc_channel_id,
                                        DvcManager::with_allowed_channels(
                                            vec![RDP8_GRAPHICS_PIPELINE_NAME.to_string()],
                                        ),
                                    )
                                    .and_then(|dvc_future_result| Ok((dvc_future_result, joined_static_channels)))
                                })
                                .map_err(|e| {
                                    io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("Failed to downgrade DVC capabilities: {}", e),
                                    )
                                })
                                .and_then(
                                    move |(dvc_future_result, joined_static_channels)| {
                                        let (client_transport, server_transport, dvc_manager) = dvc_future_result;

                                        let client_tls = client_transport.into_inner();
                                        let server_tls = server_transport.into_inner();

                                        Proxy::new(config)
                                            .build_with_message_reader(
                                                TcpTransport::new_tls(server_tls),
                                                TcpTransport::new_tls(client_tls),
                                                Some(Box::new(RdpMessageReader::new(
                                                    joined_static_channels,
                                                    dvc_manager,
                                                ))),
                                            )
                                            .map_err(move |e| {
                                                error!("Proxy error: {}", e);
                                                e
                                            })
                                    },
                                )
                            },
                        );
                        let boxed_future: Box<dyn Future<Item = (), Error = io::Error> + Send> = Box::new(future);
                        boxed_future
                    }
                }),
        )
    }
}
