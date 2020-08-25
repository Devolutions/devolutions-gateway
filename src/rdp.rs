mod connection_sequence_future;
mod dvc_manager;
mod filter;
mod identities_proxy;
mod sequence_future;

pub use self::{
    dvc_manager::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME},
    identities_proxy::{IdentitiesProxy, RdpIdentity},
};

use std::{io, sync::Arc};

use futures::Future;
use slog_scope::{error, info, debug};
use tokio::net::tcp::TcpStream;
use tokio_rustls::TlsAcceptor;
use url::Url;

use self::{
    connection_sequence_future::ConnectionSequenceFuture, sequence_future::create_downgrade_dvc_capabilities_future,
};
use crate::{
    config::{Config, Protocol},
    interceptor::rdp::RdpMessageReader,
    transport::{
        Transport,
        tcp::TcpTransport
    },
    utils,
    Proxy,
    rdp::connection_sequence_future::ConnectionResult
};
use tokio::io::AsyncWrite;
use bytes::IntoBuf;

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

        let connection_sequence_future =
            ConnectionSequenceFuture::new(client, tls_public_key, tls_acceptor, identities_proxy, config.clone())
                .map_err(move |e| {
                    error!("RDP Connection Sequence failed: {}", e);

                    io::Error::new(io::ErrorKind::Other, e)
                })
                .and_then(move |connection_result| {
                    match connection_result {
                        ConnectionResult::RdpProxyConnection {
                            client: client_transport,
                            server: server_transport,
                            channels: joined_static_channels
                        } => {
                            info!("RDP Connection Sequence finished");

                            let future = futures::lazy(move || {
                                let joined_static_channels = utils::swap_hashmap_kv(joined_static_channels);

                                let drdynvc_channel_id = *joined_static_channels
                                    .get(DR_DYN_VC_CHANNEL_NAME)
                                    .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "DVC channel was not joined"))?;

                                Ok((joined_static_channels, drdynvc_channel_id))
                            }).and_then(move |(joined_static_channels, drdynvc_channel_id)| {
                                create_downgrade_dvc_capabilities_future(
                                    client_transport,
                                    server_transport,
                                    drdynvc_channel_id,
                                    DvcManager::with_allowed_channels(vec![RDP8_GRAPHICS_PIPELINE_NAME.to_string()]),
                                ).and_then(|dvc_future_result| {
                                    Ok((dvc_future_result, joined_static_channels))
                                })
                            }).map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("Failed to downgrade DVC capabilities: {}", e),
                                )
                            })
                            .and_then(move |(dvc_future_result, joined_static_channels)| {
                                let (client_transport, server_transport, dvc_manager) =
                                    dvc_future_result;

                                let client_tls = client_transport.into_inner();
                                let server_tls = server_transport.into_inner();

                                Proxy::new(config)
                                    .build_with_message_reader(
                                        TcpTransport::new_tls(server_tls),
                                        TcpTransport::new_tls(client_tls),
                                        Box::new(RdpMessageReader::new(joined_static_channels, dvc_manager)),
                                    )
                                    .map_err(move |e| {
                                        error!("Proxy error: {}", e);
                                        e
                                    })
                            });
                            let boxed_future: Box<dyn Future<Item = (), Error = io::Error> + Send> =
                                Box::new(future);
                            boxed_future
                        },
                        ConnectionResult::TcpRedirect { client, route, leftover_data } => {
                            let server_conn = TcpTransport::connect(&route.dest_host);
                            let client_transport = TcpTransport::new(client);

                            debug!("Starting Tcp redirection specified by JWT token inside preconnection PDU");

                            let mut leftover_data = leftover_data.into_buf();
                            let future: Box<dyn Future<Item = (), Error = io::Error> + Send> =
                                Box::new(server_conn.and_then(move |mut server_transport| {
                                    server_transport
                                        .write_buf(&mut leftover_data)
                                        .and_then(|_| Ok(server_transport))
                                }).and_then(move |server_transport| {
                                    Proxy::new(config.clone()).build_with_protocol(
                                        server_transport,
                                        client_transport,
                                        &Protocol::UNKNOWN)
                                }));
                            future
                        },
                    }
                });
        Box::new(connection_sequence_future)
    }
}
