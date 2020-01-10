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
use slog_scope::{error, info};
use tokio::net::tcp::TcpStream;
use tokio_rustls::TlsAcceptor;
use url::Url;

use self::{
    connection_sequence_future::ConnectionSequenceFuture, sequence_future::create_downgrade_dvc_capabilities_future,
};
use crate::{config::Config, interceptor::rdp::RdpMessageReader, transport::tcp::TcpTransport, utils, Proxy};

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
        let config_clone = self.config.clone();
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
            ConnectionSequenceFuture::new(client, tls_public_key, tls_acceptor, identities_proxy)
                .map_err(move |e| {
                    error!("RDP Connection Sequence failed: {}", e);

                    io::Error::new(io::ErrorKind::Other, e)
                })
                .and_then(move |(client_transport, server_transport, joined_static_channels)| {
                    info!("RDP Connection Sequence finished");

                    let joined_static_channels = utils::swap_hashmap_kv(joined_static_channels);

                    let drdynvc_channel_id = joined_static_channels
                        .get(DR_DYN_VC_CHANNEL_NAME)
                        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "DVC channel was not joined"))?;

                    Ok((
                        create_downgrade_dvc_capabilities_future(
                            client_transport,
                            server_transport,
                            *drdynvc_channel_id,
                            DvcManager::with_allowed_channels(vec![RDP8_GRAPHICS_PIPELINE_NAME.to_string()]),
                        ),
                        joined_static_channels,
                    ))
                })
                .and_then(|(downgrade_dvc_capabilities_future, joined_static_channels)| {
                    downgrade_dvc_capabilities_future
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("Failed to downgrade DVC capabilities: {}", e),
                            )
                        })
                        .and_then(move |(client_transport, server_transport, dvc_manager)| {
                            let client_tls = client_transport.into_inner();
                            let server_tls = server_transport.into_inner();

                            Proxy::new(config_clone)
                                .build_with_message_reader(
                                    TcpTransport::new_tls(server_tls),
                                    TcpTransport::new_tls(client_tls),
                                    Box::new(RdpMessageReader::new(joined_static_channels, dvc_manager)),
                                )
                                .map_err(move |e| {
                                    error!("Proxy error: {}", e);
                                    e
                                })
                        })
                });

        Box::new(connection_sequence_future)
    }
}
