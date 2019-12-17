mod connection_sequence_future;
mod filter;
mod identities_proxy;
mod sequence_future;

pub use identities_proxy::{IdentitiesProxy, RdpIdentity};

use std::{io, sync::Arc};

use futures::Future;
use slog_scope::{error, info};
use tokio::{codec::FramedParts, io::write_all, net::tcp::TcpStream};
use tokio_rustls::TlsAcceptor;
use url::Url;

use self::{
    connection_sequence_future::ConnectionSequenceFuture, sequence_future::create_downgrade_dvc_capabilities_future,
};
use crate::{config::Config, transport::tcp::TcpTransport, utils, Proxy};

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

                    Ok(create_downgrade_dvc_capabilities_future(
                        client_transport,
                        server_transport,
                        *drdynvc_channel_id,
                    ))
                })
                .and_then(|downgrade_dvc_capabilities_future| {
                    downgrade_dvc_capabilities_future
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("Failed to downgrade DVC capabilities: {}", e),
                            )
                        })
                        .and_then(move |(client_transport, server_transport)| {
                            let FramedParts {
                                io: client_tls,
                                read_buf: client_read_buf,
                                ..
                            } = client_transport.into_parts();
                            let FramedParts {
                                io: server_tls,
                                read_buf: server_read_buf,
                                ..
                            } = server_transport.into_parts();

                            write_all(client_tls, server_read_buf)
                                .join(write_all(server_tls, client_read_buf))
                                .and_then(|((client_tls, _), (server_tls, _))| {
                                    Proxy::new(config_clone)
                                        .build(TcpTransport::new_tls(server_tls), TcpTransport::new_tls(client_tls))
                                        .map_err(move |e| {
                                            error!("Proxy error: {}", e);
                                            e
                                        })
                                })
                        })
                });

        Box::new(connection_sequence_future)
    }
}
