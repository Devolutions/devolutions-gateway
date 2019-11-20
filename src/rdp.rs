mod connection_sequence_future;
mod filter;
mod identities_proxy;
mod sequence_future;

pub use identities_proxy::{IdentitiesProxy, RdpIdentity};

use std::{io, sync::Arc};

use futures::Future;
use slog_scope::{error, info};
use tokio_rustls::TlsAcceptor;
use tokio_tcp::TcpStream;
use url::Url;

use self::connection_sequence_future::ConnectionSequenceFuture;
use crate::{config::Config, transport::tcp::TcpTransport, Proxy};

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
                .and_then(move |(client_tls, server_tls, _joined_static_channels)| {
                    info!("RDP Connection Sequence finished");

                    Proxy::new(config_clone)
                        .build(TcpTransport::new_tls(server_tls), TcpTransport::new_tls(client_tls))
                        .map_err(move |e| {
                            error!("Proxy error: {}", e);
                            e
                        })
                });

        Box::new(connection_sequence_future)
    }
}
