mod accept_connection_future;
mod connection_sequence_future;

mod dvc_manager;
mod filter;
mod preconnection_pdu;

mod sequence_future;

use accept_connection_future::AcceptConnectionMode;
use futures::{future, Future, TryFutureExt};
use slog_scope::{error, info};

use sspi::{internal::credssp, AuthIdentity};

use std::{io, sync::Arc};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;
use url::Url;
use bytes::Buf;

pub use self::dvc_manager::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME};

use self::{
    accept_connection_future::AcceptConnectionFuture, connection_sequence_future::ConnectionSequenceFuture,
    sequence_future::create_downgrade_dvc_capabilities_future,
};

use crate::{
    config::Config,
    interceptor::rdp::RdpMessageReader,
    transport::{tcp::TcpTransport, Transport},
    utils, Proxy,
};

pub const GLOBAL_CHANNEL_NAME: &str = "GLOBAL";
pub const USER_CHANNEL_NAME: &str = "USER";
pub const DR_DYN_VC_CHANNEL_NAME: &str = "drdynvc";

#[derive(Clone)]
pub struct RdpIdentity {
    pub proxy: AuthIdentity,
    pub target: AuthIdentity,
    pub dest_host: Url,
}

impl credssp::CredentialsProxy for RdpIdentity {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: String, domain: Option<String>) -> io::Result<Self::AuthenticationData> {
        if self.proxy.username != username {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "proxy identity is '{}' but credssp asked for '{}'",
                    self.proxy.username, username
                ),
            ));
        }

        let mut credentials = self.proxy.clone();
        credentials.domain = domain;
        Ok(credentials)
    }
}

pub struct RdpClient {
    config: Arc<Config>,
    tls_public_key: Vec<u8>,
    tls_acceptor: TlsAcceptor,
}

impl RdpClient {
    pub fn new(config: Arc<Config>, tls_public_key: Vec<u8>, tls_acceptor: TlsAcceptor) -> Self {
        Self {
            config,
            tls_public_key,
            tls_acceptor,
        }
    }

    pub async fn serve(self, client: TcpStream) -> Result<(), io::Error> {
        let config = self.config.clone();
        let tls_acceptor = self.tls_acceptor;
        let tls_public_key = self.tls_public_key;

        let (client, mode) = AcceptConnectionFuture::new(client, config.clone()).await.map_err(|e| {
            error!("Accept connection failed: {}", e);
            e
        })?;

        match mode {
            AcceptConnectionMode::RdpTcp { url, leftover_request } => {
                info!("Starting RDP-TCP redirection");

                let mut server_conn = TcpTransport::connect(&url).await?;
                let client_transport = TcpTransport::new(client);

                let mut leftover_request = leftover_request.bytes();
                server_conn.write_buf(&mut leftover_request).await.map_err(|e| {
                    error!("Failed to write leftover request: {}", e);
                    e
                })?;
                Proxy::new(config)
                    .build_with_message_reader(server_conn, client_transport, None)
                    .await
                    .map_err(|e| {
                        error!("Encountered a failure during plain tcp traffic proxying: {}", e);
                        e
                    })
            }
            AcceptConnectionMode::RdpTls { identity, request } => {
                info!("Starting RDP-TLS redirection");

                let proxy_connection = ConnectionSequenceFuture::new(
                    client,
                    request,
                    tls_public_key,
                    tls_acceptor,
                    identity
                ).await.map_err(|e| {
                    error!("RDP Connection Sequence failed: {}", e);
                    io::Error::new(io::ErrorKind::Other, e)
                })?;

                let client_transport = proxy_connection.client;
                let server_transport = proxy_connection.server;
                let joined_static_channels = proxy_connection.channels;

                info!("RDP Connection Sequence finished");
                let joined_static_channels = utils::swap_hashmap_kv(joined_static_channels);

                info!("matching channels");
                let (client_transport, server_transport, dvc_manager, joined_static_channels) = match joined_static_channels.get(DR_DYN_VC_CHANNEL_NAME) {
                    Some(drdynvc_channel_id) => {
                        let (client_transport, server_transport, dvc_manager) = create_downgrade_dvc_capabilities_future(
                            client_transport,
                            server_transport,
                            *drdynvc_channel_id,
                            DvcManager::with_allowed_channels(vec![
                                RDP8_GRAPHICS_PIPELINE_NAME.to_string()
                            ]),
                        ).await.map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("Failed to downgrade DVC capabilities: {}", e),
                            )
                        })?;

                        (client_transport, server_transport, Some(dvc_manager), joined_static_channels)
                    }
                    None => {
                        (client_transport, server_transport, None, joined_static_channels)
                    },
                };

                let client_tls = client_transport.into_inner();
                let server_tls = server_transport.into_inner();

                Proxy::new(config)
                    .build_with_message_reader(
                        TcpTransport::new_tls(server_tls),
                        TcpTransport::new_tls(client_tls),
                        Some(Box::new(RdpMessageReader::new(joined_static_channels, dvc_manager))),
                    ).await.map_err(move |e| {
                    error!("Proxy error: {}", e);
                    e
                })
            }
        }
    }
}
