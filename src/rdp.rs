pub use self::dvc_manager::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME};

use self::{
    accept_connection_future::AcceptConnectionFuture, connection_sequence_future::ConnectionSequenceFuture,
    sequence_future::create_downgrade_dvc_capabilities_future,
};

use crate::{
    config::Config,
    interceptor::rdp::RdpMessageReader,
    transport::{tcp::TcpTransport, Transport},
    // utils, Proxy,
};
/*
use accept_connection_future::AcceptConnectionMode;
use bytes::IntoBuf;
use futures::{future, Future};
use slog_scope::{error, info};
*/
use sspi::{internal::credssp, AuthIdentity};

use std::{io, sync::Arc};
// use tokio::{io::AsyncWrite, net::tcp::TcpStream, prelude::future::Either};
// use tokio_rustls::TlsAcceptor;
use url::Url;

mod accept_connection_future;
mod connection_sequence_future;

mod dvc_manager;
mod filter;
mod preconnection_pdu;

mod sequence_future;

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
/*
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

    pub fn serve(self, client: TcpStream) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let config = self.config.clone();
        let tls_acceptor = self.tls_acceptor;
        let tls_public_key = self.tls_public_key;

        Box::new(
            AcceptConnectionFuture::new(client, self.config)
                .map_err(|e| {
                    error!("Accept connection failed: {}", e);
                    e
                })
                .and_then(|(client, mode)| match mode {
                    AcceptConnectionMode::RdpTcp { url, leftover_request } => {
                        info!("Starting RDP-TCP redirection");

                        let server_conn = TcpTransport::connect(&url);
                        let client_transport = TcpTransport::new(client);

                        let mut leftover_request = leftover_request.into_buf();
                        let future = server_conn
                            .and_then(move |mut server_transport| {
                                server_transport
                                    .write_buf(&mut leftover_request)
                                    .map(|_| server_transport)
                            })
                            .and_then(move |server_transport| {
                                Proxy::new(config.clone()).build_with_message_reader(
                                    server_transport,
                                    client_transport,
                                    None,
                                )
                            });

                        let boxed_future: Box<dyn Future<Item = (), Error = io::Error> + Send> = Box::new(future);
                        boxed_future
                    }
                    AcceptConnectionMode::RdpTls { identity, request } => {
                        info!("Starting RDP-TLS redirection");

                        let future =
                            ConnectionSequenceFuture::new(client, request, tls_public_key, tls_acceptor, identity)
                                .map_err(move |e| {
                                    error!("RDP Connection Sequence failed: {}", e);
                                    io::Error::new(io::ErrorKind::Other, e)
                                })
                                .and_then(|proxy_connection| {
                                    let client_transport = proxy_connection.client;
                                    let server_transport = proxy_connection.server;
                                    let joined_static_channels = proxy_connection.channels;

                                    info!("RDP Connection Sequence finished");
                                    let joined_static_channels = utils::swap_hashmap_kv(joined_static_channels);

                                    info!("matching channels");
                                    match joined_static_channels.get(DR_DYN_VC_CHANNEL_NAME) {
                                        Some(drdynvc_channel_id) => {
                                            let create_downgrade_dvc_future = create_downgrade_dvc_capabilities_future(
                                                client_transport,
                                                server_transport,
                                                *drdynvc_channel_id,
                                                DvcManager::with_allowed_channels(vec![
                                                    RDP8_GRAPHICS_PIPELINE_NAME.to_string()
                                                ]),
                                            )
                                            .map(|(client_transport, server_transport, dvc_manager)| {
                                                (
                                                    client_transport,
                                                    server_transport,
                                                    Some(dvc_manager),
                                                    joined_static_channels,
                                                )
                                            })
                                            .map_err(|e| {
                                                io::Error::new(
                                                    io::ErrorKind::Other,
                                                    format!("Failed to downgrade DVC capabilities: {}", e),
                                                )
                                            });
                                            Either::A(create_downgrade_dvc_future)
                                        }
                                        None => Either::B(future::ok((
                                            client_transport,
                                            server_transport,
                                            None,
                                            joined_static_channels,
                                        ))),
                                    }
                                })
                                .and_then(move |future| {
                                    let (client_transport, server_transport, dvc_manager, joined_static_channels) =
                                        future;
                                    let client_tls = client_transport.into_inner();
                                    let server_tls = server_transport.into_inner();

                                    Proxy::new(config)
                                        .build_with_message_reader(
                                            TcpTransport::new_tls(server_tls),
                                            TcpTransport::new_tls(client_tls),
                                            Some(Box::new(RdpMessageReader::new(joined_static_channels, dvc_manager))),
                                        )
                                        .map_err(move |e| {
                                            error!("Proxy error: {}", e);
                                            e
                                        })
                                });
                        let boxed_future: Box<dyn Future<Item = (), Error = io::Error> + Send> = Box::new(future);
                        boxed_future
                    }
                }),
        )
    }
}
 */