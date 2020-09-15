pub use self::dvc_manager::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME};
use self::{
    accept_connection_future::AcceptConnectionFuture, connection_sequence_future::ConnectionSequenceFuture,
    sequence_future::create_downgrade_dvc_capabilities_future,
};
use crate::{config::Config, interceptor::rdp::RdpMessageReader, transport::tcp::TcpTransport, utils, Proxy};
use futures::Future;
use slog_scope::{error, info};
use sspi::{internal::credssp, AuthIdentity};
use std::{io, sync::Arc};
use tokio::net::tcp::TcpStream;
use tokio_rustls::TlsAcceptor;
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

        if self.proxy.domain != domain {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "proxy domain is '{:?}' but credssp asked for '{:?}'",
                    self.proxy.domain, domain
                ),
            ));
        }

        Ok(self.proxy.clone())
    }
}

pub struct RdpClient {
    config: Arc<Config>,
    tls_public_key: Vec<u8>,
    tls_acceptor: TlsAcceptor,
}

macro_rules! try_fut {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(e) => {
                let fut_err: Box<dyn Future<Item = (), Error = io::Error> + Send> =
                    Box::new(futures::future::err(io::Error::new(io::ErrorKind::Other, e)));
                return fut_err;
            }
        }
    };
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
            AcceptConnectionFuture::new(client)
                .map_err(|e| {
                    error!("Accept connection failed: {}", e);
                    e
                })
                .and_then(|(client, pdu, request)| {
                    let identity = try_fut!(preconnection_pdu::validate_identity(&pdu, &config));
                    info!("Starting TCP redirection specified by JWT token inside preconnection PDU");
                    let future = ConnectionSequenceFuture::new(client, request, tls_public_key, tls_acceptor, identity)
                        .map_err(move |e| {
                            error!("RDP Connection Sequence failed: {}", e);
                            io::Error::new(io::ErrorKind::Other, e)
                        })
                        .and_then(|proxy_connection| {
                            let client_transport = proxy_connection.client;
                            let server_transport = proxy_connection.server;
                            let joined_static_channels = proxy_connection.channels;

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
                                    DvcManager::with_allowed_channels(vec![RDP8_GRAPHICS_PIPELINE_NAME.to_string()]),
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
                                            Some(Box::new(RdpMessageReader::new(joined_static_channels, dvc_manager))),
                                        )
                                        .map_err(move |e| {
                                            error!("Proxy error: {}", e);
                                            e
                                        })
                                },
                            )
                        });

                    let boxed_future: Box<dyn Future<Item = (), Error = io::Error> + Send> = Box::new(future);
                    boxed_future
                }),
        )
    }
}
