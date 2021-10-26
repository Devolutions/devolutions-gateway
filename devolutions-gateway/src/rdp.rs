mod connection_sequence_future;
mod dvc_manager;
mod filter;
mod sequence_future;

pub use self::dvc_manager::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME};

use self::connection_sequence_future::ConnectionSequenceFuture;
use self::sequence_future::create_downgrade_dvc_capabilities_future;
use crate::config::Config;
use crate::interceptor::rdp::RdpMessageReader;
use crate::jet_client::JetAssociationsMap;
use crate::jet_rendezvous_tcp_proxy::JetRendezvousTcpProxy;
use crate::preconnection_pdu::{extract_association_claims, read_preconnection_pdu};
use crate::token::{ConnectionMode, JetAssociationTokenClaims};
use crate::transport::tcp::TcpTransport;
use crate::transport::x224::NegotiationWithClientTransport;
use crate::transport::{JetTransport, Transport};
use crate::{utils, Proxy};
use slog_scope::{error, info};
use sspi::internal::credssp;
use sspi::AuthIdentity;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Decoder;
use url::Url;
use uuid::Uuid;
use bytes::BytesMut;

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
    pub config: Arc<Config>,
    pub tls_public_key: Vec<u8>,
    pub tls_acceptor: TlsAcceptor,
    pub jet_associations: JetAssociationsMap,
}

impl RdpClient {
    pub async fn serve(self, mut client_stream: TcpStream) -> io::Result<()> {
        let (pdu, leftover_bytes) = read_preconnection_pdu(&mut client_stream).await?;
        let association_claims = extract_association_claims(&pdu, &self.config)?;
        self.serve_with_association_claims_and_leftover_bytes(client_stream, association_claims, leftover_bytes)
            .await
    }

    pub async fn serve_with_association_claims_and_leftover_bytes(
        self,
        mut client_stream: TcpStream,
        association_claims: JetAssociationTokenClaims,
        mut leftover_bytes: BytesMut,
    ) -> io::Result<()> {
        let Self {
            config,
            tls_acceptor,
            tls_public_key,
            jet_associations,
        } = self;

        let routing_mode = resolve_rdp_routing_mode(&association_claims)?;

        match routing_mode {
            RdpRoutingMode::Tcp(url) => {
                info!("Starting RDP-TCP redirection");

                let mut server_conn = TcpTransport::connect(&url).await?;
                let client_transport = TcpTransport::new(client_stream);

                server_conn.write_buf(&mut leftover_bytes).await.map_err(|e| {
                    error!("Failed to write leftover bytes: {}", e);
                    e
                })?;

                let result = Proxy::new(config, association_claims.into())
                    .build(server_conn, client_transport)
                    .await
                    .map_err(|e| {
                        error!("Encountered a failure during plain tcp traffic proxying: {}", e);
                        e
                    });

                result
            }
            RdpRoutingMode::Tls(identity) => {
                info!("Starting RDP-TLS redirection");

                // We can't use FramedRead directly here, because we still have to use
                // the leftover bytes. As an alternative, the decoder could be modified to use the
                // leftover bytes in some way, but that's not expected to be efficient. A better
                // alternative could be to write our own "framed reader" that could re-use the
                // leftover bytes and even go as far as handling the RDP sequence.
                // TODO(cbenoit): In any case, that's work for another day.

                let mut buf = leftover_bytes;
                let mut decoder = NegotiationWithClientTransport;

                let request = loop {
                    let len = client_stream.read_buf(&mut buf).await?;

                    if len == 0 {
                        if let Some(frame) = decoder.decode_eof(&mut buf)? {
                            break frame;
                        }
                    } else if let Some(frame) = decoder.decode(&mut buf)? {
                        break frame;
                    }
                };

                // FIXME(cbenoit): I don't feel very confident about what's going on here.
                // We might still have other leftover bytes, but it doesn't seem to be handled.
                // This may be related to the RDP-TLS instability we noticed in the past,
                // I think this is probably a good start to look at why.
                // Besides, the internal code seems overly complex and could be simplified.

                let proxy_connection = ConnectionSequenceFuture::new(
                    client_stream,
                    request,
                    tls_public_key,
                    tls_acceptor,
                    identity.clone(),
                )
                .await
                .map_err(|e| {
                    error!("RDP Connection Sequence failed: {}", e);
                    io::Error::new(io::ErrorKind::Other, e)
                })?;

                let client_transport = proxy_connection.client;
                let server_transport = proxy_connection.server;
                let joined_static_channels = proxy_connection.channels;

                info!("RDP Connection Sequence finished");
                let joined_static_channels = utils::swap_hashmap_kv(joined_static_channels);

                info!("matching channels");
                let (client_transport, server_transport, dvc_manager, joined_static_channels) =
                    match joined_static_channels.get(DR_DYN_VC_CHANNEL_NAME) {
                        Some(drdynvc_channel_id) => {
                            let (client_transport, server_transport, dvc_manager) =
                                create_downgrade_dvc_capabilities_future(
                                    client_transport,
                                    server_transport,
                                    *drdynvc_channel_id,
                                    DvcManager::with_allowed_channels(vec![RDP8_GRAPHICS_PIPELINE_NAME.to_string()]),
                                )
                                .await
                                .map_err(|e| {
                                    io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("Failed to downgrade DVC capabilities: {}", e),
                                    )
                                })?;

                            (
                                client_transport,
                                server_transport,
                                Some(dvc_manager),
                                joined_static_channels,
                            )
                        }
                        None => (client_transport, server_transport, None, joined_static_channels),
                    };

                let client_tls = client_transport.into_inner();
                let server_tls = server_transport.into_inner();

                Proxy::new(config, association_claims.into())
                    .build_with_message_reader(
                        TcpTransport::new_tls(server_tls),
                        TcpTransport::new_tls(client_tls),
                        Some(Box::new(RdpMessageReader::new(joined_static_channels, dvc_manager))),
                    )
                    .await
                    .map_err(move |e| {
                        error!("Proxy error: {}", e);
                        e
                    })
            }
            RdpRoutingMode::TcpRendezvous(association_id) => {
                info!("Starting RdpTcpRendezvous redirection");
                JetRendezvousTcpProxy::new(jet_associations, JetTransport::new_tcp(client_stream), association_id)
                    .proxy(config, &*leftover_bytes)
                    .await
            }
        }
    }
}

enum RdpRoutingMode {
    Tcp(Url),
    Tls(RdpIdentity),
    TcpRendezvous(Uuid),
}

fn resolve_rdp_routing_mode(claims: &JetAssociationTokenClaims) -> Result<RdpRoutingMode, io::Error> {
    const DEFAULT_ROUTING_HOST_SCHEME: &str = "tcp://";
    const DEFAULT_RDP_PORT: u16 = 3389;

    if !claims.jet_ap.is_rdp() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Expected RDP association, but found a different application protocol claim: {:?}",
                claims.jet_ap
            ),
        ));
    }

    match &claims.jet_cm {
        ConnectionMode::Rdv => Ok(RdpRoutingMode::TcpRendezvous(claims.jet_aid)),
        ConnectionMode::Fwd { dst_hst, creds } => {
            let route_url = if dst_hst.starts_with(DEFAULT_ROUTING_HOST_SCHEME) {
                dst_hst.to_owned()
            } else {
                format!("{}{}", DEFAULT_ROUTING_HOST_SCHEME, dst_hst)
            };

            let mut dst_hst = Url::parse(&route_url).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse routing URL in JWT token: {}", e),
                )
            })?;

            if dst_hst.port().is_none() {
                dst_hst.set_port(Some(DEFAULT_RDP_PORT)).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid URL: couldn't set default port for routing URL",
                    )
                })?;
            }

            if let Some(creds) = creds {
                Ok(RdpRoutingMode::Tls(RdpIdentity {
                    proxy: AuthIdentity {
                        username: creds.prx_usr.to_owned(),
                        password: creds.prx_pwd.to_owned(),
                        domain: None,
                    },
                    target: AuthIdentity {
                        username: creds.dst_usr.to_owned(),
                        password: creds.dst_pwd.to_owned(),
                        domain: None,
                    },
                    dest_host: dst_hst,
                }))
            } else {
                Ok(RdpRoutingMode::Tcp(dst_hst))
            }
        }
    }
}
