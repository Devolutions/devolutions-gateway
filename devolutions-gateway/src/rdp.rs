mod connection_sequence_future;
mod dvc_manager;
mod filter;
mod sequence_future;

pub use self::dvc_manager::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME};

use self::connection_sequence_future::ConnectionSequenceFuture;
use self::sequence_future::create_downgrade_dvc_capabilities_future;
use crate::config::Conf;
use crate::jet_client::JetAssociationsMap;
use crate::preconnection_pdu::{extract_association_claims, read_preconnection_pdu};
use crate::subscriber::SubscriberSender;
use crate::token::{ApplicationProtocol, AssociationTokenClaims, ConnectionMode, CurrentJrl, Protocol, TokenCache};
use crate::transport::x224::NegotiationWithClientTransport;
use crate::utils::{self, TargetAddr};
use crate::{ConnectionModeDetails, GatewaySessionInfo, Proxy};
use anyhow::Context;
use bytes::BytesMut;
use sspi::internal::credssp;
use sspi::AuthIdentity;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::Decoder;
use transport::AnyStream;
use uuid::Uuid;

pub const GLOBAL_CHANNEL_NAME: &str = "GLOBAL";
pub const USER_CHANNEL_NAME: &str = "USER";
pub const DR_DYN_VC_CHANNEL_NAME: &str = "drdynvc";

#[derive(Clone)]
pub struct RdpIdentity {
    pub proxy: AuthIdentity,
    pub target: AuthIdentity,
    pub targets: Vec<TargetAddr>,
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
    pub conf: Arc<Conf>,
    pub associations: Arc<JetAssociationsMap>,
    pub token_cache: Arc<TokenCache>,
    pub jrl: Arc<CurrentJrl>,
    pub subscriber_tx: SubscriberSender,
}

impl RdpClient {
    pub async fn serve(self, mut client_stream: TcpStream) -> anyhow::Result<()> {
        let (pdu, leftover_bytes) = read_preconnection_pdu(&mut client_stream).await?;
        let client_addr = client_stream.peer_addr()?;
        let source_ip = client_addr.ip();
        let association_claims = extract_association_claims(&pdu, source_ip, &self.conf, &self.token_cache, &self.jrl)?;
        self.serve_with_association_claims_and_leftover_bytes(
            client_addr,
            client_stream,
            association_claims,
            leftover_bytes,
        )
        .await
    }

    pub async fn serve_with_association_claims_and_leftover_bytes(
        self,
        client_addr: SocketAddr,
        client_stream: TcpStream,
        association_claims: AssociationTokenClaims,
        mut leftover_bytes: BytesMut,
    ) -> anyhow::Result<()> {
        let Self {
            conf,
            associations,
            subscriber_tx,
            ..
        } = self;

        if association_claims.jet_rec {
            anyhow::bail!("can't meet recording policy");
        }

        let routing_mode = resolve_rdp_routing_mode(&association_claims)?;

        match routing_mode {
            RdpRoutingMode::Tcp(targets) => {
                info!("Starting RDP-TCP redirection");

                let (mut server_transport, destination_host) =
                    utils::successive_try(&targets, utils::tcp_transport_connect).await?;

                server_transport
                    .write_buf(&mut leftover_bytes)
                    .await
                    .context("Failed to write leftover bytes")?;

                let info = GatewaySessionInfo::new(
                    association_claims.jet_aid,
                    association_claims.jet_ap,
                    ConnectionModeDetails::Fwd {
                        destination_host: destination_host.clone(),
                    },
                )
                .with_recording_policy(association_claims.jet_rec)
                .with_filtering_policy(association_claims.jet_flt);

                Proxy::init()
                    .conf(conf)
                    .session_info(info)
                    .addrs(client_addr, server_transport.addr)
                    .transports(client_stream, server_transport)
                    .subscriber(subscriber_tx)
                    .select_dissector_and_forward()
                    .await
                    .context("plain tcp traffic proxying failed")
            }
            #[allow(unused)]
            RdpRoutingMode::Tls(identity) => {
                info!("Starting RDP-TLS redirection");
                anyhow::bail!("RDP-TLS is temporary disabled");

                let tls_conf = conf.tls.clone().context("TLS configuration is missing")?;

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
                    tls_conf.public_key.0,
                    tls_conf.acceptor,
                    identity.clone(),
                )
                .await
                .context("RDP Connection Sequence failed")?;

                let destination_host = proxy_connection.selected_target;
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
                                .context("Failed to downgrade DVC capabilities")?;

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

                let info = GatewaySessionInfo::new(
                    association_claims.jet_aid,
                    association_claims.jet_ap,
                    ConnectionModeDetails::Fwd { destination_host },
                )
                .with_recording_policy(association_claims.jet_rec)
                .with_filtering_policy(association_claims.jet_flt);

                // use crate::interceptor::rdp::RdpMessageReader;

                // Proxy::new(config, info)
                //     .build_with_message_reader(
                //         TcpTransport::new_tls(server_tls),
                //         TcpTransport::new_tls(client_tls),
                //         Some(Box::new(RdpMessageReader::new(joined_static_channels, dvc_manager))),
                //     )
                //     .await
                //     .context("Proxy failed")
            }
            RdpRoutingMode::TcpRendezvous(association_id) => {
                info!("Starting RdpTcpRendezvous redirection");
                crate::jet_rendezvous_tcp_proxy::JetRendezvousTcpProxy::builder()
                    .associations(associations)
                    .client_transport(AnyStream::from(client_stream))
                    .association_id(association_id)
                    .subscriber_tx(subscriber_tx)
                    .build()
                    .start(&leftover_bytes)
                    .await
            }
        }
    }
}

enum RdpRoutingMode {
    Tcp(Vec<TargetAddr>),
    Tls(RdpIdentity),
    TcpRendezvous(Uuid),
}

fn resolve_rdp_routing_mode(claims: &AssociationTokenClaims) -> anyhow::Result<RdpRoutingMode> {
    if !matches!(claims.jet_ap, ApplicationProtocol::Known(Protocol::Rdp)) {
        anyhow::bail!(
            "Expected RDP association, but found a different application protocol claim: {:?}",
            claims.jet_ap
        );
    }

    match &claims.jet_cm {
        ConnectionMode::Rdv => Ok(RdpRoutingMode::TcpRendezvous(claims.jet_aid)),
        ConnectionMode::Fwd { targets, creds } => {
            if let Some(creds) = creds {
                Ok(RdpRoutingMode::Tls(RdpIdentity {
                    proxy: AuthIdentity {
                        username: creds.prx_usr.clone(),
                        password: creds.prx_pwd.clone(),
                        domain: None,
                    },
                    target: AuthIdentity {
                        username: creds.dst_usr.clone(),
                        password: creds.dst_pwd.clone(),
                        domain: None,
                    },
                    targets: targets.clone(),
                }))
            } else {
                Ok(RdpRoutingMode::Tcp(targets.clone()))
            }
        }
    }
}
