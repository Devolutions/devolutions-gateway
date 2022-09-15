use crate::config::Conf;
use crate::jet_client::JetAssociationsMap;
use crate::preconnection_pdu::{extract_association_claims, read_preconnection_pdu};
use crate::proxy::Proxy;
use crate::rdp::RdpClient;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::{ApplicationProtocol, ConnectionMode, CurrentJrl, Protocol, TokenCache};
use crate::utils;
use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use transport::Transport;
use typed_builder::TypedBuilder;

#[derive(TypedBuilder)]
pub struct GenericClient {
    conf: Arc<Conf>,
    associations: Arc<JetAssociationsMap>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    client_addr: SocketAddr,
    client_stream: TcpStream,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
}

impl GenericClient {
    pub async fn serve(self) -> anyhow::Result<()> {
        let Self {
            conf,
            associations,
            token_cache,
            jrl,
            client_addr,
            mut client_stream,
            sessions,
            subscriber_tx,
        } = self;

        let (pdu, mut leftover_bytes) = read_preconnection_pdu(&mut client_stream).await?;
        let source_ip = client_addr.ip();
        let association_claims = extract_association_claims(&pdu, source_ip, &conf, &token_cache, &jrl)?;

        match association_claims.jet_ap {
            // We currently special case this because it may be the "RDP-TLS" protocol
            ApplicationProtocol::Known(Protocol::Rdp) => {
                RdpClient {
                    conf,
                    associations,
                    token_cache,
                    jrl,
                    sessions,
                    subscriber_tx,
                }
                .serve_with_association_claims_and_leftover_bytes(
                    client_addr,
                    client_stream,
                    association_claims,
                    leftover_bytes,
                )
                .await
            }
            // everything else is pretty much the same
            _ => {
                let association_id = association_claims.jet_aid;
                let connection_mode = association_claims.jet_cm;
                let application_protocol = association_claims.jet_ap;
                let recording_policy = association_claims.jet_rec;
                let filtering_policy = association_claims.jet_flt;

                match connection_mode {
                    ConnectionMode::Rdv => {
                        info!(
                            "Starting TCP rendezvous redirection for application protocol {:?}",
                            application_protocol
                        );
                        crate::jet_rendezvous_tcp_proxy::JetRendezvousTcpProxy::builder()
                            .conf(conf)
                            .associations(associations)
                            .association_id(association_id)
                            .client_transport(Transport::new(client_stream, client_addr))
                            .sessions(sessions)
                            .subscriber_tx(subscriber_tx)
                            .build()
                            .start(&leftover_bytes)
                            .await
                    }
                    ConnectionMode::Fwd { targets, creds: None } => {
                        info!(
                            "Starting plain TCP forward redirection for application protocol {:?}",
                            application_protocol
                        );

                        if association_claims.jet_rec {
                            anyhow::bail!("can't meet recording policy");
                        }

                        let (mut server_transport, selected_target) =
                            utils::successive_try(&targets, utils::tcp_transport_connect).await?;

                        server_transport
                            .write_buf(&mut leftover_bytes)
                            .await
                            .context("Failed to write leftover bytes")?;

                        let info = SessionInfo::new(
                            association_id,
                            application_protocol,
                            ConnectionModeDetails::Fwd {
                                destination_host: selected_target.clone(),
                            },
                        )
                        .with_recording_policy(recording_policy)
                        .with_filtering_policy(filtering_policy);

                        Proxy::builder()
                            .conf(conf)
                            .session_info(info)
                            .address_a(client_addr)
                            .transport_a(client_stream)
                            .address_b(server_transport.addr)
                            .transport_b(server_transport)
                            .sessions(sessions)
                            .subscriber_tx(subscriber_tx)
                            .build()
                            .select_dissector_and_forward()
                            .await
                            .context("Encountered a failure during plain tcp traffic proxying")
                    }
                    ConnectionMode::Fwd { creds: Some(_), .. } => {
                        // Credentials handling should be special cased (e.g.: RDP-TLS)
                        anyhow::bail!("unexpected credentials");
                    }
                }
            }
        }
    }
}
