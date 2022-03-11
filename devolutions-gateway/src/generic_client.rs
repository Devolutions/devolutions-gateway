use crate::config::Config;
use crate::jet_client::JetAssociationsMap;
use crate::preconnection_pdu::{extract_association_claims, read_preconnection_pdu};
use crate::rdp::RdpClient;
use crate::token::{ApplicationProtocol, ConnectionMode, CurrentJrl, TokenCache};
use crate::{utils, ConnectionModeDetails, GatewaySessionInfo, Proxy};
use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use transport::AnyStream;
use typed_builder::TypedBuilder;

#[derive(TypedBuilder)]
pub struct GenericClient {
    config: Arc<Config>,
    associations: Arc<JetAssociationsMap>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    client_addr: SocketAddr,
    client_stream: TcpStream,
}

impl GenericClient {
    pub async fn serve(self) -> anyhow::Result<()> {
        let Self {
            config,
            associations,
            token_cache,
            jrl,
            client_addr,
            mut client_stream,
        } = self;

        let (pdu, mut leftover_bytes) = read_preconnection_pdu(&mut client_stream).await?;
        let source_ip = client_addr.ip();
        let association_claims = extract_association_claims(&pdu, source_ip, &config, &token_cache, &jrl)?;

        match association_claims.jet_ap {
            // We currently special case this because it may be the "RDP-TLS" protocol
            ApplicationProtocol::Rdp => {
                RdpClient {
                    config,
                    associations,
                    token_cache,
                    jrl,
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
                            .associations(associations)
                            .association_id(association_id)
                            .client_transport(AnyStream::from(client_stream))
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

                        let info = GatewaySessionInfo::new(
                            association_id,
                            application_protocol,
                            ConnectionModeDetails::Fwd {
                                destination_host: selected_target.clone(),
                            },
                        )
                        .with_recording_policy(recording_policy)
                        .with_filtering_policy(filtering_policy);

                        Proxy::init()
                            .config(config)
                            .session_info(info)
                            .addrs(client_addr, server_transport.addr)
                            .transports(client_stream, server_transport)
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
