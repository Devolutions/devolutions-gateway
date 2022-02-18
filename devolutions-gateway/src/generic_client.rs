use crate::config::Config;
use crate::jet_client::JetAssociationsMap;
use crate::preconnection_pdu::{extract_association_claims, read_preconnection_pdu};
use crate::rdp::RdpClient;
use crate::token::{ApplicationProtocol, ConnectionMode};
use crate::{utils, ConnectionModeDetails, GatewaySessionInfo, Proxy};
use anyhow::Context;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct GenericClient {
    pub config: Arc<Config>,
    pub jet_associations: JetAssociationsMap,
}

impl GenericClient {
    pub async fn serve(self, mut client_stream: TcpStream) -> anyhow::Result<()> {
        let Self {
            config,
            jet_associations,
        } = self;

        let (pdu, mut leftover_bytes) = read_preconnection_pdu(&mut client_stream).await?;
        let source_ip = client_stream.peer_addr()?.ip();
        let association_claims = extract_association_claims(&pdu, source_ip, &config)?;

        match association_claims.jet_ap {
            // We currently special case this because it may be the "RDP-TLS" protocol
            ApplicationProtocol::Rdp => {
                RdpClient {
                    config,
                    jet_associations,
                }
                .serve_with_association_claims_and_leftover_bytes(client_stream, association_claims, leftover_bytes)
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
                        anyhow::bail!("Jet TCP rendezvous is temporary disabled");
                        // use crate::jet_rendezvous_tcp_proxy::JetRendezvousTcpProxy;
                        // info!(
                        //     "Starting TCP rendezvous redirection for application protocol {:?}",
                        //     application_protocol
                        // );
                        // JetRendezvousTcpProxy::new(
                        //     jet_associations,
                        //     JetTransport::new_tcp(client_stream),
                        //     association_id,
                        // )
                        // .proxy(config, &*leftover_bytes)
                        // .await
                    }
                    ConnectionMode::Fwd { targets, creds: None } => {
                        info!(
                            "Starting plain TCP forward redirection for application protocol {:?}",
                            application_protocol
                        );

                        if association_claims.jet_rec {
                            anyhow::bail!("can't meet recording policy");
                        }

                        let ((server_addr, mut server_transport), selected_target) =
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

                        Proxy::new(config, info, client_stream.peer_addr()?, server_addr)
                            .select_dissector_and_forward(client_stream, server_transport)
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
