use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use typed_builder::TypedBuilder;

use crate::config::Conf;
use crate::proxy::Proxy;
use crate::rdp_pcb::{extract_association_claims, read_preconnection_pdu};
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::{ConnectionMode, CurrentJrl, TokenCache};
use crate::utils;

#[derive(TypedBuilder)]
pub struct GenericClient {
    conf: Arc<Conf>,
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

        let association_id = association_claims.jet_aid;
        let connection_mode = association_claims.jet_cm;
        let application_protocol = association_claims.jet_ap;
        let recording_policy = association_claims.jet_rec;
        let filtering_policy = association_claims.jet_flt;

        match connection_mode {
            ConnectionMode::Rdv => {
                info!(
                    "Starting TCP rendezvous redirection for application protocol {}",
                    application_protocol
                );
                anyhow::bail!("not yet supported");
            }
            ConnectionMode::Fwd { targets, creds: None } => {
                info!(
                    "Starting plain TCP forward redirection for application protocol {}",
                    application_protocol
                );

                if association_claims.jet_rec {
                    anyhow::bail!("can't meet recording policy");
                }

                let ((mut server_stream, server_addr), selected_target) =
                    utils::successive_try(&targets, utils::tcp_connect).await?;

                server_stream
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
                .with_ttl(association_claims.jet_ttl)
                .with_recording_policy(recording_policy)
                .with_filtering_policy(filtering_policy);

                Proxy::builder()
                    .conf(conf)
                    .session_info(info)
                    .address_a(client_addr)
                    .transport_a(client_stream)
                    .address_b(server_addr)
                    .transport_b(server_stream)
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
