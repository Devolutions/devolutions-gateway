use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tracing::field;
use typed_builder::TypedBuilder;

use crate::config::Conf;
use crate::credential::CredentialStoreHandle;
use crate::proxy::Proxy;
use crate::rdp_pcb::{extract_association_claims, read_pcb};
use crate::recording::ActiveRecordings;
use crate::session::{ConnectionModeDetails, DisconnectInterest, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::token::{self, ConnectionMode, CurrentJrl, RecordingPolicy, TokenCache};
use crate::utils;

#[derive(TypedBuilder)]
pub struct GenericClient<S> {
    conf: Arc<Conf>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    client_addr: SocketAddr,
    client_stream: S,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    active_recordings: Arc<ActiveRecordings>,
    credential_store: CredentialStoreHandle,
}

impl<S> GenericClient<S>
where
    S: AsyncWrite + AsyncRead + Unpin + Send + Sync,
{
    #[instrument(
        "generic_client",
        skip_all,
        fields(session_id = field::Empty, protocol = field::Empty, target = field::Empty),
    )]
    pub async fn serve(self) -> anyhow::Result<()> {
        let Self {
            conf,
            token_cache,
            jrl,
            client_addr,
            mut client_stream,
            sessions,
            subscriber_tx,
            active_recordings,
            credential_store,
        } = self;

        let span = tracing::Span::current();

        let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(10));
        let read_pcb_fut = read_pcb(&mut client_stream);

        let (pcb, mut leftover_bytes) = tokio::select! {
            () = timeout => {
                info!("Timed out at preconnection blob reception");
                return Ok(())
            }
            result = read_pcb_fut => {
                match result {
                    Ok(result) => result,
                    Err(error) => {
                        info!(%error, "Received payload not matching the expected protocol");
                        return Ok(())
                    }
                }
            }
        };

        let token = pcb.v2_payload.as_deref().context("V2 payload missing from RDP PCB")?;

        if conf.debug.dump_tokens {
            debug!(token, "**DEBUG OPTION**");
        }

        let source_ip = client_addr.ip();

        let disconnected_info = if let Ok(session_id) = token::extract_session_id(token) {
            sessions.get_disconnected_info(session_id).await.ok().flatten()
        } else {
            None
        };

        let claims = extract_association_claims(
            token,
            source_ip,
            &conf,
            &token_cache,
            &jrl,
            &active_recordings,
            disconnected_info,
        )?;

        span.record("session_id", claims.jet_aid.to_string())
            .record("protocol", claims.jet_ap.to_string());

        match claims.jet_cm {
            ConnectionMode::Rdv => {
                anyhow::bail!("TCP rendezvous not supported");
            }
            ConnectionMode::Fwd { targets } => {
                match claims.jet_rec {
                    RecordingPolicy::None | RecordingPolicy::Stream => (),
                    RecordingPolicy::Proxy => anyhow::bail!("can't meet recording policy"),
                }

                trace!("Select and connect to target");

                let ((mut server_stream, server_addr), selected_target) =
                    utils::successive_try(&targets, utils::tcp_connect).await?;

                trace!(%selected_target, "Connected");
                span.record("target", selected_target.to_string());

                let is_rdp = claims.jet_ap == token::ApplicationProtocol::Known(token::Protocol::Rdp);
                trace!(is_rdp, "IS_RDP????");

                let info = SessionInfo::builder()
                    .id(claims.jet_aid)
                    .application_protocol(claims.jet_ap)
                    .details(ConnectionModeDetails::Fwd {
                        destination_host: selected_target.clone(),
                    })
                    .time_to_live(claims.jet_ttl)
                    .recording_policy(claims.jet_rec)
                    .filtering_policy(claims.jet_flt)
                    .build();

                let disconnect_interest = DisconnectInterest::from_reconnection_policy(claims.jet_reuse);

                // We support proxy-based credential injection for RDP.
                // If a credential mapping has been pushed, we automatically switch to this mode.
                // Otherwise, we continue the generic procedure.
                if is_rdp {
                    let token_id = token::extract_jti(token).context("failed to extract jti claim from token")?;

                    if let Some(entry) = credential_store.get(token_id) {
                        anyhow::ensure!(token == entry.token, "token mismatch");

                        // NOTE: In the future, we could imagine performing proxy-based recording as well using RdpProxy.
                        if entry.mapping.is_some() {
                            return crate::rdp_proxy::RdpProxy::builder()
                                .conf(conf)
                                .session_info(info)
                                .client_addr(client_addr)
                                .client_stream(client_stream)
                                .server_addr(server_addr)
                                .server_stream(server_stream)
                                .sessions(sessions)
                                .subscriber_tx(subscriber_tx)
                                .credential_entry(entry)
                                .client_stream_leftover_bytes(leftover_bytes)
                                .server_dns_name(selected_target.host().to_owned())
                                .disconnect_interest(disconnect_interest)
                                .build()
                                .run()
                                .await
                                .context("encountered a failure during RDP proxying (credential injection)");
                        }
                    }
                }

                info!("TCP forwarding");

                server_stream
                    .write_buf(&mut leftover_bytes)
                    .await
                    .context("failed to write leftover bytes")?;

                Proxy::builder()
                    .conf(conf)
                    .session_info(info)
                    .address_a(client_addr)
                    .transport_a(client_stream)
                    .address_b(server_addr)
                    .transport_b(server_stream)
                    .sessions(sessions)
                    .subscriber_tx(subscriber_tx)
                    .disconnect_interest(disconnect_interest)
                    .build()
                    .select_dissector_and_forward()
                    .await
                    .context("encountered a failure during plain tcp traffic proxying")
            }
        }
    }
}
