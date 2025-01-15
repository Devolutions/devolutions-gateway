use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tracing::field;
use typed_builder::TypedBuilder;

use crate::config::Conf;
use crate::proxy::Proxy;
use crate::rdp_pcb::{extract_association_claims, read_pcb};
use crate::recording::ActiveRecordings;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::token::{ConnectionMode, CurrentJrl, RecordingPolicy, TokenCache};
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
}

impl<S> GenericClient<S>
where
    S: AsyncWrite + AsyncRead + Unpin,
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
        } = self;

        let span = tracing::Span::current();

        let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(10));
        let read_pcb_fut = read_pcb(&mut client_stream);

        let (pdu, mut leftover_bytes) = tokio::select! {
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

        let source_ip = client_addr.ip();
        let claims = extract_association_claims(&pdu, source_ip, &conf, &token_cache, &jrl, &active_recordings)?;

        span.record("session_id", claims.jet_aid.to_string())
            .record("protocol", claims.jet_ap.to_string());

        match claims.jet_cm {
            ConnectionMode::Rdv => {
                anyhow::bail!("TCP rendezvous not supported");
            }
            ConnectionMode::Fwd { targets, creds: None } => {
                match claims.jet_rec {
                    RecordingPolicy::None | RecordingPolicy::Stream => (),
                    RecordingPolicy::Proxy => anyhow::bail!("can't meet recording policy"),
                }

                trace!("Select and connect to target");

                let ((mut server_stream, server_addr), selected_target) =
                    utils::successive_try(&targets, utils::tcp_connect).await?;

                trace!(%selected_target, "Connected");
                span.record("target", selected_target.to_string());

                info!("TCP forwarding");

                server_stream
                    .write_buf(&mut leftover_bytes)
                    .await
                    .context("failed to write leftover bytes")?;

                let info = SessionInfo::builder()
                    .association_id(claims.jet_aid)
                    .application_protocol(claims.jet_ap)
                    .details(ConnectionModeDetails::Fwd {
                        destination_host: selected_target.clone(),
                    })
                    .time_to_live(claims.jet_ttl)
                    .recording_policy(claims.jet_rec)
                    .filtering_policy(claims.jet_flt)
                    .build();

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
                    .context("encountered a failure during plain tcp traffic proxying")
            }
            ConnectionMode::Fwd { creds: Some(_), .. } => {
                // Credentials handling should be special cased (e.g.: RDP-TLS)
                anyhow::bail!("unexpected credentials");
            }
        }
    }
}
