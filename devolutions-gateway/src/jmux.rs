use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use devolutions_gateway_task::ChildTask;
use jmux_proxy::{FilteringRule, JmuxConfig, JmuxProxy};
use tap::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use transport::{ErasedRead, ErasedWrite};

use crate::config::Conf;
use crate::credential::{ArcCredentialEntry, CredentialStoreHandle};
use crate::session::{ConnectionModeDetails, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::token::{ApplicationProtocol, JmuxTokenClaims, Protocol, RecordingPolicy};
use crate::traffic_audit::TrafficAuditHandle;

#[expect(
    clippy::too_many_arguments,
    reason = "JMUX coordinates independent transport, session, credential, and audit components"
)]
pub async fn handle(
    stream: impl AsyncRead + AsyncWrite + Send + 'static,
    claims: JmuxTokenClaims,
    conf: Arc<Conf>,
    client_addr: SocketAddr,
    credential_store: CredentialStoreHandle,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    traffic_audit_handle: TrafficAuditHandle,
) -> anyhow::Result<()> {
    match claims.jet_rec {
        RecordingPolicy::None | RecordingPolicy::Stream => (),
        RecordingPolicy::Proxy => anyhow::bail!("can't meet recording policy"),
    }

    let (reader, writer) = tokio::io::split(stream);
    let reader = Box::new(reader) as ErasedRead;
    let writer = Box::new(writer) as ErasedWrite;

    let main_destination_host = claims.hosts.first().clone();

    let config = claims_to_jmux_config(&claims);
    debug!(?config, "JMUX config");

    let credential_entry = match claims.jet_ap {
        ApplicationProtocol::Known(Protocol::Rdp) => {
            credential_store.get(claims.jti).filter(|entry| entry.mapping.is_some())
        }
        _ => None,
    };

    let session_id = claims.jet_aid;

    let info = SessionInfo::builder()
        .id(session_id)
        .application_protocol(claims.jet_ap.clone())
        .details(ConnectionModeDetails::Fwd {
            destination_host: main_destination_host,
        })
        .time_to_live(claims.jet_ttl)
        .recording_policy(claims.jet_rec)
        .build();

    let notify_kill = Arc::new(Notify::new());

    crate::session::add_session_in_progress(&sessions, &subscriber_tx, info.clone(), Arc::clone(&notify_kill), None)
        .await?;

    let traffic_event_callback = move |event: jmux_proxy::TrafficEvent| {
        let traffic_audit_handle = traffic_audit_handle.clone();

        tokio::spawn(async move {
            use std::time::UNIX_EPOCH;

            let outcome = match event.outcome {
                jmux_proxy::EventOutcome::ConnectFailure => traffic_audit::EventOutcome::ConnectFailure,
                jmux_proxy::EventOutcome::AbnormalTermination => traffic_audit::EventOutcome::AbnormalTermination,
                jmux_proxy::EventOutcome::NormalTermination => traffic_audit::EventOutcome::NormalTermination,
            };

            let protocol = match event.protocol {
                jmux_proxy::TransportProtocol::Tcp => traffic_audit::TransportProtocol::Tcp,
                jmux_proxy::TransportProtocol::Udp => traffic_audit::TransportProtocol::Udp,
            };

            let connect_at_ms = i64::try_from(
                event
                    .connect_at
                    .duration_since(UNIX_EPOCH)
                    .expect("after UNIX_EPOCH")
                    .as_millis(),
            )
            .expect("u128-to-i64");

            let disconnect_at_ms = i64::try_from(
                event
                    .disconnect_at
                    .duration_since(UNIX_EPOCH)
                    .expect("after UNIX_EPOCH")
                    .as_millis(),
            )
            .expect("u128-to-i64");

            let active_duration_ms = i64::try_from(event.active_duration.as_millis()).expect("u128-to-i64");

            let _ = traffic_audit_handle
                .push(traffic_audit::TrafficEvent {
                    session_id,
                    outcome,
                    protocol,
                    target_host: event.target_host,
                    target_ip: event.target_ip,
                    target_port: event.target_port,
                    connect_at_ms,
                    disconnect_at_ms,
                    active_duration_ms,
                    bytes_tx: event.bytes_tx,
                    bytes_rx: event.bytes_rx,
                })
                .await;
        });
    };

    let proxy = JmuxProxy::new(reader, writer)
        .with_config(config)
        .with_outgoing_traffic_event_callback(traffic_event_callback)
        .with_optional_credential_injection(CredentialInjectionContext {
            application_protocol: claims.jet_ap,
            credential_entry,
            conf,
            client_addr,
            sessions: sessions.clone(),
            subscriber_tx: subscriber_tx.clone(),
            session_info: info,
            notify_kill: Arc::clone(&notify_kill),
        });

    let proxy_fut = proxy.run();

    let proxy_handle = ChildTask::spawn(proxy_fut);
    let join_fut = proxy_handle.join();
    tokio::pin!(join_fut);

    let kill_notified = notify_kill.notified();
    tokio::pin!(kill_notified);

    let res = tokio::select! {
        res = join_fut => match res {
            Ok(res) => res.context("JMUX proxy error"),
            Err(e) => anyhow::Error::new(e).context("failed to wait for proxy task").pipe(Err),
        },
        _ = kill_notified => Ok(()),
    };

    crate::session::remove_session_in_progress(&sessions, &subscriber_tx, session_id).await?;

    res
}

struct CredentialInjectionContext {
    application_protocol: ApplicationProtocol,
    credential_entry: Option<ArcCredentialEntry>,
    conf: Arc<Conf>,
    client_addr: SocketAddr,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    session_info: SessionInfo,
    notify_kill: Arc<Notify>,
}

trait JmuxProxyCredentialInjectionExt {
    fn with_optional_credential_injection(self, context: CredentialInjectionContext) -> Self;
}

impl JmuxProxyCredentialInjectionExt for JmuxProxy {
    fn with_optional_credential_injection(self, context: CredentialInjectionContext) -> Self {
        let CredentialInjectionContext {
            application_protocol,
            credential_entry,
            conf,
            client_addr,
            sessions,
            subscriber_tx,
            session_info,
            notify_kill,
        } = context;

        let Some(credential_entry) = credential_entry else {
            return self;
        };

        match application_protocol {
            ApplicationProtocol::Known(Protocol::Rdp) => {
                self.with_outgoing_stream_interceptor(move |destination, client_stream, target_stream| {
                    let server_addr = match target_stream.peer_addr() {
                        Ok(server_addr) => server_addr,
                        Err(error) => {
                            warn!(?error, %destination, "Failed to resolve RDP target address");
                            return;
                        }
                    };

                    let conf = Arc::clone(&conf);
                    let credential_entry = Arc::clone(&credential_entry);
                    let sessions = sessions.clone();
                    let subscriber_tx = subscriber_tx.clone();
                    let session_info = session_info.clone();
                    let notify_kill = Arc::clone(&notify_kill);
                    let server_dns_name = destination.host().to_owned();

                    tokio::spawn(async move {
                        let result = crate::rdp_proxy::RdpProxy::builder()
                            .conf(conf)
                            .session_info(session_info)
                            .client_stream(client_stream)
                            .client_addr(client_addr)
                            .server_stream(target_stream)
                            .server_addr(server_addr)
                            .credential_entry(credential_entry)
                            .client_stream_leftover_bytes(bytes::BytesMut::new())
                            .sessions(sessions)
                            .subscriber_tx(subscriber_tx)
                            .server_dns_name(server_dns_name)
                            .disconnect_interest(None)
                            .registered_session_notify_kill(Some(notify_kill))
                            .build()
                            .run()
                            .await;

                        if let Err(error) = result {
                            warn!(?error, %destination, "RDP credential proxy failed");
                        }
                    });
                })
            }
            _ => self,
        }
    }
}

#[doc(hidden)] // Used in tests.
pub fn claims_to_jmux_config(claims: &JmuxTokenClaims) -> JmuxConfig {
    JmuxConfig {
        filtering: FilteringRule::Any(
            claims
                .hosts
                .iter()
                .map(|addr| match (addr.host(), addr.port()) {
                    ("*", 0) => FilteringRule::allow(),
                    ("*", port) => FilteringRule::port(port),
                    (host, 0) => FilteringRule::wildcard_host(host.to_owned()),
                    (host, port) => FilteringRule::wildcard_host(host.to_owned()).and(FilteringRule::port(port)),
                })
                .collect(),
        ),
    }
}
