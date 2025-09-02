use std::sync::Arc;

use crate::session::{ConnectionModeDetails, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::token::{JmuxTokenClaims, RecordingPolicy};
use crate::traffic_audit::TrafficAuditHandle;

use anyhow::Context as _;
use devolutions_gateway_task::ChildTask;
use jmux_proxy::{FilteringRule, JmuxConfig, JmuxProxy};
use tap::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use transport::{ErasedRead, ErasedWrite};

pub async fn handle(
    stream: impl AsyncRead + AsyncWrite + Send + 'static,
    claims: JmuxTokenClaims,
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

    let session_id = claims.jet_aid;

    let info = SessionInfo::builder()
        .id(session_id)
        .application_protocol(claims.jet_ap)
        .details(ConnectionModeDetails::Fwd {
            destination_host: main_destination_host,
        })
        .time_to_live(claims.jet_ttl)
        .recording_policy(claims.jet_rec)
        .build();

    let notify_kill = Arc::new(Notify::new());

    crate::session::add_session_in_progress(&sessions, &subscriber_tx, info, Arc::clone(&notify_kill), None).await?;

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

    let proxy_fut = JmuxProxy::new(reader, writer)
        .with_config(config)
        .with_outgoing_traffic_event_callback(traffic_event_callback)
        .run();
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
