use std::sync::Arc;

use crate::session::{ConnectionModeDetails, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::token::JmuxTokenClaims;

use anyhow::Context as _;
use devolutions_gateway_task::ChildTask;
use jmux_proxy::JmuxProxy;
use tap::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use transport::{ErasedRead, ErasedWrite};

pub async fn handle(
    stream: impl AsyncRead + AsyncWrite + Send + 'static,
    claims: JmuxTokenClaims,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<()> {
    use jmux_proxy::{FilteringRule, JmuxConfig};

    let (reader, writer) = tokio::io::split(stream);
    let reader = Box::new(reader) as ErasedRead;
    let writer = Box::new(writer) as ErasedWrite;

    let main_destination_host = claims.hosts.first().clone();

    let config = JmuxConfig {
        filtering: FilteringRule::Any(
            claims
                .hosts
                .into_iter()
                .map(|addr| {
                    if addr.host() == "*" {
                        FilteringRule::port(addr.port())
                    } else {
                        FilteringRule::wildcard_host(addr.host().to_owned()).and(FilteringRule::port(addr.port()))
                    }
                })
                .collect(),
        ),
    };

    let session_id = claims.jet_aid;

    let info = SessionInfo::new(
        session_id,
        claims.jet_ap,
        ConnectionModeDetails::Fwd {
            destination_host: main_destination_host,
        },
    )
    .with_ttl(claims.jet_ttl)
    .with_recording_policy(claims.jet_rec);

    let notify_kill = Arc::new(Notify::new());

    crate::session::add_session_in_progress(&sessions, &subscriber_tx, info, notify_kill.clone()).await?;

    let proxy_fut = JmuxProxy::new(reader, writer).with_config(config).run();
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
