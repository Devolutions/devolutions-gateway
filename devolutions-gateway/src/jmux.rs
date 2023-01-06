use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::{CurrentJrl, JmuxTokenClaims, TokenCache, TokenError};

use anyhow::Context as _;
use jmux_proxy::JmuxProxy;
use tap::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use transport::{ErasedRead, ErasedWrite};

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("token not allowed")]
    Forbidden,
    #[error("bad token")]
    BadToken(#[from] TokenError),
}

pub fn authorize(
    client_addr: SocketAddr,
    token: &str,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> Result<JmuxTokenClaims, AuthorizationError> {
    use crate::token::AccessTokenClaims;

    if let AccessTokenClaims::Jmux(claims) =
        crate::http::middlewares::auth::authenticate(client_addr, token, conf, token_cache, jrl)?
    {
        Ok(claims)
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

pub async fn handle(
    stream: impl AsyncRead + AsyncWrite + Send + 'static,
    claims: JmuxTokenClaims,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<()> {
    use futures::future::Either;
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
    .with_ttl(claims.jet_ttl);

    let notify_kill = Arc::new(Notify::new());

    crate::session::add_session_in_progress(&sessions, &subscriber_tx, info, notify_kill.clone()).await?;

    let proxy_fut = JmuxProxy::new(reader, writer).with_config(config).run();

    let proxy_handle = tokio::spawn(proxy_fut);
    tokio::pin!(proxy_handle);

    let kill_notified = notify_kill.notified();
    tokio::pin!(kill_notified);

    let res = match futures::future::select(proxy_handle, kill_notified).await {
        Either::Left((Ok(res), _)) => res.context("JMUX proxy error"),
        Either::Left((Err(e), _)) => anyhow::Error::new(e).context("Failed to wait for proxy task").pipe(Err),
        Either::Right((_, proxy_handle)) => {
            proxy_handle.abort();
            Ok(())
        }
    };

    crate::session::remove_session_in_progress(&sessions, &subscriber_tx, session_id).await?;

    res
}
