use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::proxy::Proxy;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::{AssociationTokenClaims, ConnectionMode, CurrentJrl, TokenCache, TokenError};
use crate::utils;

use anyhow::Context as _;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

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
) -> Result<AssociationTokenClaims, AuthorizationError> {
    use crate::token::AccessTokenClaims;

    if let AccessTokenClaims::Association(claims) =
        crate::http::middlewares::auth::authenticate(client_addr, token, conf, token_cache, jrl)?
    {
        Ok(claims)
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

#[instrument(skip_all)]
pub async fn handle(
    client_stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    claims: AssociationTokenClaims,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<()> {
    info!(
        "Starting WebSocket-TCP forwarding with application protocol {:?}",
        claims.jet_ap
    );

    if claims.jet_rec {
        anyhow::bail!("can't meet recording policy");
    }

    let ConnectionMode::Fwd { targets, .. } = claims.jet_cm else {
        anyhow::bail!("invalid connection mode")
    };

    let (server_transport, selected_target) = utils::successive_try(&targets, utils::tcp_transport_connect).await?;

    let info = SessionInfo::new(
        claims.jet_aid,
        claims.jet_ap,
        ConnectionModeDetails::Fwd {
            destination_host: selected_target.clone(),
        },
    )
    .with_ttl(claims.jet_ttl)
    .with_recording_policy(claims.jet_rec)
    .with_filtering_policy(claims.jet_flt);

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
