use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::proxy::Proxy;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::{AssociationTokenClaims, ConnectionMode, CurrentJrl, TokenCache, TokenError};
use crate::utils;

use anyhow::Context as _;
use tap::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::rustls::client::ClientConfig as TlsClientConfig;
use typed_builder::TypedBuilder;

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

#[derive(TypedBuilder)]
pub struct PlainForward<S> {
    conf: Arc<Conf>,
    claims: AssociationTokenClaims,
    client_stream: S,
    client_addr: SocketAddr,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    #[builder(default = false)]
    with_tls: bool,
}

impl<S> PlainForward<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[instrument(skip_all)]
    pub async fn run(self) -> anyhow::Result<()> {
        let Self {
            conf,
            claims,
            client_stream,
            client_addr,
            sessions,
            subscriber_tx,
            with_tls,
        } = self;

        if claims.jet_rec {
            anyhow::bail!("can't meet recording policy");
        }

        let ConnectionMode::Fwd { targets, .. } = claims.jet_cm else {
            anyhow::bail!("invalid connection mode")
        };

        trace!("Connecting to target");

        let (server_transport, selected_target) = utils::successive_try(&targets, utils::tcp_transport_connect).await?;

        trace!("Connected");

        if with_tls {
            trace!("Establishing TLS connection with server");

            // Establish TLS connection with server

            let dns_name = selected_target
                .host()
                .try_into()
                .context("Invalid DNS name in selected target")?;

            // TODO: optimize client config creation
            //
            // rustls doc says:
            //
            // > Making one of these can be expensive, and should be once per process rather than once per connection.
            //
            // source: https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html
            //
            // In our case, this doesn’t work, so I’m creating a new ClientConfig from scratch each time (slow).
            // rustls issue: https://github.com/rustls/rustls/issues/1186
            let tls_client_config = TlsClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(std::sync::Arc::new(
                    crate::utils::danger_transport::NoCertificateVerification,
                ))
                .with_no_client_auth()
                .pipe(Arc::new);

            let server_addr = server_transport.addr;

            let mut server_transport = tokio_rustls::TlsConnector::from(tls_client_config)
                .connect(dns_name, server_transport)
                .await
                .context("TLS connect")?;

            // https://docs.rs/tokio-rustls/latest/tokio_rustls/#why-do-i-need-to-call-poll_flush
            server_transport.flush().await?;

            trace!("TLS connection established with success");

            info!(
                "Starting WebSocket-TLS forwarding with application protocol {:?}",
                claims.jet_ap
            );

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
                .address_b(server_addr)
                .transport_b(server_transport)
                .sessions(sessions)
                .subscriber_tx(subscriber_tx)
                .build()
                .select_dissector_and_forward()
                .await
                .context("Encountered a failure during plain tls traffic proxying")
        } else {
            info!(
                "Starting WebSocket-TCP forwarding with application protocol {:?}",
                claims.jet_ap
            );

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
    }
}
