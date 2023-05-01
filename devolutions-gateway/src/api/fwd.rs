use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::ws::WebSocket;
use axum::extract::{self, ConnectInfo, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tap::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::rustls::client::ClientConfig as TlsClientConfig;
use tracing::Instrument as _;
use typed_builder::TypedBuilder;
use uuid::Uuid;

use crate::config::Conf;
use crate::extract::AssociationToken;
use crate::http::HttpError;
use crate::proxy::Proxy;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::{AssociationTokenClaims, ConnectionMode};
use crate::{utils, DgwState};

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/tcp/:id", get(fwd_tcp))
        .route("/fwd/:id", get(fwd_tls))
        .with_state(state)
}

async fn fwd_tcp(
    State(DgwState {
        conf_handle,
        sessions,
        subscriber_tx,
        ..
    }): State<DgwState>,
    AssociationToken(claims): AssociationToken,
    extract::Path(session_id): extract::Path<Uuid>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    if session_id != claims.jet_aid {
        return Err(HttpError::forbidden().msg("wrong session ID"));
    }

    let conf = conf_handle.get_conf();

    let response = ws.on_upgrade(move |ws| handle_fwd_tcp(ws, conf, sessions, subscriber_tx, claims, source_addr));

    Ok(response)
}

async fn handle_fwd_tcp(
    ws: WebSocket,
    conf: Arc<Conf>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    claims: AssociationTokenClaims,
    source_addr: SocketAddr,
) {
    let stream = crate::ws::websocket_compat(ws);

    let result = PlainForward::builder()
        .client_addr(source_addr)
        .client_stream(stream)
        .conf(conf)
        .claims(claims)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .build()
        .run()
        .instrument(info_span!("tcp", client = %source_addr))
        .await;

    if let Err(error) = result {
        error!(client = %source_addr, error = format!("{error:#}"), "WebSocket-TCP failure");
    }
}

async fn fwd_tls(
    State(DgwState {
        conf_handle,
        sessions,
        subscriber_tx,
        ..
    }): State<DgwState>,
    AssociationToken(claims): AssociationToken,
    extract::Path(session_id): extract::Path<Uuid>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    if session_id != claims.jet_aid {
        return Err(HttpError::forbidden().msg("wrong session ID"));
    }

    let conf = conf_handle.get_conf();

    let response = ws.on_upgrade(move |ws| handle_fwd_tls(ws, conf, sessions, subscriber_tx, claims, source_addr));

    Ok(response)
}

async fn handle_fwd_tls(
    ws: WebSocket,
    conf: Arc<Conf>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    claims: AssociationTokenClaims,
    source_addr: SocketAddr,
) {
    let stream = crate::ws::websocket_compat(ws);

    let result = PlainForward::builder()
        .client_addr(source_addr)
        .client_stream(stream)
        .conf(conf)
        .claims(claims)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .build()
        .run()
        .instrument(info_span!("tls", client = %source_addr))
        .await;

    if let Err(error) = result {
        error!(client = %source_addr, error = format!("{error:#}"), "WebSocket-TLS failure");
    }
}

#[derive(TypedBuilder)]
pub struct PlainForward<'a, S> {
    conf: Arc<Conf>,
    claims: AssociationTokenClaims,
    client_stream: S,
    client_addr: SocketAddr,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    #[builder(default = false)]
    with_tls: bool,
    #[builder(default = "tcp")]
    scheme: &'a str,
}

impl<S> PlainForward<'_, S>
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
            scheme,
        } = self;

        if claims.jet_rec {
            anyhow::bail!("can't meet recording policy");
        }

        let ConnectionMode::Fwd { targets, .. } = claims.jet_cm else {
            anyhow::bail!("invalid connection mode")
        };

        if let Some(bad_target) = targets.iter().find(|target| target.scheme() != scheme) {
            anyhow::bail!("invalid scheme for target {bad_target}");
        }

        trace!("Select and connect to target");

        let ((server_stream, server_addr), selected_target) =
            utils::successive_try(&targets, utils::tcp_connect).await?;

        trace!(%selected_target, "Connected");

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

            let mut server_stream = tokio_rustls::TlsConnector::from(tls_client_config)
                .connect(dns_name, server_stream)
                .await
                .context("TLS connect")?;

            // https://docs.rs/tokio-rustls/latest/tokio_rustls/#why-do-i-need-to-call-poll_flush
            server_stream.flush().await?;

            trace!("TLS connection established with success");

            info!(
                "Starting WebSocket-TLS forwarding with application protocol {}",
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
                .transport_b(server_stream)
                .sessions(sessions)
                .subscriber_tx(subscriber_tx)
                .build()
                .select_dissector_and_forward()
                .await
                .context("Encountered a failure during plain tls traffic proxying")
        } else {
            info!(
                "Starting WebSocket-TCP forwarding with application protocol {}",
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
                .transport_b(server_stream)
                .sessions(sessions)
                .subscriber_tx(subscriber_tx)
                .build()
                .select_dissector_and_forward()
                .await
                .context("Encountered a failure during plain tcp traffic proxying")
        }
    }
}
