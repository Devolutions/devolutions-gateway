use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::ws::WebSocket;
use axum::extract::{self, ConnectInfo, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{field, Instrument as _};
use typed_builder::TypedBuilder;
use uuid::Uuid;

use crate::config::Conf;
use crate::extract::AssociationToken;
use crate::http::HttpError;
use crate::proxy::Proxy;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::token::{AssociationTokenClaims, ConnectionMode};
use crate::{utils, DgwState};

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/tcp/:id", get(fwd_tcp))
        .route("/tls/:id", get(fwd_tls))
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
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    claims: AssociationTokenClaims,
    source_addr: SocketAddr,
) {
    let stream = crate::ws::websocket_compat(ws);

    let result = Forward::builder()
        .client_addr(source_addr)
        .client_stream(stream)
        .conf(conf)
        .claims(claims)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .with_tls(false)
        .build()
        .run()
        .instrument(info_span!(
            "tcp",
            client = %source_addr,
            session_id = field::Empty,
            protocol = field::Empty,
            target = field::Empty
        ))
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
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    claims: AssociationTokenClaims,
    source_addr: SocketAddr,
) {
    let stream = crate::ws::websocket_compat(ws);

    let result = Forward::builder()
        .client_addr(source_addr)
        .client_stream(stream)
        .conf(conf)
        .claims(claims)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .with_tls(true)
        .build()
        .run()
        .instrument(info_span!(
            "tls",
            client = %source_addr,
            session_id = field::Empty,
            protocol = field::Empty,
            target = field::Empty
        ))
        .await;

    if let Err(error) = result {
        error!(client = %source_addr, error = format!("{error:#}"), "WebSocket-TLS failure");
    }
}

#[derive(TypedBuilder)]
struct Forward<S> {
    conf: Arc<Conf>,
    claims: AssociationTokenClaims,
    client_stream: S,
    client_addr: SocketAddr,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    with_tls: bool,
}

impl<S> Forward<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn run(self) -> anyhow::Result<()> {
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

        tracing::Span::current().record("session_id", claims.jet_aid.to_string());
        tracing::Span::current().record("protocol", claims.jet_ap.to_string());

        trace!("Select and connect to target");

        let ((server_stream, server_addr), selected_target) =
            utils::successive_try(&targets, utils::tcp_connect).await?;

        trace!(%selected_target, "Connected");
        tracing::Span::current().record("target", selected_target.to_string());

        if with_tls {
            trace!("Establishing TLS connection with server");

            // Establish TLS connection with server

            let server_stream = crate::tls::connect(selected_target.host(), server_stream)
                .await
                .context("TLS connect")?;

            info!(protocol = %claims.jet_ap, target = %server_addr, "WebSocket-TLS forwarding");

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
            info!("WebSocket-TCP forwarding");

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
