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
use crate::token::{ApplicationProtocol, AssociationTokenClaims, ConnectionMode, Protocol, RecordingPolicy};
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
    let span = tracing::Span::current();

    let response = ws.on_upgrade(move |ws| {
        handle_fwd(ws, conf, sessions, subscriber_tx, claims, source_addr, false).instrument(span)
    });

    Ok(response)
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
    let span = tracing::Span::current();

    let response = ws.on_upgrade(move |ws| {
        handle_fwd(ws, conf, sessions, subscriber_tx, claims, source_addr, true).instrument(span)
    });

    Ok(response)
}

async fn handle_fwd(
    ws: WebSocket,
    conf: Arc<Conf>,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    claims: AssociationTokenClaims,
    source_addr: SocketAddr,
    with_tls: bool,
) {
    let stream = crate::ws::websocket_compat(ws);

    let span = info_span!(
        "fwd",
        session_id = claims.jet_aid.to_string(),
        protocol = claims.jet_ap.to_string(),
        target = field::Empty
    );

    let result = Forward::builder()
        .client_addr(source_addr)
        .client_stream(stream)
        .conf(conf)
        .claims(claims)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .with_tls(with_tls)
        .build()
        .run()
        .instrument(span.clone())
        .await;

    if let Err(error) = result {
        span.in_scope(|| {
            error!(error = format!("{error:#}"), "WebSocket forwarding failure");
        });
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

        match claims.jet_rec {
            RecordingPolicy::None | RecordingPolicy::External => (),
            RecordingPolicy::Proxy => anyhow::bail!("can't meet recording policy"),
        }

        let ConnectionMode::Fwd { targets, .. } = claims.jet_cm else {
            anyhow::bail!("invalid connection mode")
        };

        let span = tracing::Span::current();

        trace!("Select and connect to target");

        let ((server_stream, server_addr), selected_target) =
            utils::successive_try(&targets, utils::tcp_connect).await?;

        trace!(%selected_target, "Connected");
        span.record("target", selected_target.to_string());

        // ARD uses MVS codec which doesn't like buffering.
        let buffer_size = if claims.jet_ap == ApplicationProtocol::Known(Protocol::Ard) {
            Some(1024)
        } else {
            None
        };

        if with_tls {
            trace!("Establishing TLS connection with server");

            // Establish TLS connection with server

            let server_stream = crate::tls::connect(selected_target.host(), server_stream)
                .await
                .context("TLS connect")?;

            info!("WebSocket-TLS forwarding");

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
                .buffer_size(buffer_size)
                .build()
                .select_dissector_and_forward()
                .await
                .context("encountered a failure during plain tls traffic proxying")
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
                .buffer_size(buffer_size)
                .build()
                .select_dissector_and_forward()
                .await
                .context("encountered a failure during plain tcp traffic proxying")
        }
    }
}
