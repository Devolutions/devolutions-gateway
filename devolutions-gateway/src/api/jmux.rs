use std::net::SocketAddr;

use axum::extract::ws::WebSocket;
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::Response;
use tracing::Instrument as _;

use crate::extract::JmuxToken;
use crate::http::HttpError;
use crate::session::SessionManagerHandle;
use crate::subscriber::SubscriberSender;
use crate::token::JmuxTokenClaims;
use crate::DgwState;

pub async fn handler(
    State(DgwState {
        sessions,
        subscriber_tx,
        ..
    }): State<DgwState>,
    JmuxToken(claims): JmuxToken,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    let response = ws.on_upgrade(move |ws| handle_socket(ws, sessions, subscriber_tx, claims, source_addr));

    Ok(response)
}

async fn handle_socket(
    ws: WebSocket,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    claims: JmuxTokenClaims,
    source_addr: SocketAddr,
) {
    let stream = crate::ws::websocket_compat(ws);

    let result = crate::jmux::handle(stream, claims, sessions, subscriber_tx)
        .instrument(info_span!("jmux", client = %source_addr))
        .await;

    if let Err(error) = result {
        error!(client = %source_addr, error = format!("{error:#}"), "JMUX failure");
    }
}
