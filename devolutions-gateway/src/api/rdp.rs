use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::WebSocket;
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::Response;
use tracing::Instrument as _;

use crate::config::Conf;
use crate::http::HttpError;
use crate::recording::ActiveRecordings;
use crate::session::SessionMessageSender;
use crate::subscriber::SubscriberSender;
use crate::token::{CurrentJrl, TokenCache};
use crate::DgwState;

pub async fn handler(
    State(DgwState {
        conf_handle,
        token_cache,
        jrl,
        sessions,
        subscriber_tx,
        recordings,
        ..
    }): State<DgwState>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    let conf = conf_handle.get_conf();

    let response = ws.on_upgrade(move |ws| {
        handle_socket(
            ws,
            conf,
            token_cache,
            jrl,
            sessions,
            subscriber_tx,
            recordings.active_recordings,
            source_addr,
        )
    });

    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn handle_socket(
    ws: WebSocket,
    conf: Arc<Conf>,
    token_cache: Arc<TokenCache>,
    jrl: Arc<CurrentJrl>,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    active_recordings: Arc<ActiveRecordings>,
    source_addr: SocketAddr,
) {
    let stream = crate::ws::websocket_compat(ws);

    let result = crate::rdp_extension::handle(
        stream,
        source_addr,
        conf,
        &token_cache,
        &jrl,
        sessions,
        subscriber_tx,
        &active_recordings,
    )
    .instrument(info_span!("rdp", client = %source_addr))
    .await;

    if let Err(error) = result {
        error!(client = %source_addr, error = format!("{error:#}"), "RDP failure");
    }
}
