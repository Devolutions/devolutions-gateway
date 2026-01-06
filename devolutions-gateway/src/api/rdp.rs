use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::WebSocket;
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::Response;
use devolutions_gateway_task::ShutdownSignal;
use tracing::Instrument as _;

use crate::DgwState;
use crate::config::Conf;
use crate::http::HttpError;
use crate::recording::ActiveRecordings;
use crate::session::SessionMessageSender;
use crate::subscriber::SubscriberSender;
use crate::token::{CurrentJrl, TokenCache};

pub async fn handler(
    State(DgwState {
        conf_handle,
        token_cache,
        jrl,
        sessions,
        subscriber_tx,
        recordings,
        shutdown_signal,
        credential_store,
        ..
    }): State<DgwState>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    let conf = conf_handle.get_conf();
    let span = tracing::Span::current();

    let response = ws.on_upgrade(move |ws| {
        handle_socket(
            ws,
            conf,
            token_cache,
            jrl,
            sessions,
            shutdown_signal,
            subscriber_tx,
            recordings.active_recordings,
            source_addr,
            credential_store,
        )
        .instrument(span)
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
    shutdown_signal: ShutdownSignal,
    subscriber_tx: SubscriberSender,
    active_recordings: Arc<ActiveRecordings>,
    source_addr: SocketAddr,
    credential_store: crate::credential::CredentialStoreHandle,
) {
    let (stream, close_handle) = crate::ws::handle(
        ws,
        crate::ws::KeepAliveShutdownSignal(shutdown_signal),
        Duration::from_secs(conf.debug.ws_keep_alive_interval),
    );

    let result = crate::rd_clean_path::handle(
        stream,
        source_addr,
        conf,
        &token_cache,
        &jrl,
        sessions,
        subscriber_tx,
        &active_recordings,
        &credential_store,
    )
    .await;

    if let Err(error) = result {
        close_handle.server_error("forwarding failure".to_owned()).await;
        error!(client = %source_addr, error = format!("{error:#}"), "RDP failure");
    } else {
        close_handle.normal_close().await;
    }
}
