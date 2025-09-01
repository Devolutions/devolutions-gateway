use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::ws::WebSocket;
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::Response;
use devolutions_gateway_task::ShutdownSignal;
use tracing::Instrument as _;

use crate::DgwState;
use crate::extract::JmuxToken;
use crate::http::HttpError;
use crate::session::SessionMessageSender;
use crate::subscriber::SubscriberSender;
use crate::token::JmuxTokenClaims;
use crate::traffic_audit::TrafficAuditHandle;

pub async fn handler(
    State(DgwState {
        sessions,
        subscriber_tx,
        shutdown_signal,
        conf_handle,
        traffic_audit_handle,
        ..
    }): State<DgwState>,
    JmuxToken(claims): JmuxToken,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, HttpError> {
    let response = ws.on_upgrade(move |ws| {
        handle_socket(
            ws,
            shutdown_signal,
            sessions,
            subscriber_tx,
            traffic_audit_handle,
            claims,
            source_addr,
            Duration::from_secs(conf_handle.get_conf().debug.ws_keep_alive_interval),
        )
    });

    Ok(response)
}

async fn handle_socket(
    ws: WebSocket,
    shutdown_signal: ShutdownSignal,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    traffic_audit_handle: TrafficAuditHandle,
    claims: JmuxTokenClaims,
    source_addr: SocketAddr,
    keep_alive_interval: Duration,
) {
    let (stream, close_handle) = crate::ws::handle(
        ws,
        crate::ws::KeepAliveShutdownSignal(shutdown_signal),
        keep_alive_interval,
    );

    let result = crate::jmux::handle(stream, claims, sessions, subscriber_tx, traffic_audit_handle)
        .instrument(info_span!("jmux", client = %source_addr))
        .await;

    if let Err(error) = result {
        close_handle.server_error("JMUX failure".to_owned()).await;
        error!(client = %source_addr, error = format!("{error:#}"), "JMUX failure");
    } else {
        close_handle.normal_close().await;
    }
}
