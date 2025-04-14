use core::{future, time};

use axum::extract::ws::{self, CloseFrame, WebSocket};
use bytes::Bytes;
use devolutions_gateway_task::ShutdownSignal;
use futures::{SinkExt as _, StreamExt as _};
use tap::Pipe as _;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct KeepAliveShutdownSignal(pub ShutdownSignal);

impl transport::KeepAliveShutdown for KeepAliveShutdownSignal {
    fn wait(&mut self) -> impl future::Future<Output = ()> + Send + '_ {
        self.0.wait()
    }
}

/// Spawns a keep-alive task and wraps the WebSocket into a type implementing AsyncRead and AsyncWrite.
pub fn handle(
    ws: WebSocket,
    shutdown_signal: impl transport::KeepAliveShutdown,
    keep_alive_interval: time::Duration,
) -> (
    impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    transport::CloseWebSocketHandle,
) {
    let ws = transport::Shared::new(ws);

    let close_handle = transport::spawn_websocket_sentinel_task(
        ws.shared().with(|message: transport::WsWriteMsg| {
            future::ready(Result::<_, axum::Error>::Ok(match message {
                transport::WsWriteMsg::Ping => ws::Message::Ping(Bytes::new()),
                transport::WsWriteMsg::Close(frame) => ws::Message::Close(Some(CloseFrame {
                    code: frame.code,
                    reason: frame.message.into(),
                })),
            }))
        }),
        shutdown_signal,
        keep_alive_interval,
    );

    (websocket_compat(ws), close_handle)
}

fn websocket_compat(ws: transport::Shared<WebSocket>) -> impl AsyncRead + AsyncWrite + Unpin + Send + 'static {
    let ws_compat = ws
        .filter_map(|item| {
            item.map(|msg| match msg {
                ws::Message::Text(s) => Some(transport::WsReadMsg::Payload(Bytes::from(s))),
                ws::Message::Binary(data) => Some(transport::WsReadMsg::Payload(data)),
                ws::Message::Ping(_) | ws::Message::Pong(_) => None,
                ws::Message::Close(_) => Some(transport::WsReadMsg::Close),
            })
            .transpose()
            .pipe(future::ready)
        })
        .with(|item| futures::future::ready(Ok::<_, axum::Error>(ws::Message::Binary(Bytes::from(item)))));

    transport::WsStream::new(ws_compat)
}
