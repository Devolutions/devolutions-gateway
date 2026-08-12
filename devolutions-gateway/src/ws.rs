use core::{future, time};
use std::sync::Arc;

use axum::extract::ws::{self, CloseFrame, WebSocket};
use bytes::Bytes;
use devolutions_gateway_task::ShutdownSignal;
use futures::{SinkExt as _, StreamExt as _};
use tap::Pipe as _;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct KeepAliveShutdownSignal(pub ShutdownSignal);

pub type MessageObserver = Arc<dyn Fn(&ws::Message) + Send + Sync + 'static>;

impl transport::KeepAliveShutdown for KeepAliveShutdownSignal {
    fn wait(&mut self) -> impl Future<Output = ()> + Send + '_ {
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
    handle_with_observer(ws, shutdown_signal, keep_alive_interval, None)
}

pub fn handle_with_observer(
    ws: WebSocket,
    shutdown_signal: impl transport::KeepAliveShutdown,
    keep_alive_interval: time::Duration,
    observer: Option<MessageObserver>,
) -> (
    impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    transport::CloseWebSocketHandle,
) {
    let (ws, close_handle) = prepare_websocket(ws, shutdown_signal, keep_alive_interval);
    let messages = websocket_messages(ws, observer)
        .map(|item| item.map(transport::WsReadMsg::Payload))
        .with(|item: Vec<u8>| future::ready(Ok::<_, axum::Error>(Bytes::from(item))));

    (transport::WsStream::new(messages), close_handle)
}

pub fn handle_messages(
    ws: WebSocket,
    shutdown_signal: impl transport::KeepAliveShutdown,
    keep_alive_interval: time::Duration,
) -> (
    impl futures::Stream<Item = Result<Bytes, axum::Error>>
    + futures::Sink<Bytes, Error = axum::Error>
    + Unpin
    + Send
    + 'static,
    transport::CloseWebSocketHandle,
) {
    let (ws, close_handle) = prepare_websocket(ws, shutdown_signal, keep_alive_interval);
    (websocket_messages(ws, None), close_handle)
}

fn prepare_websocket(
    ws: WebSocket,
    shutdown_signal: impl transport::KeepAliveShutdown,
    keep_alive_interval: time::Duration,
) -> (transport::Shared<WebSocket>, transport::CloseWebSocketHandle) {
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

    (ws, close_handle)
}

fn websocket_messages(
    ws: transport::Shared<WebSocket>,
    observer: Option<MessageObserver>,
) -> impl futures::Stream<Item = Result<Bytes, axum::Error>>
+ futures::Sink<Bytes, Error = axum::Error>
+ Unpin
+ Send
+ 'static {
    ws.inspect(move |item| {
        if let (Some(observer), Ok(message)) = (&observer, item) {
            observer(message);
        }
    })
    .take_while(|item| future::ready(!matches!(item, Ok(ws::Message::Close(_)))))
    .filter_map(move |item| {
        item.map(|msg| match msg {
            ws::Message::Text(s) => Some(Bytes::from(s)),
            ws::Message::Binary(data) => Some(data),
            ws::Message::Ping(_) | ws::Message::Pong(_) => None,
            ws::Message::Close(_) => None,
        })
        .transpose()
        .pipe(future::ready)
    })
    .with(|item: Bytes| futures::future::ready(Ok::<_, axum::Error>(ws::Message::Binary(item))))
}
