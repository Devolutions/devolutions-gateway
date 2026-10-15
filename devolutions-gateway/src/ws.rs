use core::{future, time};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use axum::extract::ws::{self, CloseFrame, WebSocket};
use bytes::Bytes;
use devolutions_gateway_task::{ChildTask, ShutdownSignal};
use futures::{SinkExt as _, StreamExt as _};
use tap::Pipe as _;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct KeepAliveShutdownSignal(pub ShutdownSignal);

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
    let (ws, close_handle) = with_sentinel(ws, shutdown_signal, keep_alive_interval);

    (websocket_compat(ws), close_handle)
}

pub fn handle_messages(
    ws: WebSocket,
    mut shutdown_signal: impl transport::KeepAliveShutdown,
    keep_alive_interval: time::Duration,
) -> (
    impl futures::Stream<Item = Result<Bytes, axum::Error>>
    + futures::Sink<Bytes, Error = axum::Error>
    + Unpin
    + Send
    + 'static,
    MessageCloseHandle,
) {
    let ws = transport::Shared::new(ws);
    let mut keepalive_socket = ws.shared();
    let keepalive = ChildTask::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(keep_alive_interval) => {
                    if let Err(error) = keepalive_socket.send(ws::Message::Ping(Bytes::new())).await {
                        warn!(%error, "WebM WebSocket keepalive failed");
                        break;
                    }
                }
                () = shutdown_signal.wait() => break,
            }
        }
    });
    let peer_closed = Arc::new(AtomicBool::new(false));
    let close_handle = MessageCloseHandle {
        socket: ws.shared(),
        keepalive,
        peer_closed: Arc::clone(&peer_closed),
    };

    let messages = ws
        .take_while(move |item| {
            let closed = matches!(item, Ok(ws::Message::Close(_)));
            if closed {
                peer_closed.store(true, Ordering::Relaxed);
            }
            future::ready(!closed)
        })
        .filter_map(|item| {
            item.map(|msg| match msg {
                ws::Message::Text(s) => Some(Bytes::from(s)),
                ws::Message::Binary(data) => Some(data),
                ws::Message::Ping(_) | ws::Message::Pong(_) => None,
                ws::Message::Close(_) => None,
            })
            .transpose()
            .pipe(future::ready)
        })
        .with(|item: Bytes| futures::future::ready(Ok::<_, axum::Error>(ws::Message::Binary(item))));

    (messages, close_handle)
}

/// Completes the WebM closing handshake, with a five-second deadline for sending and draining.
pub struct MessageCloseHandle {
    socket: transport::Shared<WebSocket>,
    keepalive: ChildTask<()>,
    peer_closed: Arc<AtomicBool>,
}

impl MessageCloseHandle {
    pub async fn normal_close(self) -> anyhow::Result<()> {
        self.close(1000, String::new()).await
    }

    pub async fn server_error(self, message: String) -> anyhow::Result<()> {
        self.close(1011, message).await
    }

    async fn close(mut self, code: u16, reason: String) -> anyhow::Result<()> {
        tokio::time::timeout(time::Duration::from_secs(5), async move {
            self.keepalive.abort();
            if let Err(error) = self.keepalive.join().await
                && !error.is_cancelled()
            {
                return Err(anyhow::Error::new(error).context("join websocket keepalive"));
            }
            if !self.peer_closed.load(Ordering::Relaxed)
                && let Err(error) = self
                    .socket
                    .send(ws::Message::Close(Some(CloseFrame {
                        code,
                        reason: reason.into(),
                    })))
                    .await
            {
                if socket_is_closed(&error) {
                    return Ok(());
                }
                return Err(anyhow::Error::new(error).context("send websocket close"));
            }
            loop {
                if let Err(error) = self.socket.flush().await {
                    if socket_is_closed(&error) {
                        return Ok(());
                    }
                    return Err(anyhow::Error::new(error).context("flush websocket close"));
                }
                if self.peer_closed.load(Ordering::Relaxed) {
                    return Ok(());
                }
                match self.socket.next().await {
                    Some(Ok(ws::Message::Close(_))) => self.peer_closed.store(true, Ordering::Relaxed),
                    Some(Ok(_)) => {}
                    Some(Err(error)) if socket_is_closed(&error) => return Ok(()),
                    Some(Err(error)) => return Err(anyhow::Error::new(error).context("drain websocket close")),
                    None => return Ok(()),
                }
            }
        })
        .await
        .context("websocket closing handshake timed out")?
    }
}

fn socket_is_closed(error: &axum::Error) -> bool {
    use std::error::Error as _;
    error
        .source()
        .and_then(|source| source.downcast_ref::<tungstenite::Error>())
        .is_some_and(|error| {
            matches!(
                error,
                tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed
            )
        })
}

/// Shares the WebSocket with a keep-alive task, which also sends the close frame through the returned handle.
fn with_sentinel(
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
