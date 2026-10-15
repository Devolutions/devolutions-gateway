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
        self.close(1000, String::new(), time::Duration::from_secs(5)).await
    }

    pub async fn server_error(self, message: String) -> anyhow::Result<()> {
        self.close(1011, message, time::Duration::from_secs(5)).await
    }

    async fn close(mut self, code: u16, reason: String, timeout: time::Duration) -> anyhow::Result<()> {
        tokio::time::timeout(timeout, async move {
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::Context as _;
    use axum::Router;
    use axum::extract::ws::{Message as ServerMessage, WebSocket, WebSocketUpgrade};
    use axum::routing::get;
    use devolutions_gateway_task::{ChildTask, ShutdownHandle};
    use futures::{SinkExt as _, StreamExt as _};
    use rstest::rstest;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    use super::{KeepAliveShutdownSignal, handle_messages};

    type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

    #[rstest]
    #[case::quiet(false, false, false)]
    #[case::pending_pong(true, false, false)]
    #[case::error_close(false, true, false)]
    #[case::error_close_pending_pong(true, true, false)]
    #[case::keepalive_response(false, false, true)]
    #[tokio::test]
    async fn webm_end_and_close_survive_pending_control_traffic(
        #[case] pong: bool,
        #[case] failed: bool,
        #[case] keepalive: bool,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (server, mut client, _listener) = loopback_pair().await?;
            let (_shutdown, signal) = ShutdownHandle::new();
            let interval = if keepalive {
                Duration::from_millis(10)
            } else {
                Duration::from_secs(60)
            };
            let (mut messages, close) = handle_messages(server, KeepAliveShutdownSignal(signal), interval);
            let terminal = if failed {
                b"\x02{\"error\":\"UnexpectedError\"}".to_vec()
            } else {
                vec![3]
            };
            let expected = Message::Binary(terminal.clone().into());
            let (waiting, ready) = oneshot::channel();
            let (finish, ended) = oneshot::channel();
            let task = ChildTask::spawn(async move {
                assert_eq!(messages.next().await.transpose()?.expect("final Pull"), &[1][..]);
                waiting.send(()).expect("client waits for pending Pull");
                ended.await?;
                messages.send(terminal.into()).await?;
                drop(messages);
                if failed {
                    close.server_error("test stream failure".to_owned()).await
                } else {
                    close.normal_close().await
                }
            });

            client.send(Message::Binary(vec![1].into())).await?;
            ready.await?;
            if keepalive {
                assert!(matches!(
                    client.next().await.transpose()?.expect("keepalive Ping"),
                    Message::Ping(_)
                ));
                client.flush().await?;
            }
            if pong {
                client.send(Message::Pong(Vec::new().into())).await?;
            }
            finish.send(()).expect("server waits for recording end");
            assert_eq!(next_message(&mut client).await?, expected);
            let close = next_message(&mut client).await?;
            // RFC 6455, Section 7.4.1: 1000 is normal closure; 1011 signals an unexpected server condition.
            let expected_code = if failed { 1011 } else { 1000 };
            assert!(
                matches!(close, Message::Close(Some(ref frame)) if u16::from(frame.code) == expected_code),
                "expected Close {expected_code}, got {close:?}",
            );
            assert_orderly_eof(&mut client).await?;
            task.join().await??;
            anyhow::Ok(())
        })
        .await
        .context("loopback close regression timed out")?
    }

    #[tokio::test]
    async fn webm_peer_can_close_immediately_after_end() -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (server, mut client, _listener) = loopback_pair().await?;
            let (_shutdown, signal) = ShutdownHandle::new();
            let (mut messages, close) =
                handle_messages(server, KeepAliveShutdownSignal(signal), Duration::from_secs(60));
            let task = ChildTask::spawn(async move {
                messages.send(vec![3].into()).await?;
                drop(messages);
                close.normal_close().await
            });
            assert_eq!(next_message(&mut client).await?, Message::Binary(vec![3].into()));
            client.close(None).await?;
            // RFC 6455, Section 5.5.1: both peers exchange Close frames before TCP closure.
            assert!(matches!(next_message(&mut client).await?, Message::Close(_)));
            assert_orderly_eof(&mut client).await?;
            task.join().await??;
            anyhow::Ok(())
        })
        .await
        .context("peer closing after End timed out")?
    }

    #[tokio::test]
    async fn webm_acknowledges_a_close_already_received_by_the_stream() -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (server, mut client, _listener) = loopback_pair().await?;
            let (_shutdown, signal) = ShutdownHandle::new();
            let (mut messages, close) =
                handle_messages(server, KeepAliveShutdownSignal(signal), Duration::from_secs(60));
            let task = ChildTask::spawn(async move {
                assert!(messages.next().await.is_none());
                drop(messages);
                close.normal_close().await
            });
            client.close(None).await?;
            // RFC 6455, Section 5.5.1 requires a reply; tungstenite echoes the peer's empty Close payload.
            assert_eq!(next_message(&mut client).await?, Message::Close(None));
            assert_orderly_eof(&mut client).await?;
            task.join().await??;
            anyhow::Ok(())
        })
        .await
        .context("acknowledging peer Close timed out")?
    }

    #[tokio::test]
    async fn webm_client_abort_surfaces_a_close_error_without_hanging() -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (server, client, _listener) = loopback_pair().await?;
            let (_shutdown, signal) = ShutdownHandle::new();
            let (messages, close) = handle_messages(server, KeepAliveShutdownSignal(signal), Duration::from_secs(60));
            drop(client);
            drop(messages);
            close
                .normal_close()
                .await
                .expect_err("aborted peer has no closing handshake");
            anyhow::Ok(())
        })
        .await
        .context("client abort cleanup timed out")?
    }

    #[tokio::test]
    async fn webm_missing_close_reply_times_out_instead_of_reporting_success() -> anyhow::Result<()> {
        let (server, _client, _listener) = loopback_pair().await?;
        let (_shutdown, signal) = ShutdownHandle::new();
        let (messages, close) = handle_messages(server, KeepAliveShutdownSignal(signal), Duration::from_secs(60));
        drop(messages);
        tokio::time::pause();
        let deadline = Duration::from_millis(100);
        let started = tokio::time::Instant::now();
        let error = tokio::time::timeout(Duration::from_secs(1), close.close(1000, String::new(), deadline))
            .await
            .context("close deadline failed to bound cleanup")?
            .expect_err("peer did not acknowledge Close");
        assert!(error.is::<tokio::time::error::Elapsed>());
        assert!(deadline <= started.elapsed());
        Ok(())
    }

    #[tokio::test]
    async fn dropping_webm_close_owner_cancels_keepalive_and_releases_the_socket() -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (server, mut client, _listener) = loopback_pair().await?;
            let (_shutdown, signal) = ShutdownHandle::new();
            let (messages, close) = handle_messages(server, KeepAliveShutdownSignal(signal), Duration::from_millis(10));
            drop(messages);
            // Sole guard for dropping the owner without close(): its keepalive must release the socket.
            drop(close);
            assert!(client.next().await.transpose().is_err());
            anyhow::Ok(())
        })
        .await
        .context("dropped close owner retained its socket")?
    }

    #[tokio::test]
    async fn webm_close_accepts_an_already_completed_handshake() -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut server, mut client, _listener) = loopback_pair().await?;
            client.close(None).await?;
            assert!(matches!(
                server.next().await.transpose()?.context("peer Close")?,
                ServerMessage::Close(None)
            ));
            server.flush().await?;
            assert_eq!(next_message(&mut client).await?, Message::Close(None));
            let (_shutdown, signal) = ShutdownHandle::new();
            let (messages, close) = handle_messages(server, KeepAliveShutdownSignal(signal), Duration::from_secs(60));
            drop(messages);
            close.normal_close().await?;
            assert_orderly_eof(&mut client).await?;
            anyhow::Ok(())
        })
        .await
        .context("already completed handshake cleanup timed out")?
    }

    async fn next_message(client: &mut ClientSocket) -> anyhow::Result<Message> {
        loop {
            let message = client
                .next()
                .await
                .transpose()?
                .context("websocket closed before the expected frame")?;
            if matches!(message, Message::Ping(_) | Message::Pong(_)) {
                client.flush().await?;
            } else {
                return Ok(message);
            }
        }
    }

    async fn assert_orderly_eof(client: &mut ClientSocket) -> anyhow::Result<()> {
        client.flush().await?;
        let MaybeTlsStream::Plain(socket) = client.get_mut() else {
            panic!("loopback client is not TLS");
        };
        // RFC 6455, Section 7.1.1: the server should initiate the TCP close.
        assert_eq!(socket.read(&mut [0]).await?, 0, "server must finish TCP orderly");
        Ok(())
    }

    async fn loopback_pair() -> anyhow::Result<(WebSocket, ClientSocket, ChildTask<anyhow::Result<()>>)> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let (sender, receiver) = oneshot::channel();
        let sender = Arc::new(Mutex::new(Some(sender)));
        let router = Router::new().route(
            "/",
            get(move |upgrade: WebSocketUpgrade| {
                let sender = Arc::clone(&sender);
                async move {
                    upgrade.on_upgrade(move |socket| async move {
                        sender
                            .lock()
                            .expect("test sender mutex is not poisoned")
                            .take()
                            .expect("one test connection")
                            .send(socket)
                            .expect("test receiver is still waiting");
                    })
                }
            }),
        );
        let task =
            ChildTask::spawn(async move { axum::serve(listener, router).await.context("serve loopback websocket") });
        let (client, _) = tokio_tungstenite::connect_async(format!("ws://{address}/")).await?;
        let server = receiver.await.context("receive upgraded websocket")?;
        Ok((server, client, task))
    }
}
