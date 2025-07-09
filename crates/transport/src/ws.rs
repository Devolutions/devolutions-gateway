use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::{Stream, ready};
use futures_sink::Sink;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};

pub enum WsReadMsg {
    Payload(Bytes),
    Close,
}

pin_project! {
    /// Wraps a stream of WebSocket messages and provides `AsyncRead` and `AsyncWrite`.
    pub struct WsStream<S> {
        #[pin]
        pub inner: S,
        read_buf: Option<Bytes>,
    }
}

impl<S> WsStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            read_buf: None,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S, E> AsyncRead for WsStream<S>
where
    S: Stream<Item = Result<WsReadMsg, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        let mut data = if let Some(data) = this.read_buf.take() {
            data
        } else {
            match ready!(this.inner.as_mut().poll_next(cx)) {
                Some(Ok(m)) => match m {
                    WsReadMsg::Payload(data) => data,
                    WsReadMsg::Close => return Poll::Ready(Ok(())),
                },
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Ok(())),
            }
        };

        let bytes_to_copy = std::cmp::min(buf.remaining(), data.len());

        // TODO: can we get better performance with `unfilled_mut` and a bit of unsafe code?
        let dest = buf.initialize_unfilled_to(bytes_to_copy);
        dest.copy_from_slice(&data.split_to(bytes_to_copy));
        buf.advance(bytes_to_copy);

        if !data.is_empty() {
            *this.read_buf = Some(data);
        }

        Poll::Ready(Ok(()))
    }
}

impl<S, E> AsyncWrite for WsStream<S>
where
    S: Sink<Vec<u8>, Error = E>,
    E: std::error::Error + Send + Sync + 'static,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        macro_rules! try_in_poll {
            ($expr:expr) => {{
                match $expr {
                    Ok(o) => o,
                    Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                }
            }};
        }

        let mut this = self.project();

        // try flushing preemptively
        let _ = this.inner.as_mut().poll_flush(cx);

        // make sure sink is ready to send
        try_in_poll!(ready!(this.inner.as_mut().poll_ready(cx)));

        // actually submit new item
        try_in_poll!(this.inner.start_send(buf.to_vec()));
        // ^ if no error occurred, message is accepted and queued when calling `start_send`
        // (that is: `to_vec` is called only once)

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = ready!(self.project().inner.poll_flush(cx));
        Poll::Ready(to_io_result(res))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = ready!(self.project().inner.poll_close(cx));
        Poll::Ready(to_io_result(res))
    }
}

fn to_io_result<E: std::error::Error + Send + Sync + 'static>(res: Result<(), E>) -> io::Result<()> {
    match res {
        Ok(()) => Ok(()),
        Err(e) => Err(io::Error::other(e)),
    }
}

pub struct WsCloseFrame {
    pub code: u16,
    pub message: String,
}

pub enum WsWriteMsg {
    Ping,
    Close(WsCloseFrame),
}

pub trait KeepAliveShutdown: Send + 'static {
    fn wait(&mut self) -> impl Future<Output = ()> + Send + '_;
}

impl KeepAliveShutdown for std::sync::Arc<tokio::sync::Notify> {
    fn wait(&mut self) -> impl Future<Output = ()> + Send + '_ {
        self.notified()
    }
}

pub struct CloseWebSocketHandle {
    sender: tokio::sync::mpsc::Sender<WsCloseFrame>,
}

// Note: Never sends 1005 and 1006 manually, as specified in RFC6455, section 7.4.1
impl CloseWebSocketHandle {
    pub async fn normal_close(self) {
        let _ = self
            .sender
            .send(WsCloseFrame {
                code: 1000,
                message: String::new(),
            })
            .await;
    }

    pub async fn server_error(self, message: String) {
        let _ = self.sender.send(WsCloseFrame { code: 1011, message }).await;
    }

    pub async fn bad_gateway(self) {
        let _ = self
            .sender
            .send(WsCloseFrame {
                code: 1014,
                message: String::new(),
            })
            .await;
    }
}

/// A background "sentinel" task responsible for keeping the WebSocket connection alive
/// and handling close requests.
///
/// - Periodically sends Ping frames to ensure the connection remains active.
/// - Listens for close requests, forwarding any received close frames to cleanly terminate
///   the WebSocket communication.
/// - Terminates when either the close signal is processed or if sending the Ping frame fails.
pub fn spawn_websocket_sentinel_task<S>(
    mut ws: S,
    mut shutdown_signal: impl KeepAliveShutdown,
    keep_alive_interval: core::time::Duration,
) -> CloseWebSocketHandle
where
    S: Sink<WsWriteMsg> + Unpin + Send + 'static,
{
    use futures_util::SinkExt as _;
    use tracing::Instrument as _;

    let span = tracing::Span::current();
    let (close_frame_sender, mut close_frame_receiver) = tokio::sync::mpsc::channel(1);

    tokio::spawn(
        async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(keep_alive_interval) => {
                        if ws.send(WsWriteMsg::Ping).await.is_err() {
                            break;
                        }
                    }
                    frame = close_frame_receiver.recv() => {
                        if let Some(frame) = frame {
                            let _ = ws.send(WsWriteMsg::Close(frame)).await;
                        }
                        break;
                    }
                    () = shutdown_signal.wait() => break,
                }
            }
        }
        .instrument(span),
    );

    CloseWebSocketHandle {
        sender: close_frame_sender,
    }
}
