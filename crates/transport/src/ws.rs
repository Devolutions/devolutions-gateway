use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::{ready, Stream};
use futures_sink::Sink;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};

pub enum WsMessage {
    Payload(Vec<u8>),
    Ignored,
    Close,
}

pin_project! {
    /// Wraps a stream of WebSocket messages and provides `AsyncRead` and `AsyncWrite`.
    pub struct WsStream<S> {
        #[pin]
        pub inner: S,
        read_buf: Option<Vec<u8>>,
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
    S: Stream<Item = Result<WsMessage, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        let mut data = if let Some(data) = this.read_buf.take() {
            data
        } else {
            loop {
                match ready!(this.inner.as_mut().poll_next(cx)) {
                    Some(Ok(m)) => match m {
                        WsMessage::Payload(data) => {
                            break data;
                        }
                        WsMessage::Ignored => {}
                        WsMessage::Close => return Poll::Ready(Ok(())),
                    },
                    Some(Err(e)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                    None => return Poll::Ready(Ok(())),
                }
            }
        };

        let bytes_to_copy = std::cmp::min(buf.remaining(), data.len());

        // TODO: can we get better performance with `unfilled_mut` and a bit of unsafe code?
        let dest = buf.initialize_unfilled_to(bytes_to_copy);
        dest.copy_from_slice(&data[..bytes_to_copy]);
        buf.advance(bytes_to_copy);

        if data.len() > bytes_to_copy {
            data.drain(..bytes_to_copy);
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
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}
