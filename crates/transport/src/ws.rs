use anyhow::Result;
use futures_util::{ready, Sink, Stream};
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::{Error as TungsteniteError, Message as TungsteniteMessage};

pin_project! {
    /// Wraps a stream of WebSocket messages and provides `AsyncRead` and `AsyncWrite`.
    pub struct WebSocketStream<S> {
        #[pin]
        inner: S,
        read_buf: Option<Vec<u8>>,
    }
}

impl<S> WebSocketStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            read_buf: None,
        }
    }
}

impl<S> AsyncRead for WebSocketStream<S>
where
    S: Stream<Item = Result<TungsteniteMessage, TungsteniteError>>,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        let mut data = if let Some(data) = this.read_buf.take() {
            data
        } else {
            loop {
                match ready!(this.inner.as_mut().poll_next(cx)) {
                    Some(Ok(m)) => match m {
                        TungsteniteMessage::Text(s) => {
                            break s.into_bytes();
                        }
                        TungsteniteMessage::Binary(data) => {
                            break data;
                        }

                        // discard ping and pong messages (not part of actual payload)
                        TungsteniteMessage::Ping(_) | TungsteniteMessage::Pong(_) => {}

                        // end reading on Close message
                        TungsteniteMessage::Close(_) => return Poll::Ready(Ok(())),

                        TungsteniteMessage::Frame(_) => unreachable!("raw frames are never returned when reading"),
                    },
                    Some(Err(TungsteniteError::Io(e))) => return Poll::Ready(Err(e)),
                    Some(Err(e)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                    None => return Poll::Ready(Ok(())),
                }
            }
        };

        let bytes_to_copy = std::cmp::min(buf.remaining(), data.len());

        // TODO: can we can better performance with `unfilled_mut` and a bit of unsafe code?
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

impl<S> AsyncWrite for WebSocketStream<S>
where
    S: Sink<TungsteniteMessage, Error = TungsteniteError>,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        macro_rules! try_in_poll {
            ($expr:expr) => {{
                match $expr {
                    Ok(o) => o,
                    // When using `AsyncWriteExt::write_all`, `io::ErrorKind::WriteZero` will be raised.
                    // In this case it means "attempted to write on a closed socket".
                    Err(TungsteniteError::ConnectionClosed) => return Poll::Ready(Ok(0)),
                    Err(TungsteniteError::Io(e)) => return Poll::Ready(Err(e)),
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
        try_in_poll!(this.inner.start_send(TungsteniteMessage::Binary(buf.to_vec())));
        // ^ if no error occurred, message is accepted and queued when calling `start_send`
        // (that is: `to_vec` is called only once)

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = ready!(self.project().inner.poll_flush(cx));
        Poll::Ready(tungstenite_to_io_result(res))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = ready!(self.project().inner.poll_close(cx));
        Poll::Ready(tungstenite_to_io_result(res))
    }
}

fn tungstenite_to_io_result(res: Result<(), TungsteniteError>) -> io::Result<()> {
    match res {
        Ok(()) => Ok(()),
        Err(TungsteniteError::ConnectionClosed) => Ok(()),
        Err(TungsteniteError::Io(e)) => Err(e),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}
