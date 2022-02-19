use anyhow::Result;
use futures_util::{pin_mut, ready, Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::{Error as TungsteniteError, Message as TungsteniteMessage};

/// Wraps a WebSocket stream and implements `AsyncRead` and `AsyncWrite`
pub struct WebSocketStream<S> {
    inner: S,
    read_buf: Option<Vec<u8>>,
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
    S: Stream<Item = Result<TungsteniteMessage, TungsteniteError>> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut data = if let Some(data) = self.read_buf.take() {
            data
        } else {
            loop {
                let inner = &mut self.inner;
                pin_mut!(inner);
                match ready!(inner.poll_next(cx)) {
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
                    Some(Err(e)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                    None => return Poll::Ready(Ok(())),
                }
            }
        };

        let bytes_to_copy = std::cmp::min(buf.remaining(), data.len());

        let dest = buf.initialize_unfilled_to(bytes_to_copy);
        dest.copy_from_slice(&data[..bytes_to_copy]);
        buf.advance(bytes_to_copy);

        if data.len() > bytes_to_copy {
            data.drain(..bytes_to_copy);
            self.read_buf = Some(data);
        }

        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for WebSocketStream<S>
where
    S: Sink<TungsteniteMessage, Error = TungsteniteError> + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        macro_rules! try_in_poll {
            ($expr:expr) => {{
                match $expr {
                    Ok(o) => o,
                    // When using `AsyncWriteExt::write_all`, `io::ErrorKind::WriteZero` will be raised.
                    // In this case it means "attempted to write on a closed socket".
                    Err(TungsteniteError::ConnectionClosed) => return Poll::Ready(Ok(0)),
                    Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                }
            }};
        }

        // try flushing preemptively
        let inner = &mut self.inner;
        pin_mut!(inner);
        let _ = inner.poll_flush(cx);

        // make sure sink is ready to send
        let inner = &mut self.inner;
        pin_mut!(inner);
        try_in_poll!(ready!(inner.poll_ready(cx)));

        // actually submit new item
        let inner = &mut self.inner;
        pin_mut!(inner);
        try_in_poll!(inner.start_send(TungsteniteMessage::Binary(buf.to_vec())));
        // ^ if no error occurred, message is accepted and queued when calling `start_send`
        // (that is: `to_vec` is called only once)

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner = &mut self.inner;
        pin_mut!(inner);
        match ready!(inner.poll_flush(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(TungsteniteError::ConnectionClosed) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner = &mut self.inner;
        pin_mut!(inner);
        match ready!(inner.poll_close(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(TungsteniteError::ConnectionClosed) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}
