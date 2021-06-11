use anyhow::Result;
use async_tungstenite::tungstenite::{Error as TungsteniteError, Message as TungsteniteMessage};
use futures_util::{pin_mut, ready, Sink, Stream};
use slog::{trace, Logger};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn forward<R, W>(mut reader: R, mut writer: W, logger: Logger) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut buf = [0u8; 5120];

    loop {
        let bytes_read = reader.read(&mut buf).await?;

        if bytes_read == 0 {
            break;
        }

        trace!(logger, r#""{}""#, String::from_utf8_lossy(&buf[..bytes_read]));

        writer.write_all(&buf[..bytes_read]).await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Wraps a WebSocket stream and implements `AsyncRead`
pub struct ReadableWebSocketHalf<S> {
    inner: S,
    read_buf: Option<Vec<u8>>,
}

impl<S> ReadableWebSocketHalf<S>
where
    S: Stream<Item = Result<TungsteniteMessage, TungsteniteError>> + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            read_buf: None,
        }
    }
}

impl<S> AsyncRead for ReadableWebSocketHalf<S>
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

/// Wraps a WebSocket stream and implements `AsyncWrite`
pub struct WritableWebSocketHalf<S> {
    inner: S,
}

impl<S> WritableWebSocketHalf<S>
where
    S: Sink<TungsteniteMessage, Error = TungsteniteError> + Unpin,
{
    pub fn new(stream: S) -> Self {
        Self { inner: stream }
    }
}

impl<S> AsyncWrite for WritableWebSocketHalf<S>
where
    S: Sink<TungsteniteMessage, Error = TungsteniteError> + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        macro_rules! try_in_poll {
            ($expr:expr) => {{
                match $expr {
                    Ok(o) => o,
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

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner = &mut self.inner;
        pin_mut!(inner);
        inner
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner = &mut self.inner;
        pin_mut!(inner);
        inner
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}
