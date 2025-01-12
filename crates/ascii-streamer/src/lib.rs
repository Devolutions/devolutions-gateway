pub mod trp_decoder;

#[macro_use]
extern crate tracing;

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader, ReadBuf},
    sync::Notify,
};

pub trait AsciiStreamSocket {
    fn send(&mut self, value: String) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn close(&mut self) -> impl Future<Output = ()> + Send;
}

pub enum InputStreamType {
    Asciinema,
    Trp,
}

#[tracing::instrument(skip_all)]
pub async fn ascii_stream(
    mut websocket: impl AsciiStreamSocket,
    input_stream: impl AsyncRead + Unpin + Send + 'static,
    shutdown_signal: Arc<Notify>,
    input_type: InputStreamType,
    when_new_chunk_appended: impl Fn() -> tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    info!("Starting ASCII streaming");
    // Write all the data from the input stream to the output stream.
    let either = match input_type {
        InputStreamType::Asciinema => Either::Left(input_stream),
        InputStreamType::Trp => Either::Right(trp_decoder::decode_buffer(input_stream)?),
    };

    let mut lines = BufReader::new(either).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                websocket.send(line.clone()).await?;
            }
            Ok(None) => {
                break;
            }
            Err(e) => {
                warn!(error=%e, "Error reading line");
                continue;
            }
        }
    }

    loop {
        tokio::select! {
            _ = when_new_chunk_appended() => {
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            websocket.send(line.clone()).await?;
                        }
                        Ok(None) => {
                            debug!("EOF reached");
                            break;
                        }
                        Err(e) => {
                            warn!(error=%e, "Error reading line");
                            continue;
                        }
                    }
                }
            }
            _ = shutdown_signal.notified() => {
                break;
            }
        }
    }

    // Note: though sometimes we end the loop with error
    // but we still needs to send 1000 code to the client
    // as it is what is expected for the ascii-player to end the playback properly
    websocket.close().await;
    debug!("Shutting down ASCII streaming");

    Ok(())
}

pub enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<A, B> AsyncRead for Either<A, B>
where
    A: AsyncRead + Unpin + Send,
    B: AsyncRead + Unpin + Send,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Either::Left(left) => Pin::new(left).poll_read(cx, buf),
            Either::Right(right) => Pin::new(right).poll_read(cx, buf),
        }
    }
}
