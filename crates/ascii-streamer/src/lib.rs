#[macro_use]
extern crate tracing;

use std::{future::Future, sync::Arc};

use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::Notify,
};

pub trait AsciiStreamSocket {
    fn send(&mut self, value: String) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn close(&mut self) -> impl Future<Output = ()> + Send;
}

#[tracing::instrument(skip_all)]
pub async fn ascii_stream(
    mut websocket: impl AsciiStreamSocket,
    input_stream: impl tokio::io::AsyncRead + Unpin, // A file usually
    shutdown_signal: Arc<Notify>,
    when_new_chunk_appended: impl Fn() -> tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    info!("Starting ASCII streaming");
    // write all the data from the input stream to the output stream
    let buf_reader = BufReader::new(input_stream);
    let mut lines = BufReader::new(buf_reader).lines();

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

    // signal the end of the stream
    websocket.close();

    debug!("Shutting down ASCII streaming");

    Ok(())
}
