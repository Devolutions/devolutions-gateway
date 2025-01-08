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
    input_stream: impl tokio::io::AsyncRead + Unpin,
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

    // Note: though sometimes we end the loop with error
    // but we still needs to send 1000 code to the client
    // as it is what is expected for the ascii-player to end the playback properly
    websocket.close().await;
    debug!("Shutting down ASCII streaming");

    Ok(())
}
