pub(crate) mod asciinema;
pub mod trp_decoder;

#[macro_use]
extern crate tracing;

use std::future::Future;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::sync::Notify;

pub trait TerminalStreamSocket {
    fn send(&mut self, value: String) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn close(&mut self) -> impl Future<Output = ()> + Send;
}

pub enum InputStreamType {
    Asciinema,
    Trp,
}

#[tracing::instrument(skip_all)]
pub async fn terminal_stream(
    mut websocket: impl TerminalStreamSocket,
    input_stream: impl AsyncRead + Unpin + Send + 'static,
    shutdown_signal: Arc<Notify>,
    input_type: InputStreamType,
    when_new_chunk_appended: impl Fn() -> tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    info!("Starting ASCII streaming");

    let mut trp_task_handle = None;
    // Write all the data from the input stream to the output stream.
    let boxed_stream = match input_type {
        InputStreamType::Asciinema => Box::new(input_stream) as Box<dyn AsyncRead + Unpin + Send + 'static>,
        InputStreamType::Trp => {
            let (task, stream) = trp_decoder::decode_stream(input_stream)?;
            trp_task_handle = Some(task);
            Box::new(stream) as Box<dyn AsyncRead + Unpin + Send + 'static>
        }
    };

    let mut lines = BufReader::new(boxed_stream).lines();

    // iterate and drain all the lines from the input stream
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

    // Register the shutdown waiter once and keep it alive across iterations. The recording manager
    // signals end-of-stream with `Notify::notify_waiters`, which only wakes already-registered
    // waiters and stores no permit. A `notified()` future created fresh inside the `select!` would
    // miss a notification that fires while we are draining lines, leaving the stream open forever
    // (the client keeps "playing" after the source ended).
    let shutdown = shutdown_signal.notified();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = when_new_chunk_appended() => {
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
            }
            _ = &mut shutdown => {
                break;
            }
        }
    }

    // Note: though sometimes we end the loop with an error, we still send a close frame so the
    // player ends playback properly (the close code is chosen by the TerminalStreamSocket impl).
    websocket.close().await;
    if let Some(task) = trp_task_handle {
        task.abort();
    }
    debug!("Shutting down ASCII streaming");

    Ok(())
}
