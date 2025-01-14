pub(crate) mod asciinema;
pub mod trp_decoder;

#[macro_use]
extern crate tracing;

use std::{
    future::Future,
    sync::Arc,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    sync::Notify,
};

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
            _ = shutdown_signal.notified() => {
                break;
            }
        }
    }

    // Note: though sometimes we end the loop with error
    // but we still needs to send 1000 code to the client
    // as it is what is expected for the ascii-player to end the playback properly
    websocket.close().await;
    if let Some(task) = trp_task_handle {
        task.abort();
    }
    debug!("Shutting down ASCII streaming");

    Ok(())
}
