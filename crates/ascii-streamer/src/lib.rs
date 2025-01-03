#[macro_use]
extern crate tracing;

use std::{future::Future, sync::Arc};

use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::Notify,
};

pub trait AsciiStreamSocket {
    fn send(&mut self, value: String) -> impl Future<Output = anyhow::Result<()>> + Send;
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
    let mut last_line = None;

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                websocket.send(line.clone()).await?;
                last_line = Some(line);
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
                            last_line = Some(line);
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
    if let Some(line) = last_line {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            if value.get("status").is_none() {
                let _ = websocket
                    .send(serde_json::json!({"status": "offline"}).to_string())
                    .await
                    .inspect_err(|e| warn!(error = format!("{e:#}"), "failed to send offline status"));
            }
        }
    }

    debug!("Shutting down ASCII streaming");

    Ok(())
}
