use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt};
use tracing::{debug, error, warn};

use crate::pipe::Pipe;

pub(crate) async fn run_mcp_proxy(pipe: Pipe, mut mcp_proxy: mcp_proxy::McpProxy) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(pipe.stream);

    let mut reader = tokio::io::BufReader::new(reader);

    let mut line = String::new();

    loop {
        tokio::select! {
            biased;

            // Read from pipe.
            // FIXME: NOT cancel safe.
            result = reader.read_line(&mut line) => {
                let n_read = result.context("failed to read from pipe")?;

                if n_read == 0 {
                    debug!("Pipe EOFed");
                    return Ok(());
                }

                // Forward message to peer.
                match mcp_proxy.send_message(&line).await {
                    Ok(response) => {
                        // For HTTP transport, response is returned immediately.
                        // For Process/NamedPipe, response is None and will come via read_message.
                        // TODO(DGW-316): support for HTTP SSE (long polling) mode.
                        if let Some(msg) = response {
                            write_flush_message(&mut writer, msg).await?;
                        }
                    }
                    Err(mcp_proxy::SendError::Transient { message, source }) => {
                        warn!(error = format!("{source:#}"), "Transient error forwarding message");

                        if let Some(msg) = message {
                            write_flush_message(&mut writer, msg).await?;
                        }
                    }
                    Err(mcp_proxy::SendError::Fatal { message, source }) => {
                        error!(error = format!("{source:#}"), "Fatal error forwarding message, stopping proxy");

                        if let Some(msg) = message {
                            let _ = write_flush_message(&mut writer, msg).await;
                        }

                        return Ok(());
                    }
                }

                line.clear();
            }

            // Read from peer.
            // FIXME: NOT cancel safe.
            result = mcp_proxy.read_message() => {
                match result {
                    Ok(message) => {
                        write_flush_message(&mut writer, message).await?;
                    }
                    Err(mcp_proxy::ReadError::Transient(source)) => {
                        warn!(error = format!("{source:#}"), "Transient error reading from MCP server");
                    }
                    Err(mcp_proxy::ReadError::Fatal(source)) => {
                        error!(error = format!("{source:#}"), "Fatal error reading from MCP server, stopping proxy");
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn write_flush_message(
        mut writer: impl tokio::io::AsyncWrite + Unpin,
        message: mcp_proxy::Message,
    ) -> anyhow::Result<()> {
        let payload = message.as_newline_terminated_raw().as_bytes();
        writer.write_all(payload).await.context("failed to write response")?;
        writer.flush().await.context("failed to flush writer")?;
        Ok(())
    }
}
