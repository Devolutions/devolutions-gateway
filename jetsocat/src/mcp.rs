//! MCP proxy loop for jetsocat.

use anyhow::Context as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, warn};

use crate::pipe::Pipe;

pub(crate) async fn run_mcp_proxy(pipe: Pipe, mut mcp_proxy: mcp_proxy::McpProxy) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(pipe.stream);

    // Buffer for cancel-safe line reading from client.
    let mut client_read_buffer = Vec::new();

    loop {
        // ## Cancel Safety
        //
        // We use `tokio::select!` to concurrently read from both the client pipe and
        // the MCP server. Both read operations are cancel-safe:
        //
        // - `read_line_cancel_safe()` uses an internal buffer for line-framing
        // - `mcp_proxy.read_message()` has internal buffering in the mcp-proxy library
        //
        // If one branch completes first, the other branch is cancelled, but no data is lost
        // because the buffers persist across calls.
        tokio::select! {
            biased;

            // Read from client pipe in a cancel-safe manner.
            result = read_line_cancel_safe(&mut reader, &mut client_read_buffer) => {
                let line = result.context("failed to read from client pipe")?;

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
                        warn!(error = format!("{source:#}"), "Transient error sending message");

                        if let Some(msg) = message {
                            write_flush_message(&mut writer, msg).await?;
                        }
                    }
                    Err(mcp_proxy::SendError::Fatal { message, source }) => {
                        error!(error = format!("{source:#}"), "Fatal error sending message, stopping proxy");

                        if let Some(msg) = message {
                            let _ = write_flush_message(&mut writer, msg).await;
                        }

                        return Ok(());
                    }
                }
            }

            // Read from MCP peer.
            result = mcp_proxy.read_message() => {
                match result {
                    Ok(message) => {
                        write_flush_message(&mut writer, message).await?;
                    }
                    Err(mcp_proxy::ReadError::Transient(source)) => {
                        warn!(error = format!("{source:#}"), "Transient error reading from peer");
                    }
                    Err(mcp_proxy::ReadError::Fatal(source)) => {
                        error!(error = format!("{source:#}"), "Fatal error reading from peer, stopping proxy");
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

/// Read a newline-delimited line from an async reader in a cancel-safe manner.
///
/// Uses an internal buffer that persists across calls, so if the future is cancelled
/// (e.g., in a `tokio::select!`), no data is lost.
async fn read_line_cancel_safe<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> std::io::Result<String> {
    loop {
        // Check if we have a complete line in the buffer (ends with '\n').
        if let Some(newline_pos) = buffer.iter().position(|&b| b == b'\n') {
            // Extract the line including the newline.
            let line_bytes: Vec<u8> = buffer.drain(..=newline_pos).collect();
            let line = String::from_utf8(line_bytes).map_err(std::io::Error::other)?;
            return Ok(line);
        }

        // Need more data - read_buf from stdout (cancel-safe operation).
        let n = reader.read_buf(buffer).await?;

        if n == 0 {
            // EOF reached.
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
    }
}
