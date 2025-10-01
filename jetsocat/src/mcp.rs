use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt};

use crate::pipe::Pipe;

pub(crate) async fn run_mcp_proxy(pipe: Pipe, mut mcp_client: mcp_proxy::McpProxy) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(pipe.stream);

    let mut reader = tokio::io::BufReader::new(reader);

    let mut line = String::new();

    loop {
        line.clear();

        let n_read = reader.read_line(&mut line).await.context("read_line")?;

        if n_read == 0 {
            debug!("Pipe EOFed");
            return Ok(());
        }

        match mcp_client.forward_request(&line).await {
            Some(response) => {
                // For all the supported client pipe transports, messages are required to be delimited by newlines.
                let payload = response.as_newline_terminated_raw().as_bytes();
                writer.write_all(payload).await.context("failed to write response")?;
                writer.flush().await.context("failed to flush writer")?;
            }
            None => {} // Notification; no response.
        }
    }
}
