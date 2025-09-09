use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt};

use crate::pipe::Pipe;

pub(crate) async fn run_mcp_proxy(pipe: Pipe, mut mcp_client: mcp_proxy::McpProxy) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(pipe.stream);

    let mut reader = tokio::io::BufReader::new(reader);

    let mut line = String::new();

    loop {
        line.clear();

        match reader.read_line(&mut line).await? {
            0 => break, // EOF
            _ => {
                let line = line.trim();

                if line.is_empty() {
                    continue;
                }

                trace!(request = %line, "Received request");

                match mcp_client.handle_jsonrpc_request_str(line).await {
                    Ok(Some(resp)) => {
                        let response = resp.to_string()?;
                        writer
                            .write_all(response.as_bytes())
                            .await
                            .context("failed to write response")?;
                    }
                    Ok(None) => {} // Notification; no response.
                    Err(e) => {
                        error!(error = format!("{e:#}"), "failed to handle request");
                    }
                }
            }
        }
    }

    Ok(())
}
