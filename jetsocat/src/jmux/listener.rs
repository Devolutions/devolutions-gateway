use crate::jmux::JmuxApiRequest;
use slog::{error, info, Logger};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum ListenerMode {
    Tcp { bind_addr: String, destination_url: String },
    Socks5 { bind_addr: String },
}

pub async fn tcp_listener_task(
    api_request_sender: mpsc::UnboundedSender<JmuxApiRequest>,
    bind_addr: String,
    destination_url: String,
    log: Logger,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Couldn’t bind listener to {}", bind_addr))?;

    info!(log, "Started listening on {}", bind_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let (sender, _) = mpsc::unbounded_channel();
                match api_request_sender.send(JmuxApiRequest::OpenChannel {
                    stream,
                    addr,
                    destination_url: destination_url.clone(),
                    api_response_sender: sender,
                }) {
                    Ok(()) => {}
                    Err(e) => error!(log, "Couldn’t send JMUX API request: {}", e),
                }
            }
            Err(e) => {
                error!(log, "Couldn’t accept next TCP stream: {}", e);
                break;
            }
        }
    }

    Ok(())
}
