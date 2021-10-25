use crate::jmux::{JmuxApiRequest, JmuxApiResponse};
use anyhow::Context;
use jetsocat_proxy::Socks5AcceptorConfig;
use slog::{error, info, Logger};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
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
                info!(log, "{} requested redirection to {}", addr, destination_url);

                let (sender, mut receiver) = mpsc::unbounded_channel();

                match api_request_sender.send(JmuxApiRequest::OpenChannel {
                    destination_url: destination_url.clone(),
                    api_response_sender: sender,
                }) {
                    Ok(()) => {}
                    Err(e) => error!(log, "Couldn’t send JMUX API request: {}", e),
                }

                let log = log.clone();
                let api_request_sender = api_request_sender.clone();
                tokio::spawn(async move {
                    match receiver.recv().await {
                        Some(JmuxApiResponse::Success { id }) => {
                            let _ = api_request_sender.send(JmuxApiRequest::Start { id, stream });
                        }
                        Some(JmuxApiResponse::Failure { id, reason_code }) => {
                            error!(log, "Channel {} failed with reason code: {}", id, reason_code);
                        }
                        None => {}
                    }
                });
            }
            Err(e) => {
                error!(log, "Couldn’t accept next TCP stream: {}", e);
                break;
            }
        }
    }

    Ok(())
}

pub async fn socks5_listener_task(
    api_request_sender: mpsc::UnboundedSender<JmuxApiRequest>,
    bind_addr: String,
    log: Logger,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Couldn’t bind listener to {}", bind_addr))?;

    info!(log, "Started listening on {}", bind_addr);

    let conf = Arc::new(Socks5AcceptorConfig {
        no_auth_required: true,
        users: None,
    });

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let api_request_sender = api_request_sender.clone();
                let log = log.clone();
                let conf = Arc::clone(&conf);
                tokio::spawn(async move {
                    if let Err(e) = socks5_process_socket(api_request_sender, stream, addr, conf, log.clone()).await {
                        error!(log, "SOCKS5 packet processed failed: {}", e);
                    }
                });
            }
            Err(e) => {
                error!(log, "Couldn’t accept next TCP stream: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn socks5_process_socket(
    api_request_sender: mpsc::UnboundedSender<JmuxApiRequest>,
    incoming: TcpStream,
    addr: SocketAddr,
    conf: Arc<Socks5AcceptorConfig>,
    log: Logger,
) -> anyhow::Result<()> {
    use jetsocat_proxy::{Socks5Acceptor, Socks5FailureCode};

    let acceptor = Socks5Acceptor::accept_with_config(incoming, &conf).await?;

    if acceptor.is_connect_command() {
        let destination_url = match acceptor.dest_addr() {
            jetsocat_proxy::DestAddr::Ip(addr) => addr.to_string(),
            jetsocat_proxy::DestAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        };

        info!(log, "{} requested redirection to {}", addr, destination_url);

        let (sender, mut receiver) = mpsc::unbounded_channel();

        match api_request_sender.send(JmuxApiRequest::OpenChannel {
            destination_url,
            api_response_sender: sender,
        }) {
            Ok(()) => {}
            Err(e) => error!(log, "Couldn’t send JMUX API request: {}", e),
        }

        let id = match receiver.recv().await.context("negotiation interrupted")? {
            JmuxApiResponse::Success { id } => id,
            JmuxApiResponse::Failure { id, reason_code } => {
                anyhow::bail!("Channel {} failed with reason code: {}", id, reason_code);
            }
        };

        // FIXME: this is dummy data
        let target_stream_local_addr: String = "127.0.0.1:9873".to_owned();

        let stream = acceptor.connected(target_stream_local_addr).await?;

        let _ = api_request_sender.send(JmuxApiRequest::Start { id, stream });
    } else {
        acceptor.failed(Socks5FailureCode::CommandNotSupported).await?;
    }

    Ok(())
}
