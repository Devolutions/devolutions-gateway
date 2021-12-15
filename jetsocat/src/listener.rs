use anyhow::Context;
use jetsocat_proxy::Socks5AcceptorConfig;
use jmux_proxy::{ApiRequestSender, DestinationUrl, JmuxApiRequest, JmuxApiResponse};
use slog::{debug, error, info, o, warn, Logger};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::oneshot;

#[derive(Debug, Clone)]
pub enum ListenerMode {
    Tcp { bind_addr: String, destination_url: String },
    Socks5 { bind_addr: String },
}

pub async fn tcp_listener_task(
    api_request_tx: ApiRequestSender,
    bind_addr: String,
    destination_url: String,
    log: Logger,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use tokio::net::TcpListener;

    let destination_url = format!("tcp://{}", destination_url);

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Couldn’t bind listener to {}", bind_addr))?;

    info!(log, "Started listening on {}", bind_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let log = log.new(o!("addr" => addr));
                let api_request_tx = api_request_tx.clone();
                let destination_url = destination_url.clone();

                tokio::spawn(async move {
                    debug!(log, "Request {}", destination_url);

                    let destination_url = match DestinationUrl::parse_str(&destination_url) {
                        Ok(url) => url,
                        Err(e) => {
                            debug!(log, "Bad request: {}", e);
                            return;
                        }
                    };

                    let (sender, receiver) = oneshot::channel();

                    match api_request_tx
                        .send(JmuxApiRequest::OpenChannel {
                            destination_url,
                            api_response_tx: sender,
                        })
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            warn!(log, "Couldn’t send JMUX API request: {}", e);
                            return;
                        }
                    }

                    match receiver.await {
                        Ok(JmuxApiResponse::Success { id }) => {
                            let _ = api_request_tx.send(JmuxApiRequest::Start { id, stream }).await;
                        }
                        Ok(JmuxApiResponse::Failure { id, reason_code }) => {
                            debug!(log, "Channel {} failure: {}", id, reason_code);
                        }
                        Err(e) => {
                            debug!(log, "Couldn't receive API response: {}", e);
                        }
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
    api_request_tx: ApiRequestSender,
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
                let api_request_sender = api_request_tx.clone();
                let log = log.new(o!("addr" => addr));
                let conf = Arc::clone(&conf);
                tokio::spawn(async move {
                    if let Err(e) = socks5_process_socket(api_request_sender, stream, conf, log.clone()).await {
                        debug!(log, "SOCKS5 packet processing failed: {:?}", e);
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
    api_request_tx: ApiRequestSender,
    incoming: TcpStream,
    conf: Arc<Socks5AcceptorConfig>,
    log: Logger,
) -> anyhow::Result<()> {
    use jetsocat_proxy::{Socks5Acceptor, Socks5FailureCode};

    let acceptor = Socks5Acceptor::accept_with_config(incoming, &conf).await?;

    if acceptor.is_connect_command() {
        let destination_url = match acceptor.dest_addr() {
            jetsocat_proxy::DestAddr::Ip(addr) => {
                let host = addr.ip().to_string();
                let port = addr.port();
                DestinationUrl::new("tcp", &host, port)
            }
            jetsocat_proxy::DestAddr::Domain(domain, port) => DestinationUrl::new("tcp", domain, *port),
        };

        debug!(log, "Request {}", destination_url);

        let (sender, receiver) = oneshot::channel();

        match api_request_tx
            .send(JmuxApiRequest::OpenChannel {
                destination_url,
                api_response_tx: sender,
            })
            .await
        {
            Ok(()) => {}
            Err(e) => {
                warn!(log, "Couldn’t send JMUX API request: {}", e);
                anyhow::bail!("Couldn't send JMUX request");
            }
        }

        let id = match receiver.await.context("negotiation interrupted")? {
            JmuxApiResponse::Success { id } => id,
            JmuxApiResponse::Failure { id, reason_code } => {
                anyhow::bail!("Channel {} failure: {}", id, reason_code);
            }
        };

        // Dummy local address required for SOCKS5 response (JMUX protocol doesn't include this information).
        // It appears to not be an issue in general: it's used to act as if the SOCKS5 client opened a
        // socket stream as usual with a local bound address [provided by TcpStream::local_addr],
        // but I'm not aware of many application relying on this. If this become an issue we may
        // consider updating the JMUX protocol to bubble up that information.
        let dummy_local_addr = "0.0.0.0:0";
        let stream = acceptor.connected(dummy_local_addr).await?;

        let _ = api_request_tx.send(JmuxApiRequest::Start { id, stream }).await;
    } else {
        acceptor.failed(Socks5FailureCode::CommandNotSupported).await?;
    }

    Ok(())
}
