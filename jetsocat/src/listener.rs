use anyhow::Context;
use jmux_proxy::{ApiRequestSender, DestinationUrl, JmuxApiRequest, JmuxApiResponse};
use proxy_https::HttpsProxyAcceptor;
use proxy_socks::Socks5AcceptorConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing::Instrument as _;

#[derive(Debug, Clone)]
pub enum ListenerMode {
    Tcp { bind_addr: String, destination_url: String },
    Https { bind_addr: String },
    Socks5 { bind_addr: String },
}

#[instrument(skip(api_request_tx))]
pub async fn tcp_listener_task(api_request_tx: ApiRequestSender, bind_addr: String, destination_url: String) {
    let destination_url = format!("tcp://{}", destination_url);

    let processor = |stream, addr| {
        let api_request_tx = api_request_tx.clone();
        let destination_url = destination_url.clone();

        tokio::spawn(
            async move {
                debug!("Got request");

                let destination_url = match DestinationUrl::parse_str(&destination_url) {
                    Ok(url) => url,
                    Err(error) => {
                        debug!(%error, "Bad request");
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
                    Err(error) => {
                        warn!(%error, "Couldn’t send JMUX API request");
                        return;
                    }
                }

                match receiver.await {
                    Ok(JmuxApiResponse::Success { id }) => {
                        let _ = api_request_tx
                            .send(JmuxApiRequest::Start {
                                id,
                                stream,
                                leftover: None,
                            })
                            .await;
                    }
                    Ok(JmuxApiResponse::Failure { id, reason_code }) => {
                        debug!(%id, %reason_code, "Channel failure");
                    }
                    Err(error) => {
                        debug!(%error, "Couldn't receive API response");
                    }
                }
            }
            .instrument(info_span!("process", %addr)),
        );
    };

    if let Err(e) = listener_task_impl(processor, bind_addr).await {
        error!("Task failed: {:#}", e);
    }
}

#[instrument(skip(api_request_tx))]
pub async fn socks5_listener_task(api_request_tx: ApiRequestSender, bind_addr: String) {
    let conf = Arc::new(Socks5AcceptorConfig {
        no_auth_required: true,
        users: None,
    });

    let processor = |stream, addr| {
        let api_request_tx = api_request_tx.clone();
        let conf = Arc::clone(&conf);
        tokio::spawn(
            async move {
                if let Err(e) = socks5_process_socket(api_request_tx, stream, conf).await {
                    debug!("SOCKS5 packet processing failed: {:#}", e);
                }
            }
            .instrument(info_span!("process", %addr)),
        );
    };

    if let Err(e) = listener_task_impl(processor, bind_addr).await {
        error!("Task failed: {:#}", e);
    }
}

async fn socks5_process_socket(
    api_request_tx: ApiRequestSender,
    incoming: TcpStream,
    conf: Arc<Socks5AcceptorConfig>,
) -> anyhow::Result<()> {
    use proxy_socks::{Socks5Acceptor, Socks5FailureCode};

    let acceptor = Socks5Acceptor::accept_with_config(incoming, &conf).await?;

    if acceptor.is_connect_command() {
        let destination_url = dest_addr_to_url(acceptor.dest_addr());

        debug!(%destination_url, "Got request");

        let (sender, receiver) = oneshot::channel();

        match api_request_tx
            .send(JmuxApiRequest::OpenChannel {
                destination_url,
                api_response_tx: sender,
            })
            .await
        {
            Ok(()) => {}
            Err(error) => {
                warn!(%error, "Couldn’t send JMUX API request");
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

        let _ = api_request_tx
            .send(JmuxApiRequest::Start {
                id,
                stream,
                leftover: None,
            })
            .await;
    } else {
        acceptor.failed(Socks5FailureCode::CommandNotSupported).await?;
    }

    Ok(())
}

#[instrument(skip(api_request_tx))]
pub async fn https_listener_task(api_request_tx: ApiRequestSender, bind_addr: String) {
    let processor = |stream, addr| {
        let api_request_tx = api_request_tx.clone();
        tokio::spawn(
            async move {
                if let Err(error) = https_process_socket(api_request_tx, stream).await {
                    debug!("HTTPS proxy packet processing failed: {:#}", error);
                }
            }
            .instrument(info_span!("process", %addr)),
        );
    };

    if let Err(e) = listener_task_impl(processor, bind_addr).await {
        error!("Task failed: {:#}", e);
    }
}

async fn https_process_socket(api_request_tx: ApiRequestSender, incoming: TcpStream) -> anyhow::Result<()> {
    let acceptor = HttpsProxyAcceptor::accept(incoming).await?;

    let destination_url = dest_addr_to_url(acceptor.dest_addr());

    debug!(%destination_url, "Got request");

    let (sender, receiver) = oneshot::channel();

    match api_request_tx
        .send(JmuxApiRequest::OpenChannel {
            destination_url,
            api_response_tx: sender,
        })
        .await
    {
        Ok(()) => {}
        Err(error) => {
            warn!(%error, "Couldn’t send JMUX API request");
            let _ = acceptor.respond(500).await;
            anyhow::bail!("Couldn't send JMUX request");
        }
    }

    let id = match receiver.await.context("negotiation interrupted")? {
        JmuxApiResponse::Success { id } => id,
        JmuxApiResponse::Failure { id, reason_code } => {
            let _ = acceptor.respond(500).await;
            anyhow::bail!("Channel {} failure: {}", id, reason_code);
        }
    };

    // send success response
    let incoming_stream = acceptor.respond(200).await?;

    let (stream, leftover) = incoming_stream.into_parts();

    let _ = api_request_tx
        .send(JmuxApiRequest::Start {
            id,
            stream,
            leftover: Some(leftover),
        })
        .await;

    Ok(())
}

fn dest_addr_to_url(dest_addr: &proxy_types::DestAddr) -> DestinationUrl {
    match dest_addr {
        proxy_types::DestAddr::Ip(addr) => {
            let host = addr.ip().to_string();
            let port = addr.port();
            DestinationUrl::new("tcp", &host, port)
        }
        proxy_types::DestAddr::Domain(domain, port) => DestinationUrl::new("tcp", domain, *port),
    }
}

async fn listener_task_impl<F>(mut processor: F, bind_addr: String) -> anyhow::Result<()>
where
    F: FnMut(TcpStream, SocketAddr),
{
    use anyhow::Context as _;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Couldn’t bind listener to {}", bind_addr))?;

    info!(%bind_addr, "Start listener");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => processor(stream, addr),
            Err(error) => {
                error!(%error, "Couldn’t accept next TCP stream");
                break;
            }
        }
    }

    Ok(())
}
