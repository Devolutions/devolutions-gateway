use anyhow::Context;
use jmux_proxy::{ApiRequestSender, DestinationUrl, JmuxApiRequest, JmuxApiResponse};
use proxy_http::HttpProxyAcceptor;
use proxy_socks::Socks5AcceptorConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, oneshot};
use tracing::Instrument as _;

#[derive(Debug, Clone)]
pub enum ListenerMode {
    Tcp { bind_addr: String, destination_url: String },
    Http { bind_addr: String },
    Socks5 { bind_addr: String },
}

#[instrument(skip(api_request_tx))]
pub async fn tcp_listener_task(api_request_tx: ApiRequestSender, bind_addr: String, destination_url: String) {
    let destination_url = format!("tcp://{destination_url}");

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

    let local_addr = incoming.local_addr().context("couldn't get local address")?;
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
                warn!(%error, "Couldn't send JMUX API request");
                anyhow::bail!("couldn't send JMUX request");
            }
        }

        let id = match receiver.await.context("negotiation interrupted")? {
            JmuxApiResponse::Success { id } => id,
            JmuxApiResponse::Failure { id, reason_code } => {
                let _ = acceptor.failed(jmux_to_socks_error(reason_code)).await;
                anyhow::bail!("channel {} failure: {}", id, reason_code);
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
    } else if acceptor.is_udp_associate_command() {
        // Handle UDP Associate command.

        // Start UDP relay server.
        let udp_relay_addr = start_udp_relay(api_request_tx.clone(), local_addr).await?;

        debug!(%udp_relay_addr, "Started UDP relay server");

        // Send UDP Associate success response.
        let mut tcp_stream = acceptor.udp_associated(udp_relay_addr).await?;

        // Keep the TCP connection alive for the UDP association.
        // The UDP association is valid as long as the TCP connection remains open.
        // In a real implementation, we might want to handle this differently.
        debug!("UDP association established, keeping TCP connection alive");

        // Keep connection alive by reading until it closes.
        let mut buffer = [0u8; 1];
        loop {
            match AsyncReadExt::read(&mut tcp_stream, &mut buffer).await {
                Ok(0) => {
                    debug!("TCP connection closed, UDP association terminated");
                    break;
                }
                Ok(_) => {
                    // Ignore any data received on the TCP connection.
                    continue;
                }
                Err(_) => {
                    debug!("TCP connection error, UDP association terminated");
                    break;
                }
            }
        }
    } else {
        acceptor.failed(Socks5FailureCode::CommandNotSupported).await?;
    }

    Ok(())
}

fn jmux_to_socks_error(code: jmux_proto::ReasonCode) -> proxy_socks::Socks5FailureCode {
    use jmux_proto::ReasonCode;
    use proxy_socks::Socks5FailureCode;

    match code {
        ReasonCode::GENERAL_FAILURE => Socks5FailureCode::GeneralSocksServerFailure,
        ReasonCode::CONNECTION_NOT_ALLOWED_BY_RULESET => Socks5FailureCode::ConnectionNotAllowedByRuleset,
        ReasonCode::NETWORK_UNREACHABLE => Socks5FailureCode::NetworkUnreachable,
        ReasonCode::HOST_UNREACHABLE => Socks5FailureCode::HostUnreachable,
        ReasonCode::CONNECTION_REFUSED => Socks5FailureCode::ConnectionRefused,
        ReasonCode::TTL_EXPIRED => Socks5FailureCode::TtlExpired,
        ReasonCode::ADDRESS_TYPE_NOT_SUPPORTED => Socks5FailureCode::AddressTypeNotSupported,
        _ => Socks5FailureCode::GeneralSocksServerFailure,
    }
}

#[instrument(skip(api_request_tx))]
pub async fn http_listener_task(api_request_tx: ApiRequestSender, bind_addr: String) {
    let processor = |stream, addr| {
        let api_request_tx = api_request_tx.clone();
        tokio::spawn(
            async move {
                if let Err(error) = http_process_socket(api_request_tx, stream).await {
                    debug!("HTTP(S) proxy packet processing failed: {:#}", error);
                }
            }
            .instrument(info_span!("process", %addr)),
        );
    };

    if let Err(e) = listener_task_impl(processor, bind_addr).await {
        error!("Task failed: {:#}", e);
    }
}

async fn http_process_socket(api_request_tx: ApiRequestSender, incoming: TcpStream) -> anyhow::Result<()> {
    let acceptor = HttpProxyAcceptor::accept(incoming).await?;

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
            let _ = acceptor.failure(proxy_http::ErrorCode::InternalServerError).await;
            anyhow::bail!("couldn't send JMUX request");
        }
    }

    let id = match receiver.await.context("negotiation interrupted")? {
        JmuxApiResponse::Success { id } => id,
        JmuxApiResponse::Failure { id, reason_code } => {
            let _ = acceptor.failure(jmux_to_http_error_code(reason_code)).await;
            anyhow::bail!("channel {} failure: {}", id, reason_code);
        }
    };

    let incoming_stream = match acceptor {
        HttpProxyAcceptor::RegularRequest(regular_request) => regular_request.success_with_rewrite()?,
        HttpProxyAcceptor::TunnelRequest(tunnel_request) => tunnel_request.success().await?,
    };

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

fn jmux_to_http_error_code(code: jmux_proto::ReasonCode) -> proxy_http::ErrorCode {
    use jmux_proto::ReasonCode;
    use proxy_http::ErrorCode;

    match code {
        ReasonCode::GENERAL_FAILURE => ErrorCode::InternalServerError,
        ReasonCode::CONNECTION_NOT_ALLOWED_BY_RULESET => ErrorCode::Forbidden,
        ReasonCode::NETWORK_UNREACHABLE => ErrorCode::BadGateway,
        ReasonCode::HOST_UNREACHABLE => ErrorCode::BadGateway,
        ReasonCode::CONNECTION_REFUSED => ErrorCode::BadGateway,
        ReasonCode::TTL_EXPIRED => ErrorCode::RequestTimeout,
        ReasonCode::ADDRESS_TYPE_NOT_SUPPORTED => ErrorCode::BadRequest,
        _ => ErrorCode::InternalServerError,
    }
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
        .with_context(|| format!("couldn’t bind listener to {bind_addr}"))?;

    info!("Start listener");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => processor(stream, addr),
            Err(error) => {
                error!(%error, "Couldn't accept next TCP stream");
                break;
            }
        }
    }

    Ok(())
}

/// Starts a UDP relay server for SOCKS5 UDP Associate functionality.
///
/// Returns the address where the UDP relay is listening.
/// Clients will send SOCKS5-formatted UDP datagrams to this address.
async fn start_udp_relay(api_request_tx: ApiRequestSender, _tcp_addr: SocketAddr) -> anyhow::Result<SocketAddr> {
    // Bind UDP socket on any available port for relay functionality.
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let relay_addr = udp_socket.local_addr()?;

    let udp_socket = Arc::new(udp_socket);
    // Track active JMUX channels per client address.
    let active_channels: Arc<Mutex<HashMap<SocketAddr, (u32, SocketAddr)>>> = Arc::new(Mutex::new(HashMap::new()));

    // Spawn background task to handle incoming UDP datagrams.
    let udp_socket_clone = Arc::clone(&udp_socket);
    let active_channels_clone = Arc::clone(&active_channels);
    let api_request_tx_clone = api_request_tx.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 65535]; // Maximum UDP packet size.

        loop {
            match udp_socket_clone.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let data = &buf[..len];

                    // Parse SOCKS5 UDP datagram.
                    match proxy_socks::UdpDatagram::from_bytes(data) {
                        Ok(datagram) => {
                            debug!("Received UDP datagram from {} to {:?}", client_addr, datagram.dest_addr);

                            // Handle each UDP packet in a separate task.
                            let api_request_tx = api_request_tx_clone.clone();
                            let active_channels = Arc::clone(&active_channels_clone);
                            let udp_socket = Arc::clone(&udp_socket_clone);

                            tokio::spawn(async move {
                                if let Err(e) = handle_udp_packet(
                                    api_request_tx,
                                    active_channels,
                                    udp_socket,
                                    client_addr,
                                    datagram,
                                )
                                .await
                                {
                                    debug!("Failed to handle UDP packet: {e:#}");
                                }
                            });
                        }
                        Err(e) => {
                            debug!("Failed to parse UDP datagram: {e}");
                        }
                    }
                }
                Err(e) => {
                    warn!("UDP socket error: {e}");
                    break;
                }
            }
        }
    });

    Ok(relay_addr)
}

/// Handles a single UDP packet received from a SOCKS5 client.
///
/// This function manages JMUX channel creation and forwards the UDP data.
/// Currently implements a simplified UDP-to-TCP bridge for proof of concept.
async fn handle_udp_packet(
    api_request_tx: ApiRequestSender,
    active_channels: Arc<Mutex<HashMap<SocketAddr, (u32, SocketAddr)>>>,
    _udp_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    datagram: proxy_socks::UdpDatagram,
) -> anyhow::Result<()> {
    let destination_url = dest_addr_to_url(&datagram.dest_addr);

    // Check if we already have an active JMUX channel for this client.
    let channels = active_channels.lock().await;
    let channel_info = channels.get(&client_addr).copied();
    drop(channels);

    let _channel_id = if let Some((id, _)) = channel_info {
        id
    } else {
        // Create new JMUX channel for this destination.
        let (sender, receiver) = oneshot::channel();

        match api_request_tx
            .send(JmuxApiRequest::OpenChannel {
                destination_url: destination_url.clone(),
                api_response_tx: sender,
            })
            .await
        {
            Ok(()) => {}
            Err(error) => {
                warn!(%error, "Couldn't send JMUX API request");
                anyhow::bail!("couldn't send JMUX request");
            }
        }

        match receiver.await.context("negotiation interrupted")? {
            JmuxApiResponse::Success { id } => {
                // Store channel mapping for this client.
                let dest_socket_addr = match &datagram.dest_addr {
                    proxy_types::DestAddr::Ip(addr) => *addr,
                    proxy_types::DestAddr::Domain(_domain, port) => {
                        // FIXME: Domain resolution not implemented in this PoC.
                        SocketAddr::from(([0, 0, 0, 0], *port))
                    }
                };

                let mut channels = active_channels.lock().await;
                channels.insert(client_addr, (id.into(), dest_socket_addr));
                drop(channels);

                // FIXME: This is a simplified implementation for proof of concept.
                // A complete implementation would need bidirectional UDP<->TCP bridging.
                debug!("Channel {} opened for UDP packet relay", id);

                id.into()
            }
            JmuxApiResponse::Failure { id, reason_code } => {
                anyhow::bail!("channel {} failure: {}", id, reason_code);
            }
        }
    };

    Ok(())
}

// Note: This is a simplified UDP relay implementation.
// A full implementation would require establishing a proper TCP connection through JMUX
// and implementing bidirectional UDP<->TCP packet translation.
// For now, this serves as a basic proof of concept for UDP Associate support.
