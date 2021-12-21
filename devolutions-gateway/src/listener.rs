use crate::config::Config;
use crate::generic_client::GenericClient;
use crate::jet_client::{JetAssociationsMap, JetClient};
use crate::rdp::RdpClient;
use crate::routing_client;
use crate::transport::tcp::TcpTransport;
use crate::transport::ws::WsTransport;
use crate::transport::JetTransport;
use crate::utils::url_to_socket_addr;
use crate::websocket_client::{WebsocketService, WsClient};
use anyhow::Context;
use hyper::service::service_fn;
use slog::Logger;
use slog_scope_futures::future03::FutureExt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_rustls::TlsStream;
use url::Url;

pub struct GatewayListener {
    url: Url,
    listener: TcpListener,
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    logger: Logger,
}

impl GatewayListener {
    pub fn init_and_bind(
        url: Url,
        config: Arc<Config>,
        jet_associations: JetAssociationsMap,
        logger: Logger,
    ) -> anyhow::Result<Self> {
        info!("Initiating listener {}…", url);

        let socket_addr = url_to_socket_addr(&url).context("invalid url")?;

        let socket = TcpSocket::new_v4().context("failed to create TCP socket")?;
        socket.bind(socket_addr).context("failed to bind TCP socket")?;
        set_socket_options(&socket, &logger);
        let listener = socket
            .listen(64)
            .context("failed to listen with the binded TCP socket")?;

        info!("TCP listener on {} started successfully", socket_addr);

        let logger = logger.new(slog::o!("listener" => url.to_string()));

        Ok(Self {
            url,
            listener,
            config,
            jet_associations,
            logger,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        macro_rules! handle {
            ($handler:ident) => {{
                match self.listener.accept().await.context("failed to accept connection") {
                    Ok((stream, peer_addr)) => {
                        let config = self.config.clone();
                        let jet_associations = self.jet_associations.clone();
                        let logger = self.logger.new(slog::o!("client" => peer_addr.to_string()));

                        tokio::spawn(async move {
                            if let Err(e) = $handler(config, jet_associations, stream, peer_addr, logger.clone()).await {
                                slog_error!(logger, concat!(stringify!($handler), " failure: {:#}"), e);
                            }
                        });
                    }
                    Err(e) => slog_warn!(self.logger, "listener failure: {:#}", e),
                }
            }}
        }

        match self.url.scheme() {
            "tcp" => loop {
                handle!(handle_tcp_client)
            },
            "ws" => loop {
                handle!(handle_ws_client)
            },
            "wss" => loop {
                handle!(handle_wss_client)
            },
            unsupported => anyhow::bail!("unsupported listener scheme: {}", unsupported),
        }
    }

    pub async fn handle_one(&self) -> anyhow::Result<()> {
        let (conn, peer_addr) = self.listener.accept().await.context("failed to accept connection")?;

        let config = self.config.clone();
        let jet_associations = self.jet_associations.clone();
        let logger = self.logger.new(slog::o!("client" => peer_addr.to_string()));

        match self.url.scheme() {
            "tcp" => handle_tcp_client(config, jet_associations, conn, peer_addr, logger).await?,
            "ws" => handle_ws_client(config, jet_associations, conn, peer_addr, logger).await?,
            "wss" => handle_wss_client(config, jet_associations, conn, peer_addr, logger).await?,
            unsupported => anyhow::bail!("unsupported listener scheme: {}", unsupported),
        }

        Ok(())
    }
}

async fn handle_tcp_client(
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    stream: TcpStream,
    peer_addr: SocketAddr,
    logger: Logger,
) -> anyhow::Result<()> {
    set_stream_option(&stream, &logger);

    if let Some(routing_url) = &config.routing_url {
        // TODO: should we keep support for this "routing URL" option? (it's not really used in
        // real world usecases)
        match routing_url.scheme() {
            "tcp" => {
                let transport = TcpTransport::new(stream);

                routing_client::Client::new(routing_url.clone(), config)
                    .serve(transport)
                    .with_logger(logger)
                    .await?;
            }
            "tls" => {
                let tls_stream = config
                    .tls
                    .as_ref()
                    .unwrap()
                    .acceptor
                    .accept(stream)
                    .await
                    .context("TlsAcceptor handshake failed")?;
                let transport = TcpTransport::new_tls(TlsStream::Server(tls_stream));

                routing_client::Client::new(routing_url.clone(), config)
                    .serve(transport)
                    .with_logger(logger)
                    .await?;
            }
            "ws" => {
                let stream = tokio_tungstenite::accept_async(stream)
                    .await
                    .context("WebSocket handshake failed")?;
                let transport = WsTransport::new_tcp(stream, Some(peer_addr));

                WsClient::new(routing_url.clone(), config)
                    .serve(transport)
                    .with_logger(logger)
                    .await?;
            }
            "wss" => {
                let tls_stream = config
                    .tls
                    .as_ref()
                    .unwrap()
                    .acceptor
                    .accept(stream)
                    .await
                    .context("TLS handshake failed")?;
                let stream = tokio_tungstenite::accept_async(TlsStream::Server(tls_stream))
                    .await
                    .context("WebSocket handshake failed")?;
                let transport = WsTransport::new_tls(stream, Some(peer_addr));

                WsClient::new(routing_url.clone(), config)
                    .serve(transport)
                    .with_logger(logger)
                    .await?;
            }
            "rdp" => {
                RdpClient {
                    config,
                    jet_associations,
                }
                .serve(stream)
                .with_logger(logger)
                .await?;
            }
            scheme => anyhow::bail!("Unsupported routing URL scheme {}", scheme),
        }
    } else {
        let mut peeked = [0; 4];
        let n_read = stream
            .peek(&mut peeked)
            .await
            .context("couldn't peek four first bytes")?;

        // Check if first four bytes contains some protocol magic bytes
        match &peeked[..n_read] {
            [b'J', b'E', b'T', b'\0'] => {
                JetClient {
                    config,
                    jet_associations,
                }
                .serve(JetTransport::new_tcp(stream))
                .with_logger(logger)
                .await?;
            }
            [b'J', b'M', b'U', b'X'] => anyhow::bail!("JMUX TCP listener not yet implemented"),
            _ => {
                GenericClient {
                    config,
                    jet_associations,
                }
                .serve(stream)
                .with_logger(logger)
                .await?;
            }
        }
    };

    Ok(())
}

async fn handle_ws_client(
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    conn: TcpStream,
    peer_addr: SocketAddr,
    logger: Logger,
) -> anyhow::Result<()> {
    set_stream_option(&conn, &logger);
    process_ws_stream(conn, peer_addr, config, jet_associations, logger).await?;
    Ok(())
}

async fn handle_wss_client(
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    stream: TcpStream,
    peer_addr: SocketAddr,
    logger: Logger,
) -> anyhow::Result<()> {
    set_stream_option(&stream, &logger);

    let tls_conf = config.tls.as_ref().context("TLS configuration is missing")?;
    let tls_stream = tls_conf.acceptor.accept(stream).await.context("TLS handshake failed")?;

    process_ws_stream(tls_stream, peer_addr, config, jet_associations, logger).await?;

    Ok(())
}

async fn process_ws_stream<I>(
    io: I,
    remote_addr: SocketAddr,
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    logger: Logger,
) -> anyhow::Result<()>
where
    I: AsyncWrite + AsyncRead + Unpin + Send + Sync + 'static,
{
    let websocket_service = WebsocketService {
        jet_associations,
        config,
    };

    let service = service_fn(move |req| {
        let mut ws_serve = websocket_service.clone();
        async move {
            ws_serve.handle(req, remote_addr).await.map_err(|e| {
                debug!("WebSocket HTTP server error: {}", e);
                e
            })
        }
    });

    let http = hyper::server::conn::Http::new();

    http.serve_connection(io, service)
        .with_upgrades()
        .with_logger(logger)
        .await?;

    Ok(())
}

fn set_socket_options(socket: &TcpSocket, logger: &Logger) {
    const SOCKET_SEND_BUFFER_SIZE: u32 = 0x7FFFF;
    const SOCKET_RECV_BUFFER_SIZE: u32 = 0x7FFFF;

    // FIXME: temporarily not available in tokio 1.5 (https://github.com/tokio-rs/tokio/issues/3082)
    // if let Err(e) = socket.set_keepalive(Some(Duration::from_secs(2))) {
    //     slog_error!(logger, "set_keepalive on TcpStream failed: {}", e);
    // }

    if let Err(e) = socket.set_send_buffer_size(SOCKET_SEND_BUFFER_SIZE) {
        slog_error!(logger, "set_send_buffer_size on TcpStream failed: {}", e);
    }

    if let Err(e) = socket.set_recv_buffer_size(SOCKET_RECV_BUFFER_SIZE) {
        slog_error!(logger, "set_recv_buffer_size on TcpStream failed: {}", e);
    }
}

fn set_stream_option(stream: &TcpStream, logger: &Logger) {
    if let Err(e) = stream.set_nodelay(true) {
        slog_error!(logger, "set_nodelay on TcpStream failed: {}", e);
    }
}
