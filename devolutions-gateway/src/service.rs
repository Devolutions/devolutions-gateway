use crate::config::Config;
use crate::generic_client::GenericClient;
use crate::http::http_server::configure_http_server;
use crate::jet_client::{JetAssociationsMap, JetClient};
use crate::logger;
use crate::rdp::RdpClient;
use crate::routing_client::Client;
use crate::transport::tcp::TcpTransport;
use crate::transport::ws::WsTransport;
use crate::transport::JetTransport;
use crate::utils::{get_pub_key_from_der, load_cert, load_private_key, url_to_socket_addr, AsyncReadWrite};
use crate::websocket_client::{WebsocketService, WsClient};
use hyper::service::service_fn;
use slog::{o, Logger};
use slog_scope::{error, info, slog_error, warn};
use slog_scope_futures::future03::FutureExt;
use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio_rustls::{rustls, TlsAcceptor, TlsStream};
use url::Url;

type VecOfFuturesType = Vec<Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>>;

#[allow(clippy::large_enum_variant)] // `Running` variant is bigger than `Stopped` but we don't care
pub enum GatewayState {
    Stopped,
    Running { runtime: Runtime },
}

impl Default for GatewayState {
    fn default() -> Self {
        Self::Stopped
    }
}

pub struct GatewayService {
    config: Arc<Config>,
    logger: Logger,
    state: GatewayState,
    _logger_guard: slog_scope::GlobalLoggerGuard,
}

impl GatewayService {
    pub fn load() -> Option<Self> {
        let config = Arc::new(Config::init());
        let logger = logger::init(config.log_file.as_deref()).expect("failed to setup logger");
        let logger_guard = slog_scope::set_global_logger(logger.clone());
        slog_stdlog::init().expect("failed to init logger");

        if let Err(e) = config.validate() {
            error!("Devolutions Gateway can't be launched. Invalid configuration: {}", e);
            return None;
        }

        Some(GatewayService {
            config,
            logger,
            state: GatewayState::Stopped,
            _logger_guard: logger_guard,
        })
    }

    pub fn get_service_name(&self) -> &str {
        self.config.service_name.as_str()
    }

    pub fn get_display_name(&self) -> &str {
        self.config.display_name.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.config.description.as_str()
    }

    pub fn start(&mut self) {
        let runtime = Runtime::new().expect("failed to create runtime");

        let config = self.config.clone();
        let logger = self.logger.clone();

        let context = create_context(config, logger).expect("failed to create gateway context");

        let join_all = futures::future::join_all(context.futures);
        runtime.spawn(async {
            join_all.await.into_iter().for_each(|future_result| {
                let _ = future_result.map_err(|err| error!("{}", format!("Listeners failed: {}", err)));
            });
        });

        self.state = GatewayState::Running { runtime };
    }

    pub fn stop(&mut self) {
        match std::mem::take(&mut self.state) {
            GatewayState::Stopped => {
                info!("Attempted to stop gateway service, but it isn't started");
            }
            GatewayState::Running { runtime } => {
                info!("Stopping gateway service");

                // stop runtime now
                runtime.shutdown_background();

                self.state = GatewayState::Stopped;
            }
        }
    }
}

pub struct GatewayContext {
    pub futures: VecOfFuturesType,
}

pub fn create_context(config: Arc<Config>, logger: slog::Logger) -> Result<GatewayContext, Cow<'static, str>> {
    let tcp_listeners: Vec<Url> = config
        .listeners
        .iter()
        .filter_map(|listener| {
            if listener.internal_url.scheme() == "tcp" {
                Some(listener.internal_url.clone())
            } else {
                None
            }
        })
        .collect();

    let websocket_listeners: Vec<Url> = config
        .listeners
        .iter()
        .filter_map(|listener| {
            if listener.internal_url.scheme() == "ws" || listener.internal_url.scheme() == "wss" {
                Some(listener.internal_url.clone())
            } else {
                None
            }
        })
        .collect();

    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));

    // configure http server
    configure_http_server(config.clone(), jet_associations.clone()).map_err(|e| {
        error!("{}", e);
        "failed to configure http server"
    })?;

    // Create the TLS acceptor.
    let cert = load_cert(&config.certificate).map_err(|e| format!("could not load cert: {}", e))?;
    let tls_public_key = get_pub_key_from_der(&cert.0).map_err(|e| format!("could not parse TLS public key: {}", e))?;
    let priv_key = load_private_key(&config.certificate).map_err(|e| format!("could not load private key: {}", e))?;

    let rustls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], priv_key)
        .map_err(|e| format!("couldn't set server config cert: {}", e))?;
    let rustls_config = Arc::new(rustls_config);

    let tls_acceptor = TlsAcceptor::from(rustls_config);

    let listeners_count = websocket_listeners.len() + tcp_listeners.len();
    let mut futures: VecOfFuturesType = Vec::with_capacity(listeners_count);

    for url in &websocket_listeners {
        futures.push(Box::pin(start_websocket_server(
            url.clone(),
            config.clone(),
            jet_associations.clone(),
            tls_acceptor.clone(),
            logger.clone(),
        )));
    }

    for url in &tcp_listeners {
        futures.push(Box::pin(start_tcp_server(
            url.clone(),
            config.clone(),
            jet_associations.clone(),
            tls_acceptor.clone(),
            tls_public_key.clone(),
            logger.clone(),
        )));
    }

    Ok(GatewayContext { futures })
}

fn set_socket_option(socket: &TcpSocket, logger: &Logger) {
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

async fn start_tcp_server(
    url: Url,
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    tls_acceptor: TlsAcceptor,
    tls_public_key: Vec<u8>,
    logger: Logger,
) -> Result<(), String> {
    use futures::FutureExt as _;

    info!("Starting TCP jet server ({})...", url);

    let socket_addr = url_to_socket_addr(&url).expect("invalid url");

    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(socket_addr).unwrap();
    set_socket_option(&socket, &logger);
    let listener = socket.listen(1024).unwrap();

    info!("TCP jet server started successfully. Now listening on {}", socket_addr);

    loop {
        match listener.accept().await {
            Ok((conn, peer_addr)) => {
                // Configure logger
                let mut logger = logger.new(o!("client" => peer_addr.to_string()));
                if let Ok(local_addr) = conn.local_addr() {
                    logger = logger.new(o!("listener" => local_addr.to_string()));
                }
                if let Some(url) = &config.routing_url {
                    logger = logger.new(o!("scheme" => url.scheme().to_string()));
                }

                set_stream_option(&conn, &logger);

                let client_fut: Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + 'static>> =
                    if let Some(routing_url) = &config.routing_url {
                        match routing_url.scheme() {
                            "tcp" => {
                                let transport = TcpTransport::new(conn);
                                Box::pin(Client::new(routing_url.clone(), config.clone()).serve(transport))
                            }
                            "tls" => {
                                let tls_stream = tls_acceptor
                                    .accept(conn)
                                    .await
                                    .map_err(|err| format!("TlsAcceptor handshake error - {:?}", err))?;
                                let transport = TcpTransport::new_tls(TlsStream::Server(tls_stream));
                                Box::pin(Client::new(routing_url.clone(), config.clone()).serve(transport))
                            }
                            "ws" => {
                                let peer_addr = conn.peer_addr().ok();

                                let stream = tokio_tungstenite::accept_async(conn)
                                    .await
                                    .map_err(|err| format!("Tokio-tungstenite handshake error - {:?}", err))?;

                                let transport = WsTransport::new_tcp(stream, peer_addr);
                                Box::pin(WsClient::new(routing_url.clone(), config.clone()).serve(transport))
                            }
                            "wss" => {
                                let tls_stream = tls_acceptor
                                    .accept(conn)
                                    .await
                                    .map_err(|err| format!("TlsAcceptor handshake error - {:?}", err))?;

                                let peer_addr = tls_stream.get_ref().0.peer_addr().ok();
                                let stream = tokio_tungstenite::accept_async(TlsStream::Server(tls_stream))
                                    .await
                                    .map_err(|err| format!("Tokio-tungstenite handshake error - {:?}", err))?;

                                let transport = WsTransport::new_tls(stream, peer_addr);
                                Box::pin(WsClient::new(routing_url.clone(), config.clone()).serve(transport))
                            }
                            "rdp" => Box::pin(
                                RdpClient {
                                    config: config.clone(),
                                    tls_public_key: tls_public_key.clone(),
                                    tls_acceptor: tls_acceptor.clone(),
                                    jet_associations: jet_associations.clone(),
                                }
                                .serve(conn),
                            ),
                            scheme => panic!("Unsupported routing URL scheme {}", scheme),
                        }
                    } else {
                        let tls_public_key = tls_public_key.clone();
                        let jet_associations = jet_associations.clone();
                        let config = config.clone();
                        let tls_acceptor = tls_acceptor.clone();

                        async {
                            let mut peeked = [0; 4];
                            let _ = conn.peek(&mut peeked).await;

                            // Check if first four bytes contains some protocol magic bytes
                            match peeked {
                                [b'J', b'E', b'T', b'\0'] => {
                                    JetClient {
                                        config,
                                        jet_associations,
                                    }
                                    .serve(JetTransport::new_tcp(conn), tls_acceptor)
                                    .await
                                }
                                [b'J', b'M', b'U', b'X'] => Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "JMUX TCP listener not yet implemented",
                                )),
                                _ => {
                                    GenericClient {
                                        config,
                                        tls_public_key,
                                        tls_acceptor,
                                        jet_associations,
                                    }
                                    .serve(conn)
                                    .await
                                }
                            }
                        }
                        .boxed()
                    };

                let client_fut = client_fut.with_logger(logger);

                tokio::spawn(async move {
                    match client_fut.await {
                        Ok(_) => {}
                        Err(e) => error!("Error with client: {}", e),
                    }
                });
            }
            Err(e) => warn!("{}", format!("Tcp listener failed to accept connection - {:?}", e)),
        }
    }
}

async fn start_websocket_server(
    websocket_url: Url,
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    tls_acceptor: TlsAcceptor,
    logger: slog::Logger,
) -> Result<(), String> {
    info!("Starting websocket server ({})...", websocket_url);

    let mut websocket_addr = String::new();
    websocket_addr.push_str(websocket_url.host_str().unwrap_or("0.0.0.0"));
    websocket_addr.push(':');
    websocket_addr.push_str(
        websocket_url
            .port()
            .map(|port| port.to_string())
            .unwrap_or_else(|| match websocket_url.scheme() {
                "wss" => "443".to_string(),
                "ws" => "80".to_string(),
                _ => "80".to_string(),
            })
            .as_str(),
    );

    let websocket_addr = websocket_addr
        .parse::<SocketAddr>()
        .expect("Websocket addr can't be parsed.");

    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(websocket_addr).unwrap();
    set_socket_option(&socket, &logger);
    let websocket_listener = socket.listen(1024).unwrap();

    let websocket_service = WebsocketService {
        jet_associations,
        config,
    };

    let mut listener_logger = logger.clone();
    if let Ok(local_addr) = websocket_listener.local_addr() {
        listener_logger = listener_logger.new(o!("listener" => local_addr.to_string()));
    }

    type ConnectionType = Box<dyn AsyncReadWrite + Unpin + Send + Sync + 'static>;

    let connection_process =
        |connection: ConnectionType, remote_addr: SocketAddr, websocket_service: WebsocketService| {
            let http = hyper::server::conn::Http::new();
            let listener_logger = listener_logger.clone();

            let service = service_fn(move |req| {
                let mut ws_serve = websocket_service.clone();
                async move {
                    {
                        ws_serve.handle(req, remote_addr).await.map_err(|e| {
                            debug!("WebSocket HTTP server error: {}", e);
                            e
                        })
                    }
                }
            });

            tokio::spawn(async move {
                let serve_connection = http.serve_connection(connection, service).with_upgrades();
                let _ = serve_connection.with_logger(listener_logger).await.map_err(|_| ());
            });
        };

    info!("WebSocket server started successfully. Listening on {}", websocket_addr);

    match websocket_url.scheme() {
        "ws" => loop {
            match websocket_listener.accept().await {
                Ok((tcp, remote_addr)) => {
                    set_stream_option(&tcp, &logger);
                    let conn = Box::new(tcp) as ConnectionType;
                    connection_process(conn, remote_addr, websocket_service.clone());
                }
                Err(err) => warn!(
                    "{}",
                    format!("WebSocket listener failed to accept connection - {:?}", err)
                ),
            }
        },
        "wss" => loop {
            match websocket_listener.accept().await {
                Ok((tcp, remote_addr)) => {
                    set_stream_option(&tcp, &logger);

                    match tls_acceptor.accept(tcp).await {
                        Ok(tls) => {
                            let conn = Box::new(tls) as ConnectionType;
                            connection_process(conn, remote_addr, websocket_service.clone());
                        }
                        Err(err) => warn!("{}", format!("TlsAcceptor failed to accept handshake - {:?}", err)),
                    }
                }
                Err(err) => warn!(
                    "{}",
                    format!("WebSocket listener failed to accept connection - {:?}", err)
                ),
            }
        },
        scheme => panic!("Not a websocket scheme {}", scheme),
    }
}
