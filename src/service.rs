use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::Arc,
};

use futures::stream::StreamExt;
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::Mutex,
};
use tokio_compat_02::FutureExt as _;

use tokio_compat_02::IoCompat;
use tokio_rustls::{rustls, TlsAcceptor, TlsStream};

use hyper::service::service_fn;
use url::Url;

use slog::{o, Logger};
use slog_scope::{error, info, slog_error, warn};
use slog_scope_futures::future03::FutureExt;

use crate::{
    config::Config,
    http::http_server::HttpServer,
    jet_client::{JetAssociationsMap, JetClient},
    logger,
    rdp::RdpClient,
    routing_client::Client,
    transport::{tcp::TcpTransport, ws::WsTransport, JetTransport},
    utils::{
        get_default_port_from_server_url, get_pub_key_from_der, load_certs, load_private_key, AsyncReadWrite, Incoming,
    },
    websocket_client::{WebsocketService, WsClient},
};

type VecOfFuturesType = Vec<Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>>;

#[allow(clippy::large_enum_variant)] // `Running` variant is bigger than `Stopped` but we don't care
pub enum GatewayState {
    Stopped,
    Running { http_server: HttpServer, runtime: Runtime },
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

        // start http server
        context.http_server.start();

        let join_all = futures::future::join_all(context.futures);
        runtime.spawn(async {
            join_all.await.into_iter().for_each(|future_result| {
                let _ = future_result.map_err(|err| error!("{}", format!("Listeners failed: {}", err)));
            });
        });

        self.state = GatewayState::Running {
            http_server: context.http_server,
            runtime,
        };
    }

    pub fn stop(&mut self) {
        match std::mem::take(&mut self.state) {
            GatewayState::Stopped => {
                info!("Attempted to stop gateway service, but it isn't started");
            }
            GatewayState::Running { http_server, runtime } => {
                info!("Stopping gateway service");

                // stop http server
                http_server.stop();

                // stop runtime now
                runtime.shutdown_background();

                self.state = GatewayState::Stopped;
            }
        }
    }
}

pub struct GatewayContext {
    pub http_server: HttpServer,
    pub futures: VecOfFuturesType,
}

pub fn create_context(config: Arc<Config>, logger: slog::Logger) -> Result<GatewayContext, &'static str> {
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

    let http_server = HttpServer::new(config.clone(), jet_associations.clone());

    // Create the TLS acceptor.
    let client_no_auth = rustls::NoClientAuth::new();
    let mut server_config = rustls::ServerConfig::new(client_no_auth);
    let certs = load_certs(&config.certificate).map_err(|_| "could not load certs")?;
    let tls_public_key = get_pub_key_from_der(&certs[0].0).map_err(|_| "could not parse TLS public key")?;
    let priv_key = load_private_key(&config.certificate).map_err(|_| "could not load private key")?;
    server_config
        .set_single_cert(certs, priv_key)
        .map_err(|_| "couldn't set server config cert")?;

    let config_ref = Arc::new(server_config);
    let tls_acceptor = TlsAcceptor::from(config_ref);

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

    Ok(GatewayContext { http_server, futures })
}

/*
const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;
*/

fn set_socket_option(stream: &TcpStream, logger: &Logger) {
    if let Err(e) = stream.set_nodelay(true) {
        slog_error!(logger, "set_nodelay on TcpStream failed: {}", e);
    }
    // FIXME: The following methods are temporarily not available in tokio 0.3.3.
    // Tokio issue: (https://github.com/tokio-rs/tokio/issues/3082)
    // When they will be implemented in the newer tokio version,
    // the next lines should be uncommented.
    /*
    if let Err(e) = stream.set_keepalive(Some(Duration::from_secs(2))) {
        slog_error!(logger, "set_keepalive on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_send_buffer_size(SOCKET_SEND_BUFFER_SIZE) {
        slog_error!(logger, "set_send_buffer_size on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_recv_buffer_size(SOCKET_RECV_BUFFER_SIZE) {
        slog_error!(logger, "set_recv_buffer_size on TcpStream failed: {}", e);
    }
    */
}

async fn start_tcp_server(
    url: Url,
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    tls_acceptor: TlsAcceptor,
    tls_public_key: Vec<u8>,
    logger: Logger,
) -> Result<(), String> {
    info!("Starting TCP jet server...");

    let socket_addr = url
        .with_default_port(|url| get_default_port_from_server_url(url).map_err(|_| ()))
        .expect("invalid URL")
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let listener = TcpListener::bind(&socket_addr).await.unwrap();
    let mut incoming = Incoming {
        listener: &listener,
        accept: None,
    };
    while let Some(Ok(conn)) = incoming.next().await {
        // Configure logger
        let mut logger = logger.clone();
        if let Ok(peer_addr) = conn.peer_addr() {
            logger = logger.new(o!("client" => peer_addr.to_string()));
        }
        if let Ok(local_addr) = conn.local_addr() {
            logger = logger.new(o!("listener" => local_addr.to_string()));
        }
        if let Some(url) = &config.routing_url {
            logger = logger.new(o!("scheme" => url.scheme().to_string()));
        }

        set_socket_option(&conn, &logger);

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
                        RdpClient::new(config.clone(), tls_public_key.clone(), tls_acceptor.clone()).serve(conn),
                    ),
                    scheme => panic!("Unsupported routing URL scheme {}", scheme),
                }
            } else if config.is_rdp_supported() {
                let mut peeked = [0; 4];
                let _ = conn.peek(&mut peeked).await;

                if peeked == [74, 69, 84, 0] {
                    // four first bytes matching JET protocol
                    let jet_client = JetClient::new(config.clone(), jet_associations.clone());
                    Box::pin(jet_client.serve(JetTransport::new_tcp(conn)))
                } else {
                    let rdp_client = RdpClient::new(config.clone(), tls_public_key.clone(), tls_acceptor.clone());
                    Box::pin(rdp_client.serve(conn))
                }
            } else {
                let jet_client = JetClient::new(config.clone(), jet_associations.clone());
                Box::pin(jet_client.serve(JetTransport::new_tcp(conn)))
            };

        let client_fut = client_fut.with_logger(logger);
        tokio::spawn(async move {
            match client_fut.await {
                Ok(_) => {}
                Err(e) => error!("Error with client: {}", e),
            }
        });
    }

    info!("TCP jet server started successfully. Now listening on {}", socket_addr);

    Ok(())
}

async fn start_websocket_server(
    websocket_url: Url,
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    tls_acceptor: TlsAcceptor,
    logger: slog::Logger,
) -> Result<(), String> {
    info!("Starting websocket server ...");

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

    let websocket_listener = TcpListener::bind(websocket_addr)
        .await
        .map_err(|err| format!("{}", err))?;

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
        |connection: ConnectionType, remote_addr: Option<SocketAddr>, websocket_service: WebsocketService| {
            let http = hyper::server::conn::Http::new();
            let listener_logger = listener_logger.clone();

            let service = service_fn(move |req| {
                let mut ws_serve = websocket_service.clone();
                async move { ws_serve.handle(req, remote_addr).await }
            });

            tokio::spawn(async move {
                let conn = IoCompat::new(connection);
                let serve_connection = http.serve_connection(conn, service).with_upgrades();
                // use .compat to run 0.2 hyper on tokio 0.3 runtime
                let _ = serve_connection
                    .with_logger(listener_logger)
                    .compat()
                    .await
                    .map_err(|_| ());
            });
        };

    let mut incoming = Incoming {
        listener: &websocket_listener,
        accept: None,
    };

    match websocket_url.scheme() {
        "ws" => {
            while let Some(tcp) = incoming.next().await {
                match tcp {
                    Ok(tcp) => {
                        set_socket_option(&tcp, &logger);

                        let remote_addr = tcp.peer_addr().ok();
                        let conn = Box::new(tcp) as ConnectionType;

                        connection_process(conn, remote_addr, websocket_service.clone());
                    }
                    Err(err) => warn!(
                        "{}",
                        format!("WebSocket listener failed to accept connection - {:?}", err)
                    ),
                }
            }
        }
        "wss" => {
            while let Some(tcp) = incoming.next().await {
                match tcp {
                    Ok(tcp) => {
                        set_socket_option(&tcp, &logger);

                        match tls_acceptor.accept(tcp).await {
                            Ok(tls) => {
                                let remote_addr = tls.get_ref().0.peer_addr().ok();
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
            }
        }
        scheme => panic!("Not a websocket scheme {}", scheme),
    };

    info!("WebSocket server started successfully. Listening on {}", websocket_addr);
    Ok(())
}
