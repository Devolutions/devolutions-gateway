use devolutions_jet::{
    config::Config,
    http::http_server::HttpServer,
    jet_client::{JetAssociationsMap, JetClient},
    logger,
    rdp::RdpClient,
    routing_client::Client,
    transport::{
        tcp::TcpTransport,
        ws::{TcpWebSocketServerHandshake, TlsWebSocketServerHandshake, WsTransport},
        JetTransport,
    },
    utils::{get_pub_key_from_der, load_certs, load_private_key},
    websocket_client::{WebsocketService, WsClient},
};
use futures::{
    future,
    future::{ok, Either},
    Future, Stream,
};
use hyper::service::service_fn;
use saphir::server::HttpService;
use slog::{o, Logger};
use slog_scope::{error, info, slog_error, warn};
use slog_scope_futures::future01::FutureExt;
use std::{
    collections::HashMap,
    io,
    io::ErrorKind,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::tcp::{TcpListener, TcpStream},
    prelude::{AsyncRead, AsyncWrite},
    runtime::{Runtime, TaskExecutor},
    sync::oneshot,
};
use tokio_rustls::{TlsAcceptor, TlsStream};
use url::Url;

pub struct StopAllTasksEvent;

#[allow(clippy::large_enum_variant)] // `Running` variant is bigger than `Stopped` but we don't care
pub enum GatewayState {
    Stopped,
    Running {
        http_server: HttpServer,
        runtime: Runtime,
        stop_tasks_sender: oneshot::Sender<StopAllTasksEvent>,
    },
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
        let config = Arc::new(Config::load().unwrap_or_else(|| Config::init()));
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

    #[allow(dead_code)]
    pub fn get_service_name(&self) -> &str {
        self.config.service_name.as_str()
    }

    #[allow(dead_code)]
    pub fn get_display_name(&self) -> &str {
        self.config.display_name.as_str()
    }

    #[allow(dead_code)]
    pub fn get_description(&self) -> &str {
        self.config.description.as_str()
    }

    pub fn start(&mut self) {
        let runtime = Runtime::new().expect("failed to create runtime");

        let config = self.config.clone();
        let logger = self.logger.clone();
        let executor_handle = runtime.executor();
        let context =
            create_context(config, logger, executor_handle.clone()).expect("failed to create gateway context");

        // start http server
        if let Err(e) = context.http_server.start(executor_handle.clone()) {
            error!("HTTP server failed to start: {}", e);
        }

        // future joining all jet tasks
        let all_tasks = future::join_all(context.futures).map_err(|e| {
            error!("Listeners failed: {}", e);
        });

        // oneshot channel to stop our tasks using a select future
        let (sender, receiver) = oneshot::channel::<StopAllTasksEvent>();

        let select_fut = receiver
            .map_err(|e| error!("Receiver error: {}", e))
            .select2(all_tasks)
            .map(|_| ())
            .map_err(|_| ());

        executor_handle.spawn(select_fut);

        self.state = GatewayState::Running {
            http_server: context.http_server,
            runtime,
            stop_tasks_sender: sender,
        };
    }

    pub fn stop(&mut self) {
        match std::mem::take(&mut self.state) {
            GatewayState::Stopped => {
                info!("Attempted to stop gateway service, but it isn't started");
            }
            GatewayState::Running {
                http_server,
                runtime,
                stop_tasks_sender,
            } => {
                info!("Stopping gateway service");

                // stop http server
                http_server.stop();

                // stop all tasks using our sender
                if stop_tasks_sender.send(StopAllTasksEvent).is_err() {
                    error!("Failed to send stop event; will force runtime shutdown now");
                    runtime.shutdown_now().wait().unwrap();
                } else {
                    info!("Waiting for graceful shutdown");
                    runtime.shutdown_on_idle().wait().unwrap();
                }

                self.state = GatewayState::Stopped;
            }
        }
    }
}

pub struct GatewayContext {
    pub http_server: HttpServer,
    pub futures: Vec<Box<dyn Future<Error = String, Item = ()> + Send>>,
}

pub fn create_context(
    config: Arc<Config>,
    logger: slog::Logger,
    executor_handle: TaskExecutor,
) -> Result<GatewayContext, &'static str> {
    let tcp_listeners: Vec<Url> = config
        .listeners
        .iter()
        .filter_map(|listener| {
            if listener.url.scheme() == "tcp" {
                Some(listener.url.clone())
            } else {
                None
            }
        })
        .collect();

    let websocket_listeners: Vec<Url> = config
        .listeners
        .iter()
        .filter_map(|listener| {
            if listener.url.scheme() == "ws" || listener.url.scheme() == "wss" {
                Some(listener.url.clone())
            } else {
                None
            }
        })
        .collect();

    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));

    let http_server = HttpServer::new(config.clone(), jet_associations.clone(), executor_handle.clone());
    let http_service = http_server.server.get_request_handler().clone();

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

    let mut futures = Vec::new();

    for url in &websocket_listeners {
        futures.push(start_websocket_server(
            url.clone(),
            config.clone(),
            http_service.clone(),
            jet_associations.clone(),
            tls_acceptor.clone(),
            executor_handle.clone(),
            logger.clone(),
        ));
    }

    for url in &tcp_listeners {
        futures.push(start_tcp_server(
            url.clone(),
            config.clone(),
            jet_associations.clone(),
            tls_acceptor.clone(),
            tls_public_key.clone(),
            executor_handle.clone(),
            logger.clone(),
        ));
    }

    Ok(GatewayContext { http_server, futures })
}

const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;

fn set_socket_option(stream: &TcpStream, logger: &Logger) {
    if let Err(e) = stream.set_nodelay(true) {
        slog_error!(logger, "set_nodelay on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_keepalive(Some(Duration::from_secs(2))) {
        slog_error!(logger, "set_keepalive on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_send_buffer_size(SOCKET_SEND_BUFFER_SIZE) {
        slog_error!(logger, "set_send_buffer_size on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_recv_buffer_size(SOCKET_RECV_BUFFER_SIZE) {
        slog_error!(logger, "set_recv_buffer_size on TcpStream failed: {}", e);
    }
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Send + Sync + 'static {}

fn start_tcp_server(
    url: Url,
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    tls_acceptor: TlsAcceptor,
    tls_public_key: Vec<u8>,
    executor_handle: TaskExecutor,
    logger: Logger,
) -> Box<dyn Future<Item = (), Error = String> + Send> {
    info!("Starting TCP jet server...");

    let socket_addr = url
        .with_default_port(default_port)
        .expect("invalid URL")
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let listener = TcpListener::bind(&socket_addr).unwrap();

    let server = listener.incoming().for_each(move |conn| {
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

        let client_fut = if let Some(routing_url) = &config.routing_url {
            match routing_url.scheme() {
                "tcp" => {
                    let transport = TcpTransport::new(conn);
                    Client::new(routing_url.clone(), config.clone(), executor_handle.clone()).serve(transport)
                }
                "tls" => {
                    let routing_url_clone = routing_url.clone();
                    let executor_handle_clone = executor_handle.clone();
                    let config_clone = config.clone();

                    Box::new(
                        tls_acceptor
                            .accept(conn)
                            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))
                            .and_then(move |tls_stream| {
                                let transport = TcpTransport::new_tls(TlsStream::Server(tls_stream));
                                Client::new(routing_url_clone, config_clone, executor_handle_clone).serve(transport)
                            }),
                    )
                }
                "ws" => {
                    let routing_url_clone = routing_url.clone();
                    let executor_handle_clone = executor_handle.clone();
                    let peer_addr = conn.peer_addr().ok();
                    let accept = tungstenite::accept(conn);

                    match accept {
                        Ok(stream) => {
                            let transport = WsTransport::new_tcp(stream, peer_addr);
                            Box::new(
                                WsClient::new(routing_url_clone, config.clone(), executor_handle_clone)
                                    .serve(transport),
                            )
                        }
                        Err(tungstenite::handshake::HandshakeError::Interrupted(e)) => {
                            let config_clone = config.clone();
                            Box::new(TcpWebSocketServerHandshake(Some(e)).and_then(move |stream| {
                                let transport = WsTransport::new_tcp(stream, peer_addr);
                                WsClient::new(routing_url_clone, config_clone, executor_handle_clone).serve(transport)
                            })) as Box<dyn Future<Item = (), Error = io::Error> + Send>
                        }
                        Err(tungstenite::handshake::HandshakeError::Failure(e)) => {
                            Box::new(future::err(io::Error::new(io::ErrorKind::Other, e)))
                        }
                    }
                }
                "wss" => {
                    let routing_url_clone = routing_url.clone();
                    let executor_handle_clone = executor_handle.clone();
                    let config_clone = config.clone();

                    Box::new(
                        tls_acceptor
                            .accept(conn)
                            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))
                            .and_then(move |tls_stream| {
                                let peer_addr = tls_stream.get_ref().0.peer_addr().ok();
                                let accept = tungstenite::accept(TlsStream::Server(tls_stream));
                                match accept {
                                    Ok(stream) => {
                                        let transport = WsTransport::new_tls(stream, peer_addr);
                                        Box::new(
                                            WsClient::new(routing_url_clone, config_clone, executor_handle_clone)
                                                .serve(transport),
                                        )
                                    }
                                    Err(tungstenite::handshake::HandshakeError::Interrupted(e)) => {
                                        Box::new(TlsWebSocketServerHandshake(Some(e)).and_then(move |stream| {
                                            let transport = WsTransport::new_tls(stream, peer_addr);
                                            WsClient::new(routing_url_clone, config_clone, executor_handle_clone)
                                                .serve(transport)
                                        }))
                                            as Box<dyn Future<Item = (), Error = io::Error> + Send>
                                    }
                                    Err(tungstenite::handshake::HandshakeError::Failure(e)) => {
                                        Box::new(future::err(io::Error::new(io::ErrorKind::Other, e)))
                                    }
                                }
                            }),
                    )
                }
                "rdp" => RdpClient::new(config.clone(), tls_public_key.clone(), tls_acceptor.clone()).serve(conn),
                scheme => panic!("Unsupported routing URL scheme {}", scheme),
            }
        } else if config.rdp {
            RdpClient::new(config.clone(), tls_public_key.clone(), tls_acceptor.clone()).serve(conn)
        } else {
            JetClient::new(config.clone(), jet_associations.clone(), executor_handle.clone())
                .serve(JetTransport::new_tcp(conn))
        };

        executor_handle.spawn(
            client_fut
                .then(move |res| {
                    match res {
                        Ok(_) => {}
                        Err(e) => error!("Error with client: {}", e),
                    }

                    Ok(())
                })
                .with_logger(logger),
        );

        ok(())
    });

    info!("TCP jet server started successfully. Now listening on {}", socket_addr);

    Box::new(server.map_err(|e| format!("TCP listener failed: {}", e)))
}

fn start_websocket_server(
    websocket_url: Url,
    config: Arc<Config>,
    http_service: HttpService,
    jet_associations: JetAssociationsMap,
    tls_acceptor: TlsAcceptor,
    executor_handle: TaskExecutor,
    logger: slog::Logger,
) -> Box<dyn Future<Item = (), Error = String> + Send> {
    // Start websocket server if needed
    info!("Starting websocket server ...");

    let mut websocket_addr = String::new();
    websocket_addr.push_str(websocket_url.host_str().unwrap_or("0.0.0.0"));
    websocket_addr.push_str(":");
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

    let websocket_listener = TcpListener::bind(
        &websocket_addr
            .parse::<SocketAddr>()
            .expect("Websocket addr can't be parsed."),
    )
    .unwrap();

    let websocket_service = WebsocketService {
        http_service,
        jet_associations,
        executor_handle,
        config,
    };

    let mut listener_logger = logger.clone();
    if let Ok(local_addr) = websocket_listener.local_addr() {
        listener_logger = listener_logger.new(o!("listener" => local_addr.to_string()));
    }

    let http = hyper::server::conn::Http::new();

    let incoming = match websocket_url.scheme() {
        "ws" => Either::A(websocket_listener.incoming().map(move |tcp| {
            let remote_addr = tcp.peer_addr().ok();
            set_socket_option(&tcp, &logger);

            (
                Box::new(tcp) as Box<dyn AsyncReadWrite + Send + Sync + 'static>,
                remote_addr,
            )
        })),

        "wss" => Either::B(websocket_listener.incoming().and_then(move |tcp| {
            set_socket_option(&tcp, &logger);

            tls_acceptor
                .accept(tcp)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                .map(|tls| {
                    let remote_addr = tls.get_ref().0.peer_addr().ok();
                    (
                        Box::new(tls) as Box<dyn AsyncReadWrite + Send + Sync + 'static>,
                        remote_addr,
                    )
                })
        })),

        scheme => panic!("Not a websocket scheme {}", scheme),
    };

    let websocket_server = incoming.then(Ok).for_each(move |conn_res| {
        match conn_res {
            Ok((conn, remote_addr)) => {
                let mut ws_serve = websocket_service.clone();
                let srvc = service_fn(move |req| ws_serve.handle(req, remote_addr));
                websocket_service
                    .executor_handle
                    .spawn(http.serve_connection(conn, srvc).with_upgrades().map_err(|_| ()));
            }
            Err(e) => {
                warn!("incoming connection encountered an error: {}", e);
            }
        }

        future::ok(())
    });

    info!("WebSocket server started successfully. Listening on {}", websocket_addr);
    Box::new(websocket_server.with_logger(listener_logger))
}

fn default_port(url: &Url) -> Result<u16, ()> {
    match url.scheme() {
        "tcp" => Ok(8080),
        _ => Err(()),
    }
}
