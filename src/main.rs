use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{future, future::ok, future::Either, Future, Stream};
use hyper::service::{make_service_fn, service_fn};
use saphir::server::HttpService;
use slog::{o, Logger};
use slog_scope::{error, info, slog_error, warn};
use slog_scope_futures::future01::FutureExt;
use tokio::net::tcp::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::runtime::TaskExecutor;
use tokio_rustls::{TlsAcceptor, TlsStream};
use url::Url;
use x509_parser::pem::pem_to_der;

use devolutions_jet::config::Config;
use devolutions_jet::http::http_server::HttpServer;
use devolutions_jet::jet_client::{JetAssociationsMap, JetClient};
use devolutions_jet::logger;
use devolutions_jet::rdp::RdpClient;
use devolutions_jet::routing_client::Client;
use devolutions_jet::transport::tcp::TcpTransport;
use devolutions_jet::transport::ws::{TcpWebSocketServerHandshake, TlsWebSocketServerHandshake, WsTransport};
use devolutions_jet::transport::JetTransport;
use devolutions_jet::utils::{get_pub_key_from_der, load_certs, load_private_key};
use devolutions_jet::websocket_client::{WebsocketService, WsClient};
use tokio::io::Error;
use tokio::prelude::{AsyncRead, AsyncWrite};

const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;

fn main() {
    let config = Arc::new(Config::init());

    let logger = logger::init(config.log_file()).expect("logging setup must not fail");
    let _logger_guard = slog_scope::set_global_logger(logger.clone());
    let _std_logger_guard = slog_stdlog::init().unwrap();

    let listeners = config.listeners();

    let tcp_listeners: Vec<Url> = listeners
        .iter()
        .filter_map(|listener| {
            if listener.url.scheme() == "tcp" {
                Some(listener.url.clone())
            } else {
                None
            }
        })
        .collect();
    let websocket_listeners: Vec<Url> = listeners
        .iter()
        .filter_map(|listener| {
            if listener.url.scheme() == "ws" || listener.url.scheme() == "wss" {
                Some(listener.url.clone())
            } else {
                None
            }
        })
        .collect();

    // Initialize the various data structures we're going to use in our server.
    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));

    let mut runtime =
        Runtime::new().expect("This should never fails, a runtime is needed by the entire implementation");
    let executor_handle = runtime.executor();

    info!("Starting http server ...");
    let http_server = HttpServer::new(config.clone(), jet_associations.clone(), executor_handle.clone());
    if let Err(e) = http_server.start(executor_handle.clone()) {
        error!("http_server failed to start: {}", e);
        return;
    }
    info!("Http server successfully started");
    let http_service = http_server.server.get_request_handler().clone();

    // Create the TLS acceptor.
    let certs = load_certs(&config.certificate).expect("Could not load a certificate src/cert/publicCert.pem");
    let priv_key = load_private_key(&config.certificate).expect("Could not load a certificate src/cert/private.pem");

    let client_no_auth = rustls::NoClientAuth::new();
    let mut server_config = rustls::ServerConfig::new(client_no_auth);
    server_config.set_single_cert(certs, priv_key).unwrap();
    let config_ref = Arc::new(server_config);
    let tls_acceptor = TlsAcceptor::from(config_ref);

    let mut futures = Vec::with_capacity(websocket_listeners.len() + tcp_listeners.len());
    for url in websocket_listeners {
        futures.push(start_websocket_server(
            url,
            config.clone(),
            http_service.clone(),
            jet_associations.clone(),
            tls_acceptor.clone(),
            executor_handle.clone(),
            logger.clone(),
        ));
    }

    for url in tcp_listeners {
        futures.push(start_tcp_server(
            url,
            config.clone(),
            jet_associations.clone(),
            tls_acceptor.clone(),
            executor_handle.clone(),
            logger.clone(),
        ));
    }

    if let Err(e) = runtime.block_on(future::join_all(futures)) {
        error!("Listeners failed: {}", e);
    }

    http_server.stop();
}

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
    executor_handle: TaskExecutor,
    logger: Logger,
) -> Box<dyn Future<Item = (), Error = String> + Send> {
    info!("Starting TCP jet server...");
    let socket_addr = url
        .with_default_port(default_port)
        .expect(&format!("Error in Url {}", url))
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let listener = TcpListener::bind(&socket_addr).unwrap();
    let server = listener.incoming().for_each(move |conn| {
        let mut logger = logger.clone();

        if let Ok(peer_addr) = conn.peer_addr() {
            logger = logger.new(o!( "client" => peer_addr.to_string()));
        }

        if let Ok(local_addr) = conn.local_addr() {
            logger = logger.new(o!("listener" => local_addr.to_string()));
        }

        if let Some(ref url) = config.routing_url() {
            logger = logger.new(o!( "scheme" => url.scheme().to_string()));
        }
        set_socket_option(&conn, &logger);

        let routing_url_opt = config.routing_url();

        let config_clone = config.clone();
        let client_fut = if let Some(routing_url) = routing_url_opt {
            match routing_url.scheme() {
                "tcp" => {
                    let transport = TcpTransport::new(conn);
                    Client::new(routing_url.clone(), config_clone, executor_handle.clone()).serve(transport)
                }
                "tls" => {
                    let routing_url_clone = routing_url.clone();
                    let executor_handle_clone = executor_handle.clone();
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
                                WsClient::new(routing_url_clone, config_clone, executor_handle_clone).serve(transport),
                            )
                        }
                        Err(tungstenite::handshake::HandshakeError::Interrupted(e)) => {
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
                "rdp" => {
                    let certificate = include_bytes!("cert/publicCert.pem");
                    let pem = pem_to_der(certificate).expect("Could not convert pem to der file");
                    let tls_public_key = get_pub_key_from_der(pem.1.contents).expect("Could not parse pem file");

                    RdpClient::new(
                        routing_url.clone(),
                        config.clone(),
                        tls_public_key.clone(),
                        tls_acceptor.clone(),
                    )
                    .serve(conn)
                }
                scheme => panic!("Unsupported routing url scheme {}", scheme),
            }
        } else {
            JetClient::new(config_clone, jet_associations.clone(), executor_handle.clone())
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
    info!("TCP jet server started successfully. Listening on {}", socket_addr);

    Box::new(server.map_err(|e| format!("TCP listener failed: {}", e)))
}

fn start_websocket_server(
    websocket_url: Url,
    config: Arc<Config>,
    http_service: HttpService,
    jet_associations: JetAssociationsMap,
    tls_acceptor: TlsAcceptor,
    executor_handle: TaskExecutor,
    mut logger: slog::Logger,
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
        jet_associations: jet_associations.clone(),
        executor_handle: executor_handle.clone(),
        config,
    };

    if let Ok(local_addr) = websocket_listener.local_addr() {
        logger = logger.new(o!("listener" => local_addr.to_string()));
    }

    let ws_tls_acceptor = tls_acceptor.clone();
    let http = hyper::server::conn::Http::new();

    let incoming = match websocket_url.scheme() {
        "ws" => Either::A(websocket_listener.incoming().map(|tcp| {
            let remote_addr = tcp.peer_addr().ok();
            (
                Box::new(tcp) as Box<dyn AsyncReadWrite + Send + Sync + 'static>,
                remote_addr,
            )
        })),

        "wss" => Either::B(websocket_listener.incoming().and_then(move |conn| {
            ws_tls_acceptor
                .accept(conn)
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

    let websocket_server = incoming.then(|conn_res| Ok(conn_res)).for_each(move |conn_res| {
        match conn_res {
            Ok((conn, remote_addr)) => {
                let mut ws_serve = websocket_service.clone();
                let srvc = service_fn(move |req| ws_serve.handle(req, remote_addr));
                websocket_service
                    .executor_handle
                    .spawn(http.serve_connection(conn, srvc).map_err(|_| ()));
            }
            Err(e) => {
                warn!("incoming connection encountered an error: {}", e);
            }
        }

        future::ok(())
    });

    info!("WebSocket server started successfully. Listening on {}", websocket_addr);
    Box::new(websocket_server.with_logger(logger))
}

fn default_port(url: &Url) -> Result<u16, ()> {
    match url.scheme() {
        "tcp" => Ok(8080),
        _ => Err(()),
    }
}
