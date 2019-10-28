#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

mod config;
mod http;
mod interceptor;
mod jet;
mod jet_client;
mod logger;
mod rdp;
mod routing_client;
mod transport;
mod utils;
mod websocket_client;

use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{future, future::ok, future::Either, Future, Stream};
use tokio::runtime::Runtime;
use tokio::runtime::TaskExecutor;
use tokio_tcp::{TcpListener, TcpStream};

use lazy_static::lazy_static;
use slog::{o, Logger};
use slog_scope::{error, info, slog_error, warn};
use slog_scope_futures::future01::FutureExt;
use url::Url;

use crate::config::{Config, Protocol};
use crate::http::http_server::HttpServer;
use crate::interceptor::pcap::PcapInterceptor;
use crate::interceptor::{rdp::RdpMessageReader, UnknownMessageReader, WaykMessageReader};
use crate::jet_client::{JetAssociationsMap, JetClient};
use crate::rdp::RdpClient;
use crate::routing_client::Client;
use crate::transport::tcp::TcpTransport;
use crate::transport::{JetTransport, Transport};
use hyper::service::{make_service_fn, service_fn};
use crate::utils::{get_pub_key_from_der, load_certs, load_private_key};
use crate::websocket_client::{WebsocketService, WsClient};
use std::error::Error;
use crate::transport::ws::{WsTransport, TlsWebSocketServerHandshake, TcpWebSocketServerHandshake};
use tokio_rustls::{TlsAcceptor, TlsStream};
use saphir::server::HttpService;

use x509_parser::pem::pem_to_der;

const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;

lazy_static! {
    pub static ref SESSION_IN_PROGRESS_COUNT: AtomicU64 = AtomicU64::new(0);
}

fn main() {
    let config = Config::init();

    let logger = logger::init(config.log_file().as_ref()).expect("logging setup must not fail");
    let _logger_guard = slog_scope::set_global_logger(logger.clone());

    let listeners = config.listeners();

    let tcp_listeners: Vec<Url> = listeners.iter().filter_map(|listener| {
        if listener.url.scheme() == "tcp" {
            return Some(listener.url.clone());
        }
        None
    }).collect();
    let websocket_listeners: Vec<Url> = listeners.iter().filter_map(|listener| {
        if listener.url.scheme() == "ws" || listener.url.scheme() == "wss" {
            return Some(listener.url.clone());
        }
        None
    }).collect();

    // Initialize the various data structures we're going to use in our server.
    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));

    let mut runtime =
        Runtime::new().expect("This should never fails, a runtime is needed by the entire implementation");
    let executor_handle = runtime.executor();

    info!("Starting http server ...");
    let http_server = HttpServer::new(&config, jet_associations.clone(), executor_handle.clone());
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

    let mut futures = Vec::new();
    for url in websocket_listeners {
        futures.push(start_websocket_server(url.clone(), config.clone(), http_service.clone(), jet_associations.clone(), tls_acceptor.clone(), executor_handle.clone(), logger.clone()));
    }

    for url in tcp_listeners {
        futures.push(start_tcp_server(url.clone(), config.clone(), jet_associations.clone(), tls_acceptor.clone(), executor_handle.clone(), logger.clone()));
    }

    runtime.block_on(future::join_all(futures).map_err(|_| ())).unwrap();
    http_server.stop()
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

struct Proxy {
    config: Config,
}

impl Proxy {
    pub fn new(config: Config) -> Self {
        Proxy { config }
    }

    pub fn build<T: Transport, U: Transport>(
        &self,
        server_transport: T,
        client_transport: U,
    ) -> Box<dyn Future<Item=(), Error=io::Error> + Send> {
        let jet_sink_server = server_transport.message_sink();
        let mut jet_stream_server = server_transport.message_stream();

        let jet_sink_client = client_transport.message_sink();
        let mut jet_stream_client = client_transport.message_stream();

        if let Some(pcap_files_path) = self.config.pcap_files_path() {
            let server_peer_addr = jet_stream_server.peer_addr().unwrap();
            let client_peer_addr = jet_stream_client.peer_addr().unwrap();

            let filename = format!(
                "{}({})-to-{}({})-at-{}.pcap",
                client_peer_addr.ip(),
                client_peer_addr.port(),
                server_peer_addr.ip().to_string(),
                server_peer_addr.port(),
                chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S")
            );
            let mut path = path::PathBuf::from(pcap_files_path);
            path.push(filename);

            let mut interceptor = PcapInterceptor::new(
                server_peer_addr,
                client_peer_addr,
                path.to_str().expect("path to pcap files must be valid"),
            );

            match self.config.protocol() {
                Protocol::WAYK => {
                    info!("WaykMessageReader will be used to interpret application protocol.");
                    interceptor.set_message_reader(WaykMessageReader::get_messages);
                }
                Protocol::RDP => {
                    info!("RdpMessageReader will be used to interpret application protocol");
                    interceptor.set_message_reader(RdpMessageReader::get_messages);
                }
                Protocol::UNKNOWN => {
                    warn!("Protocol is unknown. Data received will not be split to get application message.");
                    interceptor.set_message_reader(UnknownMessageReader::get_messages);
                }
            }

            jet_stream_server.set_packet_interceptor(Box::new(interceptor.clone()));
            jet_stream_client.set_packet_interceptor(Box::new(interceptor.clone()));
        }

        // Build future to forward all bytes
        let f1 = jet_stream_server.forward(jet_sink_client);
        let f2 = jet_stream_client.forward(jet_sink_server);

        SESSION_IN_PROGRESS_COUNT.fetch_add(1, Ordering::Relaxed);

        Box::new(f1.and_then(|(mut jet_stream, mut jet_sink)| {
            // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
            let _ = jet_stream.shutdown();
            let _ = jet_sink.shutdown();
            ok((jet_stream, jet_sink))
        })
            .join(f2.and_then(|(mut jet_stream, mut jet_sink)| {
                // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
                let _ = jet_stream.shutdown();
                let _ = jet_sink.shutdown();
                ok((jet_stream, jet_sink))
            }))
            .and_then(|((jet_stream_1, jet_sink_1), (jet_stream_2, jet_sink_2))| {
                let server_addr = jet_stream_1
                    .peer_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let client_addr = jet_stream_2
                    .peer_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                info!(
                    "Proxy result : {} bytes read on {server} and {} bytes written on {client}. {} bytes read on {client} and {} bytes written on {server}",
                    jet_stream_1.nb_bytes_read(),
                    jet_sink_1.nb_bytes_written(),
                    jet_stream_2.nb_bytes_read(),
                    jet_sink_2.nb_bytes_written(),
                    server = &server_addr,
                    client = &client_addr
                );
                ok(())
            }).then(|result| {
            SESSION_IN_PROGRESS_COUNT.fetch_sub(1, Ordering::Relaxed);
            result
        }))
    }
}

fn start_tcp_server(url: Url, config: Config, jet_associations: JetAssociationsMap, tls_acceptor: TlsAcceptor, executor_handle: TaskExecutor, logger: Logger) -> Box<dyn Future<Item=(), Error=()> + Send> {
    info!("Starting TCP jet server...");
    let socket_addr = url.with_default_port(default_port).expect(&format!("Error in Url {}", url)).to_socket_addrs().unwrap().next().unwrap();
    let listener = TcpListener::bind(&socket_addr).unwrap();
    let server = listener.incoming().for_each(move |conn| {
        let mut logger = logger.clone();
        if let Ok(peer_addr) = conn.peer_addr() {
            logger = logger.new(o!( "client" => peer_addr.to_string()));
        }

        if let Some(ref url) = config.routing_url() {
            let routing_url = Url::parse(&url).expect("routing_url is invalid.");
            logger = logger.new(o!( "scheme" => routing_url.scheme().to_string()));
        }
        set_socket_option(&conn, &logger);

        let routing_url_opt = match config.routing_url() {
            Some(url) => Some(Url::parse(&url).expect("routing_url is invalid.")),
            None => None,
        };

        let config_clone = config.clone();
        let client_fut = if let Some(ref routing_url) = routing_url_opt {
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
                    ) as Box<dyn Future<Item=(), Error=io::Error> + Send>
                }
                "ws" => {
                    let routing_url_clone = routing_url.clone();
                    let executor_handle_clone = executor_handle.clone();
                    let peer_addr = conn.peer_addr().ok();
                    let accept = tungstenite::accept(conn);
                    match accept {
                        Ok(stream) => {
                            let transport = WsTransport::new_tcp(stream, peer_addr);
                            Box::new(WsClient::new(routing_url_clone, config_clone, executor_handle_clone).serve(transport)) as Box<dyn Future<Item=(), Error=io::Error> + Send>
                        },
                        Err(tungstenite::handshake::HandshakeError::Interrupted(e)) => {
                            Box::new(TcpWebSocketServerHandshake(Some(e)).and_then(move |stream| {
                                let transport = WsTransport::new_tcp(stream, peer_addr);
                                WsClient::new(routing_url_clone, config_clone, executor_handle_clone).serve(transport)
                            })) as Box<dyn Future<Item=(), Error=io::Error> + Send>
                        }
                        Err(tungstenite::handshake::HandshakeError::Failure(e)) => Box::new(future::lazy(|| {
                            future::err(io::Error::new(io::ErrorKind::Other, e))
                        })) as Box<dyn Future<Item=(), Error=io::Error> + Send>
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
                                        Box::new(WsClient::new(routing_url_clone, config_clone, executor_handle_clone).serve(transport)) as Box<dyn Future<Item=(), Error=io::Error> + Send>
                                    },
                                    Err(tungstenite::handshake::HandshakeError::Interrupted(e)) => {
                                        Box::new(TlsWebSocketServerHandshake(Some(e)).and_then(move |stream| {
                                            let transport = WsTransport::new_tls(stream, peer_addr);
                                            WsClient::new(routing_url_clone, config_clone, executor_handle_clone).serve(transport)
                                        })) as Box<dyn Future<Item=(), Error=io::Error> + Send>
                                    }
                                    Err(tungstenite::handshake::HandshakeError::Failure(e)) => Box::new(future::lazy(|| {
                                        future::err(io::Error::new(io::ErrorKind::Other, e))
                                    })) as Box<dyn Future<Item=(), Error=io::Error> + Send>
                                }
                            })
                    ) as Box<dyn Future<Item=(), Error=io::Error> + Send>
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
                },
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

                    future::ok(())
                })
                .with_logger(logger));

        ok(())
    });
    info!("TCP jet server started successfully. Listening on {}", socket_addr);

    Box::new(server.map_err(|_|())) as Box<dyn Future<Item=(), Error=()> + Send>
}

fn start_websocket_server(websocket_url: Url, config: Config, http_service: HttpService, jet_associations: JetAssociationsMap, tls_acceptor: TlsAcceptor, executor_handle: TaskExecutor, logger: slog::Logger) -> Box<dyn Future<Item=(), Error=()> + Send>  {
    // Start websocket server if needed
    info!("Starting websocket server ...");
    let mut websocket_addr = String::new();
    websocket_addr.push_str(websocket_url.host_str().unwrap_or("0.0.0.0"));
    websocket_addr.push_str(":");
    websocket_addr.push_str(websocket_url
        .port()
        .map(|port| port.to_string())
        .unwrap_or_else(|| {
            match websocket_url.scheme() {
                "wss" => "443".to_string(),
                "ws" => "80".to_string(),
                _ => "80".to_string()
            }
        }).as_str());
    let websocket_listener = TcpListener::bind(&websocket_addr.parse::<SocketAddr>().expect("Websocket addr can't be parsed.")).unwrap();
    let websocket_service = WebsocketService {
        http_service,
        jet_associations: jet_associations.clone(),
        executor_handle: executor_handle.clone(),
        config: config,
    };

    let closure = |_| ();
    let ws_tls_acceptor = tls_acceptor.clone();
    let websocket_server = match websocket_url.scheme() {
        "ws" => {
            let incoming = websocket_listener.incoming();
            Either::A(hyper::Server::builder(incoming).serve(make_service_fn(move |stream: &tokio::net::tcp::TcpStream| {
                let remote_addr = stream.peer_addr().ok();
                let mut ws_serve = websocket_service.clone();
                service_fn(move |req| {
                    ws_serve.handle(req, remote_addr.clone())
                })
            }))).map_err(closure)
        }

        "wss" => {
            let incoming = websocket_listener.incoming().and_then(move |conn| {
                ws_tls_acceptor.accept(conn).map_err(|e| io::Error::new(io::ErrorKind::Other, e.description()))
            });
            Either::B(hyper::Server::builder(incoming).serve(make_service_fn(move |stream: &tokio_rustls::server::TlsStream<tokio::net::tcp::TcpStream>| {
                let remote_addr = stream.get_ref().0.peer_addr().ok();
                let mut ws_serve = websocket_service.clone();
                service_fn(move |req| {
                    ws_serve.handle(req, remote_addr.clone())
                })
            }))).map_err(closure)
        }

        scheme => panic!("Not a websocket scheme {}", scheme),
    };

    info!("Websocket server started successfully. Listening on {}", websocket_addr);
    Box::new(websocket_server.with_logger(logger)) as Box<dyn Future<Item=(), Error=()> + Send>
}

fn default_port(url: &Url) -> Result<u16, ()> {
    match url.scheme() {
        "tcp" => Ok(8080),
        _ => Err(()),
    }
}
