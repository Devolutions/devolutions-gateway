#[macro_use]
extern crate serde_json;

#[macro_use]
mod utils;
mod config;
mod http;
mod interceptor;
mod jet;
mod jet_client;
mod rdp;
mod routing_client;
mod transport;
mod websocket_client;

use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{future, future::ok, Future, Stream};
use native_tls::Identity;
use tokio::runtime::Runtime;
use tokio::runtime::TaskExecutor;
use tokio_tcp::{TcpListener, TcpStream};

use lazy_static::lazy_static;
use log::{error, info, warn};
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
use crate::utils::get_tls_pubkey;
use hyper::service::{service_fn, make_service_fn};
use crate::websocket_client::{WebsocketService, WsClient};
use std::error::Error;
use futures::future::Either;
use crate::transport::ws::{WsTransport, TlsWebSocketServerHandshake, TcpWebSocketServerHandshake};
use tokio_tls::TlsAcceptor;
use saphir::server::HttpService;

const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;

lazy_static! {
    pub static ref SESSION_IN_PROGRESS_COUNT: AtomicU64 = AtomicU64::new(0);
}

fn main() {
    env_logger::init();
    let config = Config::init();
    let listeners = config.listeners();

    let tcp_listeners: Vec<&Url> = listeners.iter().filter(|listener| listener.scheme() == "tcp").collect();
    let websocket_listeners: Vec<&Url> = listeners.iter().filter(|listener| listener.scheme() == "ws" || listener.scheme() == "wss").collect();

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
    info!("Http server succesfully started");
    let http_service = http_server.server.get_request_handler().clone();

    // Create the TLS acceptor.
    let der = include_bytes!("cert/certificate.p12");
    let tls_public_key = get_tls_pubkey(der.as_ref(), "password").unwrap();
    let cert = Identity::from_pkcs12(der, "password").unwrap();
    let tls_acceptor = tokio_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build().unwrap());

    for url in websocket_listeners {
        start_websocket_server(url.clone(), config.clone(), http_service.clone(), jet_associations.clone(), tls_acceptor.clone(), executor_handle.clone());
    }

    let mut server_opt = None;
    for url in tcp_listeners {
        server_opt = Some(start_tcp_server(url.clone(), config.clone(), jet_associations.clone(), tls_acceptor.clone(), tls_public_key.clone(), executor_handle.clone()));
    }


    if let Some(server) = server_opt {
        runtime.block_on(server.map_err(|_| ())).unwrap();
    }
    http_server.stop()
}

fn set_socket_option(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        error!("set_nodelay on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_keepalive(Some(Duration::from_secs(2))) {
        error!("set_keepalive on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_send_buffer_size(SOCKET_SEND_BUFFER_SIZE) {
        error!("set_send_buffer_size on TcpStream failed: {}", e);
    }

    if let Err(e) = stream.set_recv_buffer_size(SOCKET_RECV_BUFFER_SIZE) {
        error!("set_recv_buffer_size on TcpStream failed: {}", e);
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

        if let Some(pcap_filename) = self.config.pcap_filename() {
            let mut interceptor = PcapInterceptor::new(
                jet_stream_server.peer_addr().unwrap(),
                jet_stream_client.peer_addr().unwrap(),
                &pcap_filename,
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
                    server = server_addr,
                    client = client_addr
                );
                ok(())
            }).then(|result| {
            SESSION_IN_PROGRESS_COUNT.fetch_sub(1, Ordering::Relaxed);
            result
        }))
    }
}

fn start_tcp_server(url: Url, config: Config, jet_associations: JetAssociationsMap, tls_acceptor: TlsAcceptor, tls_public_key: Vec<u8>, executor_handle: TaskExecutor) -> Box<dyn Future<Item=(), Error=io::Error> + Send> {
    info!("Starting TCP jet server...");
    let socket_addr = url.with_default_port(default_port).expect(&format!("Error in Url {}", url)).to_socket_addrs().unwrap().next().unwrap();
    let listener = TcpListener::bind(&socket_addr).unwrap();
    let server = listener.incoming().for_each(move |conn| {
        set_socket_option(&conn);

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
                                let transport = TcpTransport::new_tls(tls_stream);
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
                                let peer_addr = tls_stream.get_ref().get_ref().peer_addr().ok().clone();
                                let accept = tungstenite::accept(tls_stream);
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
                "rdp" => RdpClient::new(
                    routing_url.clone(),
                    config.clone(),
                    tls_public_key.clone(),
                    tls_acceptor.clone(),
                )
                    .serve(conn),
                scheme => panic!("Unsupported routing url scheme {}", scheme),
            }
        } else {
            JetClient::new(config_clone, jet_associations.clone(), executor_handle.clone())
                .serve(JetTransport::new_tcp(conn))
        };

        executor_handle.spawn(client_fut.then(move |res| {
            match res {
                Ok(_) => {}
                Err(e) => error!("Error with client: {}", e),
            }
            future::ok(())
        }));
        ok(())
    });
    info!("TCP jet server started successfully. Listening on {}", socket_addr);

    Box::new(server) as Box<dyn Future<Item=(), Error=io::Error> + Send>
}

fn start_websocket_server(websocket_url: Url, config: Config, http_service: HttpService, jet_associations: JetAssociationsMap, tls_acceptor: TlsAcceptor, executor_handle: TaskExecutor) {

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
            Either::B(hyper::Server::builder(incoming).serve(make_service_fn(move |stream: &tokio_tls::TlsStream<tokio::net::tcp::TcpStream>| {
                let remote_addr = stream.get_ref().get_ref().peer_addr().ok();
                let mut ws_serve = websocket_service.clone();
                service_fn(move |req| {
                    ws_serve.handle(req, remote_addr.clone())
                })
            }))).map_err(closure)
        }

        scheme => panic!("Not a websocket scheme {}", scheme),
    };

    &executor_handle.spawn(websocket_server);
    info!("Websocket server started successfully. Listening on {}", websocket_addr);
}

fn default_port(url: &Url) -> Result<u16, ()> {
    match url.scheme() {
        "tcp" => Ok(8080),
        _ => Err(()),
    }
}