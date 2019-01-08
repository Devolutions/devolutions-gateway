mod config;
mod jet_client;
mod routing_client;
mod transport;

use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{future, future::ok, Future, Stream};
use tokio::runtime::Runtime;
use tokio_tcp::{TcpListener, TcpStream};

use log::{error, info};
use native_tls::Identity;
use url::Url;

use crate::config::Config;
use crate::jet_client::{JetAssociationsMap, JetClient};
use crate::routing_client::Client;
use crate::transport::tcp::TcpTransport;
use crate::transport::{Transport, JetTransport};

const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;

fn main() {
    env_logger::init();
    let config = Config::init();
    let url = Url::parse(&config.listener_url()).unwrap();
    let host = url.host_str().unwrap_or("0.0.0.0").to_string();
    let port = url
        .port()
        .map(|port| port.to_string())
        .unwrap_or_else(|| "8080".to_string());

    let mut listener_addr = String::new();
    listener_addr.push_str(&host);
    listener_addr.push_str(":");
    listener_addr.push_str(&port);

    let socket_addr = listener_addr.parse::<SocketAddr>().unwrap();

    let routing_url_opt = match config.routing_url() {
        Some(url) => Some(Url::parse(&url).expect("routing_url is invalid.")),
        None => None,
    };

    // Initialize the various data structures we're going to use in our server.
    let listener = TcpListener::bind(&socket_addr).unwrap();
    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));

    let mut runtime =
        Runtime::new().expect("This should never fails, a runtime is needed by the entire implementation");
    let executor_handle = runtime.executor();

    // Create the TLS acceptor.
    let der = include_bytes!("cert/certificate.p12");
    let cert = Identity::from_pkcs12(der, "").unwrap();
    let tls_acceptor = tokio_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build().unwrap());

    info!("Listening for devolutions-jet proxy connections on {}", socket_addr);
    let server = listener.incoming().for_each(move |conn| {
        set_socket_option(&conn);

        let client_fut = if let Some(ref routing_url) = routing_url_opt {
            match routing_url.scheme() {
                "tcp" => {
                    let transport = TcpTransport::new(conn);
                    Client::new(routing_url.clone(), executor_handle.clone()).serve(transport)
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
                                Client::new(routing_url_clone, executor_handle_clone).serve(transport)
                            }),
                    ) as Box<Future<Item = (), Error = io::Error> + Send>
                }
                _ => unreachable!(),
            }
        } else {
            JetClient::new(jet_associations.clone(), executor_handle.clone()).serve(JetTransport::new_tcp(conn))
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

    runtime.block_on(server.map_err(|_| ())).unwrap();
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

fn build_proxy<T: Transport, U: Transport>(server_transport: T, client_transport: U) -> Box<Future<Item = (), Error = io::Error> + Send> {
    let jet_sink_server = server_transport.message_sink();
    let jet_stream_server = server_transport.message_stream();

    let jet_sink_client = client_transport.message_sink();
    let jet_stream_client = client_transport.message_stream();

    // Build future to forward all bytes
    let f1 = jet_stream_server.forward(jet_sink_client);
    let f2 = jet_stream_client.forward(jet_sink_server);

    Box::new(f1.and_then(|(jet_stream, jet_sink)| {
        // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
        let _ = jet_stream.shutdown();
        let _ = jet_sink.shutdown();
        ok((jet_stream, jet_sink))
    })
    .join(f2.and_then(|(jet_stream, jet_sink)| {
        // Shutdown stream and the sink so the f2 will finish as well (and the join future will finish)
        let _ = jet_stream.shutdown();
        let _ = jet_sink.shutdown();
        ok((jet_stream, jet_sink))
    }))
    .and_then(|((jet_stream_1, jet_sink_1), (jet_stream_2, jet_sink_2))| {
        let server_addr = jet_stream_1
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or("unknown".to_string());
        let client_addr = jet_stream_2
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or("unknown".to_string());
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
    }))
}
