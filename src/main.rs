#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate clap;
extern crate url;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate futures;
extern crate byteorder;
extern crate jet_proto;
extern crate native_tls;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_tcp;
extern crate tokio_tls;
extern crate uuid;

mod config;
mod jet_client;
mod routing_client;
mod transport;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use futures::future::{self, ok};
use futures::{Future, Stream};
use tokio::runtime::Runtime;
use tokio_tcp::{TcpListener, TcpStream};

use config::Config;
use jet_client::{JetAssociationsMap, JetClient};
use native_tls::Identity;
use routing_client::Client;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::Mutex;
use transport::tcp::TcpTransport;
use transport::JetTransport;
use url::Url;

const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;

fn main() {
    env_logger::init();
    let config = Config::init();
    let url = Url::parse(&config.listener_url()).unwrap();
    let host = url.host_str().unwrap_or("0.0.0.0").to_string();
    let port = url.port().map(|port| port.to_string()).unwrap_or_else(|| "8080".to_string());

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

    info!("Listening for wayk-jet proxy connections on {}", socket_addr);
    let server = listener.incoming().for_each(move |conn| {
        set_socket_option(&conn);

        let client_fut = if let Some(ref routing_url) = routing_url_opt {
            match routing_url.scheme() {
                "tcp" => {
                    let mut transport = TcpTransport::new(conn);
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
