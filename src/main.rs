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
extern crate tokio;
extern crate tokio_io;
extern crate tokio_tcp;
extern crate uuid;
extern crate jet_proto;

mod config;
mod jet_client;
mod routing_client;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::{self, ok};
use futures::{Async, AsyncSink, Future, Sink, Stream};
use tokio::runtime::{Runtime};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::{TcpListener, TcpStream};

use config::Config;
use std::net::Shutdown;
use url::Url;
use jet_client::{JetAssociationsMap, JetClient};
use routing_client::Client;

const SOCKET_SEND_BUFFER_SIZE: usize = 0x7FFFF;
const SOCKET_RECV_BUFFER_SIZE: usize = 0x7FFFF;

fn main() {
    env_logger::init();
    let config = Config::init();
    let url = Url::parse(&config.listener_url()).unwrap();
    let host = url.host_str().unwrap_or("0.0.0.0").to_string();
    let port = url.port().map(|port| port.to_string()).unwrap_or("8080".to_string());

    let mut listener_addr = String::new();
    listener_addr.push_str(&host);
    listener_addr.push_str(":");
    listener_addr.push_str(&port);

    let socket_addr = listener_addr.parse::<SocketAddr>().unwrap();

    // Initialize the various data structures we're going to use in our server.
    let listener = TcpListener::bind(&socket_addr).unwrap();
    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));
    let mut runtime =
        Runtime::new().expect("This should never fails, a runtime is needed by the entire implementation");
    let executor_handle = runtime.executor();

    info!("Listening for wayk-jet proxy connections on {}", socket_addr);
    let server = listener.incoming().for_each(move |conn| {
        set_socket_option(&conn);

        let client_fut =
            if let Some(routing_url) = config.routing_url() {
                Client::new(routing_url, executor_handle.clone()).serve(Arc::new(Mutex::new(conn)))
            }
            else {
                JetClient::new(jet_associations.clone(), executor_handle.clone()).serve(Arc::new(Mutex::new(conn)))
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

struct JetStream {
    stream: Arc<Mutex<TcpStream>>,
    nb_bytes_read: u64,
}

impl JetStream {
    fn new(stream: Arc<Mutex<TcpStream>>) -> Self {
        JetStream {
            stream,
            nb_bytes_read: 0,
        }
    }

    fn get_addr(&self) -> io::Result<SocketAddr> {
        let stream = self.stream.lock().unwrap();
        stream.peer_addr()
    }

    fn _nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read
    }

    fn shutdown(&self) {
        let stream = self.stream.lock().unwrap();
        let _ = stream.shutdown(Shutdown::Both);
    }
}

impl Stream for JetStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if let Ok(mut stream) = self.stream.try_lock() {
            let mut buffer = [0u8; 1024];
            match stream.poll_read(&mut buffer) {
                Ok(Async::Ready(0)) => Ok(Async::Ready(None)),
                Ok(Async::Ready(len)) => {
                    let mut v = buffer.to_vec();
                    v.truncate(len);
                    self.nb_bytes_read += len as u64;
                    Ok(Async::Ready(Some(v)))
                }
                Ok(Async::NotReady) => Ok(Async::NotReady),
                Err(e) => {
                    error!("Can't read on socket: {}", e);
                    Ok(Async::Ready(None))
                }
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}

struct JetSink {
    stream: Arc<Mutex<TcpStream>>,
    data_to_send: Vec<u8>,
    nb_bytes_written: u64,
}

impl JetSink {
    fn new(stream: Arc<Mutex<TcpStream>>) -> Self {
        JetSink {
            stream,
            data_to_send: Vec::new(),
            nb_bytes_written: 0,
        }
    }

    fn nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written
    }

    fn shutdown(&self) {
        let stream = self.stream.lock().unwrap();
        let _ = stream.shutdown(Shutdown::Both);
    }
}

impl Sink for JetSink {
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        mut item: <Self as Sink>::SinkItem,
    ) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        self.data_to_send.append(&mut item);
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            match stream.poll_write(&self.data_to_send) {
                Ok(Async::Ready(len)) => {
                    if len > 0 {
                        self.nb_bytes_written += len as u64;
                        self.data_to_send.drain(0..len);
                    }
                    if self.data_to_send.len() == 0 {
                        Ok(Async::Ready(()))
                    } else {
                        Ok(Async::NotReady)
                    }
                }
                Ok(Async::NotReady) => Ok(Async::NotReady),
                Err(e) => {
                    error!("Can't write on socket: {}", e);
                    Ok(Async::Ready(()))
                }
            }
        } else {
            Ok(Async::NotReady)
        }
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        Ok(Async::Ready(()))
    }
}

