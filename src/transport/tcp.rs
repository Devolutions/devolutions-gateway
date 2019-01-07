use futures::{Async, AsyncSink, Future, Sink, Stream};
use log::{debug, error, info};
use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::TcpStream;
use tokio_tls::TlsStream;
use url::Url;

use crate::transport::{JetFuture, JetSink, JetStream, Transport};

pub enum TcpStreamWrapper {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl TcpStreamWrapper {
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            TcpStreamWrapper::Plain(stream) => stream.peer_addr().ok(),
            TcpStreamWrapper::Tls(stream) => stream.get_ref().get_ref().peer_addr().ok(),
        }
    }
}

impl Read for TcpStreamWrapper {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            TcpStreamWrapper::Plain(ref mut stream) => stream.read(&mut buf),
            TcpStreamWrapper::Tls(ref mut stream) => stream.read(&mut buf),
        }
    }
}

impl Write for TcpStreamWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            TcpStreamWrapper::Plain(ref mut stream) => stream.write(&buf),
            TcpStreamWrapper::Tls(ref mut stream) => stream.write(&buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            TcpStreamWrapper::Plain(ref mut stream) => stream.flush(),
            TcpStreamWrapper::Tls(ref mut stream) => stream.flush(),
        }
    }
}

impl AsyncRead for TcpStreamWrapper {}
impl AsyncWrite for TcpStreamWrapper {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match *self {
            TcpStreamWrapper::Plain(ref mut stream) => AsyncWrite::shutdown(stream),
            TcpStreamWrapper::Tls(ref mut stream) => AsyncWrite::shutdown(stream),
        }
    }
}

pub struct TcpTransport {
    stream: Arc<Mutex<TcpStreamWrapper>>,
}

impl Clone for TcpTransport {
    fn clone(&self) -> Self {
        TcpTransport {
            stream: self.stream.clone(),
        }
    }
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> Self {
        TcpTransport {
            stream: Arc::new(Mutex::new(TcpStreamWrapper::Plain(stream))),
        }
    }

    pub fn new_tls(stream: TlsStream<TcpStream>) -> Self {
        TcpTransport {
            stream: Arc::new(Mutex::new(TcpStreamWrapper::Tls(stream))),
        }
    }
}

impl Read for TcpTransport {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.read(&mut buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}
impl AsyncRead for TcpTransport {}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.write(&buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.flush(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl AsyncWrite for TcpTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.shutdown(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl Transport for TcpTransport {
    fn message_stream(&self) -> JetStream<Vec<u8>> {
        Box::new(TcpJetStream::new(self.stream.clone()))
    }

    fn message_sink(&self) -> JetSink<Vec<u8>> {
        Box::new(TcpJetSink::new(self.stream.clone()))
    }

    fn connect(url: &Url) -> JetFuture<Self>
    where
        Self: Sized,
    {
        match url.scheme() {
            "tcp" => {
                let mut addr = String::new();
                let host = url.host_str().unwrap().to_string();
                let port = url.port().map(|port| port.to_string()).unwrap();
                addr.push_str(&host);
                addr.push_str(":");
                addr.push_str(&port);
                let socket_addr = addr.parse::<SocketAddr>().unwrap();

                Box::new(TcpStream::connect(&socket_addr).map(|stream| TcpTransport::new(stream))) as JetFuture<Self>
            }
            "tls" => {
                let mut addr = String::new();
                let host = url.host_str().unwrap().to_string();
                let port = url.port().map(|port| port.to_string()).unwrap();
                addr.push_str(&host);
                addr.push_str(":");
                addr.push_str(&port);
                let socket_addr = addr.parse::<SocketAddr>().unwrap();

                let socket = TcpStream::connect(&socket_addr);
                let cx = TlsConnector::builder()
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true)
                    .build()
                    .unwrap();
                let cx = tokio_tls::TlsConnector::from(cx);

                info!("Try to connect to socket_addr: {}", socket_addr);
                let url_clone = url.clone();
                let tls_handshake = socket.and_then(move |socket| {
                    info!("before cx.connect");
                    cx.connect(url_clone.host_str().unwrap_or(""), socket)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                });
                let request = tls_handshake.map(|tls_stream| TcpTransport::new_tls(tls_stream));
                Box::new(request) as JetFuture<Self>
            }

            scheme => {
                panic!("Unsuported scheme: {}", scheme);
            }
        }
    }
}

struct TcpJetStream {
    stream: Arc<Mutex<TcpStreamWrapper>>,
    nb_bytes_read: u64,
}

impl TcpJetStream {
    fn new(stream: Arc<Mutex<TcpStreamWrapper>>) -> Self {
        TcpJetStream {
            stream,
            nb_bytes_read: 0,
        }
    }

    fn _get_addr(&self) -> io::Result<SocketAddr> {
        let _stream = self.stream.lock().unwrap();
        //todo
        unimplemented!()
        //stream.peer_addr()
    }

    fn _nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read
    }

    fn _shutdown(&mut self) {
        let mut stream = self.stream.lock().unwrap();
        let _ = stream.shutdown();
    }
}

impl Stream for TcpJetStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if let Ok(ref mut stream) = self.stream.try_lock() {
            let mut buffer = [0u8; 1024];
            match stream.poll_read(&mut buffer) {
                Ok(Async::Ready(0)) => Ok(Async::Ready(None)),
                Ok(Async::Ready(len)) => {
                    let mut v = buffer.to_vec();
                    v.truncate(len);
                    self.nb_bytes_read += len as u64;
                    debug!("{} bytes read on {}", len, stream.peer_addr().unwrap());
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

struct TcpJetSink {
    stream: Arc<Mutex<TcpStreamWrapper>>,
    nb_bytes_written: u64,
}

impl TcpJetSink {
    fn new(stream: Arc<Mutex<TcpStreamWrapper>>) -> Self {
        TcpJetSink {
            stream,
            nb_bytes_written: 0,
        }
    }

    fn _nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written
    }

    fn _shutdown(&mut self) {
        let mut stream = self.stream.lock().unwrap();
        let _ = stream.shutdown();
    }
}

impl Sink for TcpJetSink {
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        mut item: <Self as Sink>::SinkItem,
    ) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            debug!("{} bytes to write on {}", item.len(), stream.peer_addr().unwrap());
            match stream.poll_write(&item) {
                Ok(Async::Ready(len)) => {
                    if len > 0 {
                        self.nb_bytes_written += len as u64;
                        item.drain(0..len);
                        debug!("{} bytes written on {}", len, stream.peer_addr().unwrap())
                    } else {
                        debug!("0 bytes written on {}", stream.peer_addr().unwrap())
                    }
                    if item.is_empty() {
                        Ok(AsyncSink::Ready)
                    } else {
                        Ok(AsyncSink::NotReady(item))
                    }
                }
                Ok(Async::NotReady) => Ok(AsyncSink::NotReady(item)),
                Err(e) => {
                    error!("Can't write on socket: {}", e);
                    Ok(AsyncSink::Ready)
                }
            }
        } else {
            Ok(AsyncSink::NotReady(item))
        }
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            stream.poll_flush()
        } else {
            Ok(Async::NotReady)
        }
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        Ok(Async::Ready(()))
    }
}
