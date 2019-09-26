use std::sync::atomic::{AtomicU64, Ordering};
use tungstenite::{WebSocket, ServerHandshake, HandshakeError, ClientHandshake};
use hyper::upgrade::Upgraded;
use std::sync::{Mutex, Arc};
use std::io::{Read, Write, ErrorKind};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio::io;
use crate::interceptor::PacketInterceptor;
use futures::{Async, Stream, Sink, AsyncSink, Future};
use crate::transport::{Transport, JetStreamType, JetSinkType, JetFuture, JetStream, JetSink};
use url::Url;
use slog_scope::{debug, error};
use std::net::SocketAddr;
use tungstenite::Message;
use tungstenite::protocol::Role;
use crate::utils::{danger_transport, url_to_socket_arr};
use crate::transport::tcp::TCP_READ_LEN;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::TlsStream;
use tungstenite::handshake::client::{Request, Response};
use futures::future;
use tungstenite::handshake::MidHandshake;
use tungstenite::handshake::server::NoCallback;
use std::error::Error;

pub enum WsStreamWrapper {
    Http((WebSocket<Upgraded>, Option<SocketAddr>)),
    Tcp((WebSocket<TcpStream>, Option<SocketAddr>)),
    Tls((WebSocket<TlsStream<TcpStream>>, Option<SocketAddr>)),
}

impl WsStreamWrapper {
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            WsStreamWrapper::Http((_stream, addr)) => addr.clone(),
            WsStreamWrapper::Tcp((_stream, addr)) => addr.clone(),
            WsStreamWrapper::Tls((_stream, addr)) => addr.clone(),
        }
    }

    pub fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            WsStreamWrapper::Http((stream, _)) => stream.close(None).map(|()| ()).map_err(|_| io::Error::new(io::ErrorKind::NotFound, "".to_string())),
            WsStreamWrapper::Tcp((stream, _)) => stream.close(None).map(|()| ()).map_err(|_| io::Error::new(io::ErrorKind::NotFound, "".to_string())),
            WsStreamWrapper::Tls((stream, _)) => stream.close(None).map(|()| ()).map_err(|_| io::Error::new(io::ErrorKind::NotFound, "".to_string())),
        }
    }

    pub fn async_shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self {
            WsStreamWrapper::Http((stream, _)) => stream.close(None).map(|()| Async::Ready(())).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())),
            WsStreamWrapper::Tcp((stream, _)) => stream.close(None).map(|()| Async::Ready(())).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())),
            WsStreamWrapper::Tls((stream, _)) => stream.close(None).map(|()| Async::Ready(())).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }
}

impl Read for WsStreamWrapper {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let message_result = match *self {
            WsStreamWrapper::Http((ref mut stream, _)) => {
                stream.read_message()
            }
            WsStreamWrapper::Tcp((ref mut stream, _)) => {
                stream.read_message()
            }
            WsStreamWrapper::Tls((ref mut stream, _)) => {
                stream.read_message()
            }
        };

        match message_result {
            Ok(message) => {
                if (message.is_binary() || message.is_text()) && !message.is_empty() {
                    buf.write(message.into_data().as_mut_slice())
                } else {
                    Err(io::Error::new(ErrorKind::WouldBlock, "No Data"))
                }
            }
            Err(e) => {
                Err(tungstenite_err_to_io_err(e))
            }
        }
    }
}

impl Write for WsStreamWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            WsStreamWrapper::Http((ref mut stream, _)) =>
                stream.write_message(Message::Binary(buf.to_vec())).map(|_| buf.len()).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tcp((ref mut stream, ref mut _addr)) =>
                stream.write_message(Message::Binary(buf.to_vec())).map(|_| buf.len()).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tls((ref mut stream, ref mut _addr)) =>
                stream.write_message(Message::Binary(buf.to_vec())).map(|_| buf.len()).map_err(|e| tungstenite_err_to_io_err(e)),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            WsStreamWrapper::Http((ref mut stream, _)) =>
                stream.write_pending().map(|_| ()).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tcp((ref mut stream, _)) =>
                stream.write_pending().map(|_| ()).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tls((ref mut stream, ref mut _addr)) =>
                stream.write_pending().map(|_| ()).map_err(|e| tungstenite_err_to_io_err(e)),
        }
    }
}

impl AsyncRead for WsStreamWrapper {}

impl AsyncWrite for WsStreamWrapper {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match *self {
            WsStreamWrapper::Http((ref mut stream, _)) =>
                stream.close(None).map(|_| Async::Ready(())).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tcp((ref mut stream, _)) =>
                stream.close(None).map(|_| Async::Ready(())).map_err(|e| tungstenite_err_to_io_err(e)),
            WsStreamWrapper::Tls((ref mut stream, _)) =>
                stream.close(None).map(|_| Async::Ready(())).map_err(|e| tungstenite_err_to_io_err(e)),
        }
    }
}

pub struct WsTransport {
    stream: Arc<Mutex<WsStreamWrapper>>,
    nb_bytes_read: Arc<AtomicU64>,
    nb_bytes_written: Arc<AtomicU64>,
}

impl Clone for WsTransport {
    fn clone(&self) -> Self {
        WsTransport {
            stream: self.stream.clone(),
            nb_bytes_read: self.nb_bytes_read.clone(),
            nb_bytes_written: self.nb_bytes_written.clone(),
        }
    }
}

impl WsTransport {
    pub fn new_http(upgraded: Upgraded, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: Arc::new(Mutex::new(WsStreamWrapper::Http((WebSocket::from_raw_socket(upgraded, Role::Server, None), addr)))),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_tcp(stream: WebSocket<TcpStream>, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: Arc::new(Mutex::new(WsStreamWrapper::Tcp((stream, addr)))),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_tls(stream: WebSocket<TlsStream<TcpStream>>, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: Arc::new(Mutex::new(WsStreamWrapper::Tls((stream, addr)))),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn get_nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read.load(Ordering::Relaxed)
    }

    pub fn get_nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written.load(Ordering::Relaxed)
    }
}

impl Read for WsTransport {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.read(&mut buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl AsyncRead for WsTransport {}

impl Write for WsTransport {
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

impl AsyncWrite for WsTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.async_shutdown(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "".to_string())),
        }
    }
}

impl Transport for WsTransport {
    fn connect(url: &Url) -> JetFuture<Self>
        where
            Self: Sized,
    {
        let socket_addr = url_to_socket_arr(&url);
        let owned_url = url.clone();
        match url.scheme() {
            "ws" =>
                Box::new(futures::lazy(move || {
                    TcpStream::connect(&socket_addr).map_err(|e| io::Error::new(io::ErrorKind::Other, e.description())).and_then(|stream| {
                        let peer_addr = stream.peer_addr().ok();
                        let client = tungstenite::client(
                            Request {
                                url: owned_url,
                                extra_headers: None,
                            }, stream);
                        match client {
                            Ok((stream, _)) => Box::new(future::lazy(move || {
                                future::ok(WsTransport::new_tcp(stream, peer_addr))
                            })) as JetFuture<Self>,
                            Err(tungstenite::handshake::HandshakeError::Interrupted(e)) =>
                                Box::new(TcpWebSocketClientHandshake(Some(e)).and_then(move |(stream, _)| {
                                    future::ok(WsTransport::new_tcp(stream, peer_addr))
                                })) as JetFuture<Self>,

                            Err(tungstenite::handshake::HandshakeError::Failure(e)) => Box::new(future::lazy(|| {
                                future::err(io::Error::new(io::ErrorKind::Other, e))
                            })) as JetFuture<Self>,
                        }
                    })
                })) as JetFuture<Self>,
            "wss" => {
                let socket = TcpStream::connect(&socket_addr);

                let mut client_config = rustls::ClientConfig::default();
                client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(danger_transport::NoCertificateVerification {}));
                let config_ref = Arc::new(client_config);
                let cx = TlsConnector::from(config_ref);
                let dns_name = webpki::DNSNameRef::try_from_ascii_str("stub_string").unwrap();

                Box::new(socket.and_then(move |socket| {
                    cx.connect(dns_name, socket)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                }).map_err(|e| io::Error::new(io::ErrorKind::Other, e.description())).and_then(|stream| {
                    let peer_addr = stream.get_ref().0.peer_addr().ok();
                    let client = tungstenite::client(
                        Request {
                            url: owned_url,
                            extra_headers: None,
                        }, TlsStream::Client(stream));
                    match client {
                        Ok((stream, _)) => Box::new(future::lazy(move || {
                            future::ok(WsTransport::new_tls(stream, peer_addr))
                        })) as JetFuture<Self>,
                        Err(tungstenite::handshake::HandshakeError::Interrupted(e)) =>
                            Box::new(TlsWebSocketClientHandshake(Some(e)).and_then(move |(stream, _)| {
                                future::ok(WsTransport::new_tls(stream, peer_addr))
                            })) as JetFuture<Self>,

                        Err(tungstenite::handshake::HandshakeError::Failure(e)) => Box::new(future::lazy(|| {
                            future::err(io::Error::new(io::ErrorKind::Other, e))
                        })) as JetFuture<Self>,
                    }
                })) as JetFuture<Self>
            }
            scheme => {
                panic!("Unsuported scheme: {}", scheme);
            }
        }
    }

    fn message_sink(&self) -> JetSinkType<Vec<u8>> {
        Box::new(WsJetSink::new(self.stream.clone(), self.nb_bytes_written.clone()))
    }

    fn message_stream(&self) -> JetStreamType<Vec<u8>> {
        Box::new(WsJetStream::new(self.stream.clone(), self.nb_bytes_read.clone()))
    }
}

struct WsJetStream {
    stream: Arc<Mutex<WsStreamWrapper>>,
    nb_bytes_read: Arc<AtomicU64>,
    packet_interceptor: Option<Box<dyn PacketInterceptor>>,
}

impl WsJetStream {
    fn new(stream: Arc<Mutex<WsStreamWrapper>>, nb_bytes_read: Arc<AtomicU64>) -> Self {
        WsJetStream {
            stream,
            nb_bytes_read,
            packet_interceptor: None,
        }
    }
}

impl Stream for WsJetStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if let Ok(ref mut stream) = self.stream.try_lock() {
            let mut result = Vec::new();
            while result.len() <= TCP_READ_LEN {
                let mut buffer = [0u8; 8192];
                match stream.poll_read(&mut buffer) {
                    Ok(Async::Ready(0)) => {
                        if result.len() > 0 {
                            if let Some(interceptor) = self.packet_interceptor.as_mut() {
                                interceptor.on_new_packet(stream.peer_addr(), &result);
                            }

                            return Ok(Async::Ready(Some(result)));
                        }

                        return Ok(Async::Ready(None))
                    },

                    Ok(Async::Ready(len)) => {
                        self.nb_bytes_read.fetch_add(len as u64, Ordering::SeqCst);
                        debug!("{} bytes read on {}", len, stream.peer_addr().unwrap());
                        if len < buffer.len() {
                            result.extend_from_slice(&buffer[0..len]);
                        } else {
                            result.extend_from_slice(&buffer);
                            continue;
                        }

                        if let Some(interceptor) = self.packet_interceptor.as_mut() {
                            interceptor.on_new_packet(stream.peer_addr(), &result);
                        }

                        return Ok(Async::Ready(Some(result)));
                    }

                    Ok(Async::NotReady) => {
                        if result.len() > 0 {
                            if let Some(interceptor) = self.packet_interceptor.as_mut() {
                                interceptor.on_new_packet(stream.peer_addr(), &result);
                            }

                            return Ok(Async::Ready(Some(result)));
                        }

                        return Ok(Async::NotReady)
                    },

                    Err(e) => {
                        error!("Can't read on socket: {}", e);
                        return Ok(Async::Ready(None));
                    }
                }
            }
            Ok(Async::Ready(Some(result)))
        } else {
            Ok(Async::NotReady)
        }
    }
}

pub struct TcpWebSocketServerHandshake(pub Option<MidHandshake<ServerHandshake<TcpStream, NoCallback>>>);

impl Future for TcpWebSocketServerHandshake {
    type Item = WebSocket<TcpStream>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, Self::Error> {
        let handshake = self.0.take().expect("This should never happen");
        match handshake.handshake() {
            Ok(ws) => Ok(Async::Ready(ws)),
            Err(HandshakeError::Interrupted(m)) => {
                self.0 = Some(m);
                Ok(Async::NotReady)
            }
            Err(HandshakeError::Failure(e)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

pub struct TlsWebSocketServerHandshake(pub Option<MidHandshake<ServerHandshake<TlsStream<TcpStream>, NoCallback>>>);

impl Future for TlsWebSocketServerHandshake {
    type Item = WebSocket<TlsStream<TcpStream>>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, Self::Error> {
        let handshake = self.0.take().expect("This should never happen");
        match handshake.handshake() {
            Ok(ws) => Ok(Async::Ready(ws)),
            Err(HandshakeError::Interrupted(m)) => {
                self.0 = Some(m);
                Ok(Async::NotReady)
            }
            Err(HandshakeError::Failure(e)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

pub struct TcpWebSocketClientHandshake(pub Option<MidHandshake<ClientHandshake<TcpStream>>>);

impl Future for TcpWebSocketClientHandshake {
    type Item = (WebSocket<TcpStream>, Response);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, Self::Error> {
        let handshake = self.0.take().expect("This should never happen");
        match handshake.handshake() {
            Ok(ws) => Ok(Async::Ready(ws)),
            Err(HandshakeError::Interrupted(m)) => {
                self.0 = Some(m);
                Ok(Async::NotReady)
            }
            Err(HandshakeError::Failure(e)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

pub struct TlsWebSocketClientHandshake(pub Option<MidHandshake<ClientHandshake<TlsStream<TcpStream>>>>);

impl Future for TlsWebSocketClientHandshake {
    type Item = (WebSocket<TlsStream<TcpStream>>, Response);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, Self::Error> {
        let handshake = self.0.take().expect("This should never happen");
        match handshake.handshake() {
            Ok(ws) => Ok(Async::Ready(ws)),
            Err(HandshakeError::Interrupted(m)) => {
                self.0 = Some(m);
                Ok(Async::NotReady)
            }
            Err(HandshakeError::Failure(e)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

impl JetStream for WsJetStream {
    fn shutdown(&mut self) -> std::io::Result<()> {
        let mut stream = self.stream.lock().unwrap();
        stream.shutdown()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        let stream = self.stream.lock().unwrap();
        stream.peer_addr()
    }

    fn nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read.load(Ordering::Relaxed)
    }

    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>) {
        self.packet_interceptor = Some(interceptor);
    }
}

struct WsJetSink {
    stream: Arc<Mutex<WsStreamWrapper>>,
    nb_bytes_written: Arc<AtomicU64>,
}

impl WsJetSink {
    fn new(stream: Arc<Mutex<WsStreamWrapper>>, nb_bytes_written: Arc<AtomicU64>) -> Self {
        WsJetSink {
            stream,
            nb_bytes_written,
        }
    }
}

impl Sink for WsJetSink {
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
                        self.nb_bytes_written.fetch_add(len as u64, Ordering::SeqCst);
                        item.drain(0..len);
                        debug!("{} bytes written on {}", len, stream.peer_addr().unwrap())
                    } else {
                        debug!("0 bytes written on {}", stream.peer_addr().unwrap())
                    }

                    if item.is_empty() {
                        Ok(AsyncSink::Ready)
                    } else {
                        futures::task::current().notify();
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

impl JetSink for WsJetSink {
    fn shutdown(&mut self) -> std::io::Result<()> {
        let mut stream = self.stream.lock().unwrap();
        stream.shutdown()
    }

    fn nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written.load(Ordering::Relaxed)
    }
}


fn tungstenite_err_to_io_err(err: tungstenite::Error) -> io::Error {
    match err {
        tungstenite::Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::Other, other.description()),
    }
}
