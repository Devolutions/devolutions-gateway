use std::io::Cursor;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use futures::future;
use futures::{Async, Future};
use hyper::upgrade::Upgraded;
use spsc_bip_buffer::{BipBufferReader, BipBufferWriter};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::TlsStream;
use tungstenite::handshake::client::{Request, Response};
use tungstenite::handshake::server::NoCallback;
use tungstenite::handshake::MidHandshake;
use tungstenite::protocol::Role;
use tungstenite::Message;
use tungstenite::{ClientHandshake, HandshakeError, ServerHandshake, WebSocket};
use url::Url;

use crate::transport::{JetFuture, JetSinkImpl, JetSinkType, JetStreamImpl, JetStreamType, Transport};
use crate::utils::{danger_transport, url_to_socket_arr};

pub struct WsStream {
    inner: WsStreamWrapper,
    previous_message: Option<Cursor<Vec<u8>>>,
}

impl WsStream {
    #[inline]
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }

    #[inline]
    pub fn async_shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        self.inner.async_shutdown()
    }
}

impl From<WsStreamWrapper> for WsStream {
    fn from(wrapper: WsStreamWrapper) -> Self {
        WsStream {
            inner: wrapper,
            previous_message: None,
        }
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.previous_message {
            Some(message) => {
                let remaining_len = (message.get_ref().len() as u64) - message.position();

                let read_size = message.read(buf)?;

                slog_scope::trace!(
                    "Read an old message. remaining_len={}, buf_len={}, read_len={}",
                    remaining_len,
                    buf.len(),
                    read_size
                );

                if message.position() == message.get_ref().len() as u64 {
                    slog_scope::trace!("Old message is completely read");
                    self.previous_message = None;
                }

                Ok(read_size)
            }
            None => {
                let message_result = match self.inner {
                    WsStreamWrapper::Http((ref mut stream, _)) => stream.read_message(),
                    WsStreamWrapper::Tcp((ref mut stream, _)) => stream.read_message(),
                    WsStreamWrapper::Tls((ref mut stream, _)) => stream.read_message(),
                };

                let message = message_result.map_err(tungstenite_err_to_io_err)?;

                slog_scope::trace!(
                    "New message received: {} - len={}",
                    match message {
                        Message::Text(_) => "Text",
                        Message::Binary(_) => "Binary",
                        Message::Ping(_) => "Ping",
                        Message::Pong(_) => "Pong",
                        Message::Close(_) => "Close",
                    },
                    message.len()
                );

                if (message.is_binary() || message.is_text()) && !message.is_empty() {
                    let mut message = Cursor::new(message.into_data());
                    let read_size = message.read(buf)?;
                    if message.position() < message.get_ref().len() as u64 {
                        slog_scope::trace!(
                            "Message can't be totally read. buf_len={}, read_len={}",
                            buf.len(),
                            read_size
                        );
                        self.previous_message = Some(message);
                    } else {
                        slog_scope::trace!("Message completely read.");
                    }

                    Ok(read_size)
                } else {
                    Err(io::Error::new(ErrorKind::WouldBlock, "No Data"))
                }
            }
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let message = Message::Binary(buf.to_vec());

        let result = match self.inner {
            WsStreamWrapper::Http((ref mut stream, _)) => {
                stream.write_message(message).map_err(tungstenite_err_to_io_err)
            }
            WsStreamWrapper::Tcp((ref mut stream, ref mut _addr)) => {
                stream.write_message(message).map_err(tungstenite_err_to_io_err)
            }
            WsStreamWrapper::Tls((ref mut stream, ref mut _addr)) => {
                stream.write_message(message).map_err(tungstenite_err_to_io_err)
            }
        };

        match result {
            Ok(()) => Ok(buf.len()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // tungstenite already buffers the message, so we need to return buf.len() anyway
                // because otherwise bip buffer in JetSinkImpl's Sink implementation doesn't mark
                // data as consumed even though it is. We should arrange for the current task (via
                // `cx.waker()`) to receive a notification when the object becomes readable or is closed.
                // This is normally done by returning io::Error with WouldBlock, but we can't because
                // otherwise consumed part of the bip buffer isn't marked as consumed.
                // Accordingly, if you need to wait an undetermined amount of time before receiving
                // the remaining part of your message, the reason is probably right here.
                // Our best bet is to couple tightly the bip buffer with the tungstenite websocket
                // so that we can consume out of the bip buffer all the message now buffered in the tungstenite websocket
                // while returning a WouldBlock for rescheduling.
                // We may have a look at PollEvented (https://docs.rs/tokio/0.1.22/tokio/reactor/struct.PollEvented2.html)
                // as well.
                Ok(buf.len())
            }
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner {
            WsStreamWrapper::Http((ref mut stream, _)) => {
                stream.write_pending().map(|_| ()).map_err(tungstenite_err_to_io_err)
            }
            WsStreamWrapper::Tcp((ref mut stream, _)) => {
                stream.write_pending().map(|_| ()).map_err(tungstenite_err_to_io_err)
            }
            WsStreamWrapper::Tls((ref mut stream, ref mut _addr)) => {
                stream.write_pending().map(|_| ()).map_err(tungstenite_err_to_io_err)
            }
        }
    }
}

impl AsyncRead for WsStream {}

impl AsyncWrite for WsStream {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self.inner {
            WsStreamWrapper::Http((ref mut stream, _)) => stream
                .close(None)
                .map(|_| Async::Ready(()))
                .map_err(tungstenite_err_to_io_err),
            WsStreamWrapper::Tcp((ref mut stream, _)) => stream
                .close(None)
                .map(|_| Async::Ready(()))
                .map_err(tungstenite_err_to_io_err),
            WsStreamWrapper::Tls((ref mut stream, _)) => stream
                .close(None)
                .map(|_| Async::Ready(()))
                .map_err(tungstenite_err_to_io_err),
        }
    }
}

pub enum WsStreamWrapper {
    Http((WebSocket<Upgraded>, Option<SocketAddr>)),
    Tcp((WebSocket<TcpStream>, Option<SocketAddr>)),
    Tls((WebSocket<TlsStream<TcpStream>>, Option<SocketAddr>)),
}

impl WsStreamWrapper {
    #[inline]
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            WsStreamWrapper::Http((_stream, addr)) => *addr,
            WsStreamWrapper::Tcp((_stream, addr)) => *addr,
            WsStreamWrapper::Tls((_stream, addr)) => *addr,
        }
    }

    #[inline]
    pub fn async_shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self {
            WsStreamWrapper::Http((stream, _)) => stream
                .close(None)
                .map(|()| Async::Ready(()))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            WsStreamWrapper::Tcp((stream, _)) => stream
                .close(None)
                .map(|()| Async::Ready(()))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            WsStreamWrapper::Tls((stream, _)) => stream
                .close(None)
                .map(|()| Async::Ready(()))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

pub struct WsTransport {
    stream: WsStream,
    nb_bytes_read: Arc<AtomicU64>,
    nb_bytes_written: Arc<AtomicU64>,
}

impl WsTransport {
    pub fn new_http(upgraded: Upgraded, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: WsStreamWrapper::Http((WebSocket::from_raw_socket(upgraded, Role::Server, None), addr)).into(),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_tcp(stream: WebSocket<TcpStream>, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: WsStreamWrapper::Tcp((stream, addr)).into(),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_tls(stream: WebSocket<TlsStream<TcpStream>>, addr: Option<SocketAddr>) -> Self {
        WsTransport {
            stream: WsStreamWrapper::Tls((stream, addr)).into(),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn clone_nb_bytes_read(&self) -> Arc<AtomicU64> {
        self.nb_bytes_read.clone()
    }

    pub fn clone_nb_bytes_written(&self) -> Arc<AtomicU64> {
        self.nb_bytes_written.clone()
    }
}

impl Read for WsTransport {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(&mut buf)
    }
}

impl AsyncRead for WsTransport {}

impl Write for WsTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(&buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl AsyncWrite for WsTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        self.stream.async_shutdown()
    }
}

impl Transport for WsTransport {
    fn connect(url: &Url) -> JetFuture<Self>
    where
        Self: Sized,
    {
        let socket_addr = url_to_socket_arr(&url);

        let request = match Request::builder().uri(url.as_str()).body(()) {
            Ok(req) => req,
            Err(e) => {
                return Box::new(future::lazy(|| future::err(io::Error::new(io::ErrorKind::Other, e))))
                    as JetFuture<Self>;
            }
        };

        match url.scheme() {
            "ws" => Box::new(futures::lazy(move || {
                TcpStream::connect(&socket_addr)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                    .and_then(|stream| {
                        let peer_addr = stream.peer_addr().ok();
                        match tungstenite::client(request, stream) {
                            Ok((stream, _)) => Box::new(future::lazy(move || {
                                future::ok(WsTransport::new_tcp(stream, peer_addr))
                            })) as JetFuture<Self>,
                            Err(tungstenite::handshake::HandshakeError::Interrupted(e)) => Box::new(
                                TcpWebSocketClientHandshake(Some(e))
                                    .and_then(move |(stream, _)| future::ok(WsTransport::new_tcp(stream, peer_addr))),
                            )
                                as JetFuture<Self>,

                            Err(tungstenite::handshake::HandshakeError::Failure(e)) => {
                                Box::new(future::lazy(|| future::err(io::Error::new(io::ErrorKind::Other, e))))
                                    as JetFuture<Self>
                            }
                        }
                    })
            })) as JetFuture<Self>,
            "wss" => {
                let socket = TcpStream::connect(&socket_addr);

                let mut client_config = rustls::ClientConfig::default();
                client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(danger_transport::NoCertificateVerification));
                let config_ref = Arc::new(client_config);
                let cx = TlsConnector::from(config_ref);
                let dns_name = webpki::DNSNameRef::try_from_ascii_str("stub_string").unwrap();

                Box::new(
                    socket
                        .and_then(move |socket| {
                            cx.connect(dns_name, socket)
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                        })
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                        .and_then(|stream| {
                            let peer_addr = stream.get_ref().0.peer_addr().ok();
                            match tungstenite::client(request, TlsStream::Client(stream)) {
                                Ok((stream, _)) => Box::new(future::lazy(move || {
                                    future::ok(WsTransport::new_tls(stream, peer_addr))
                                })) as JetFuture<Self>,
                                Err(tungstenite::handshake::HandshakeError::Interrupted(e)) => {
                                    Box::new(TlsWebSocketClientHandshake(Some(e)).and_then(move |(stream, _)| {
                                        future::ok(WsTransport::new_tls(stream, peer_addr))
                                    })) as JetFuture<Self>
                                }

                                Err(tungstenite::handshake::HandshakeError::Failure(e)) => {
                                    Box::new(future::lazy(|| future::err(io::Error::new(io::ErrorKind::Other, e))))
                                        as JetFuture<Self>
                                }
                            }
                        }),
                ) as JetFuture<Self>
            }
            scheme => {
                panic!("Unsupported scheme: {}", scheme);
            }
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.peer_addr()
    }

    fn split_transport(
        self,
        buffer_writer: BipBufferWriter,
        buffer_reader: BipBufferReader,
    ) -> (JetStreamType<usize>, JetSinkType<usize>) {
        let peer_addr = self.peer_addr();
        let (reader, writer) = self.stream.split();

        let stream = Box::new(JetStreamImpl::new(reader, self.nb_bytes_read, peer_addr, buffer_writer));
        let sink = Box::new(JetSinkImpl::new(
            writer,
            self.nb_bytes_written,
            peer_addr,
            buffer_reader,
        ));

        (stream, sink)
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
            Err(HandshakeError::Failure(e)) => Err(io::Error::new(io::ErrorKind::Other, e)),
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
            Err(HandshakeError::Failure(e)) => Err(io::Error::new(io::ErrorKind::Other, e)),
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
            Err(HandshakeError::Failure(e)) => Err(io::Error::new(io::ErrorKind::Other, e)),
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
            Err(HandshakeError::Failure(e)) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}

fn tungstenite_err_to_io_err(err: tungstenite::Error) -> io::Error {
    match err {
        tungstenite::Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::Other, other),
    }
}
