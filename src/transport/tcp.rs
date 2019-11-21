use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use slog_scope::{error, trace};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_rustls::{TlsConnector, TlsStream};
use tokio_tcp::TcpStream;
use url::Url;

use crate::interceptor::PacketInterceptor;
use crate::transport::{JetFuture, JetSink, JetSinkType, JetStream, JetStreamType, Transport};
use crate::utils::{danger_transport, url_to_socket_arr};

pub const TCP_READ_LEN: usize = 57343;

pub enum TcpStreamWrapper {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl TcpStreamWrapper {
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            TcpStreamWrapper::Plain(stream) => stream.peer_addr().ok(),
            TcpStreamWrapper::Tls(stream) => stream.get_ref().0.peer_addr().ok(),
        }
    }

    pub fn async_shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self {
            TcpStreamWrapper::Plain(stream) => AsyncWrite::shutdown(stream),
            TcpStreamWrapper::Tls(stream) => AsyncWrite::shutdown(stream),
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
    stream: TcpStreamWrapper,
    nb_bytes_read: Arc<AtomicU64>,
    nb_bytes_written: Arc<AtomicU64>,
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> Self {
        TcpTransport {
            stream: TcpStreamWrapper::Plain(stream),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_tls(stream: TlsStream<TcpStream>) -> Self {
        TcpTransport {
            stream: TcpStreamWrapper::Tls(stream),
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

impl Read for TcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl AsyncRead for TcpTransport {}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(&buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl AsyncWrite for TcpTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        self.stream.async_shutdown()
    }
}

impl Transport for TcpTransport {
    fn connect(url: &Url) -> JetFuture<Self>
    where
        Self: Sized,
    {
        let socket_addr = url_to_socket_arr(&url);
        match url.scheme() {
            "tcp" => Box::new(TcpStream::connect(&socket_addr).map(TcpTransport::new)),
            "tls" => {
                let socket = TcpStream::connect(&socket_addr);

                let mut client_config = rustls::ClientConfig::default();
                client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(danger_transport::NoCertificateVerification {}));
                let config_ref = Arc::new(client_config);
                let tls_connector = TlsConnector::from(config_ref);
                let dns_name = webpki::DNSNameRef::try_from_ascii_str("stub_string").unwrap();

                let tls_handshake = socket.and_then(move |socket| {
                    tls_connector
                        .connect(dns_name, socket)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                });
                let request =
                    tls_handshake.map(|stream| TcpTransport::new_tls(tokio_rustls::TlsStream::Client(stream)));

                Box::new(request)
            }
            scheme => {
                panic!("Unsupported scheme: {}", scheme);
            }
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.peer_addr()
    }

    fn split_transport(self) -> (JetStreamType<Vec<u8>>, JetSinkType<Vec<u8>>) {
        let peer_addr = self.peer_addr();
        let (reader, writer) = self.stream.split();

        let stream = Box::new(TcpJetStream::new(reader, self.nb_bytes_read, peer_addr.clone()));
        let sink = Box::new(TcpJetSink::new(writer, self.nb_bytes_written, peer_addr));

        (stream, sink)
    }
}

struct TcpJetStream {
    stream: ReadHalf<TcpStreamWrapper>,
    nb_bytes_read: Arc<AtomicU64>,
    packet_interceptor: Option<Box<dyn PacketInterceptor>>,
    buffer: Vec<u8>,
    peer_addr: Option<SocketAddr>,
}

impl TcpJetStream {
    fn new(stream: ReadHalf<TcpStreamWrapper>, nb_bytes_read: Arc<AtomicU64>, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            stream,
            nb_bytes_read,
            packet_interceptor: None,
            buffer: vec![0; 8192],
            peer_addr,
        }
    }
}

impl Stream for TcpJetStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut result = Vec::new();
        while result.len() <= TCP_READ_LEN {
            match self.stream.poll_read(&mut self.buffer) {
                Ok(Async::Ready(0)) => {
                    if result.len() > 0 {
                        if let Some(interceptor) = self.packet_interceptor.as_mut() {
                            interceptor.on_new_packet(self.peer_addr, &result);
                        }

                        return Ok(Async::Ready(Some(result)));
                    }

                    return Ok(Async::Ready(None));
                }

                Ok(Async::Ready(len)) => {
                    self.nb_bytes_read.fetch_add(len as u64, Ordering::SeqCst);
                    trace!(
                        "{} bytes read on {}",
                        len,
                        self.peer_addr.map_or("Unknown".to_string(), |addr| addr.to_string())
                    );

                    result.extend_from_slice(&self.buffer[..len]);
                    if len == self.buffer.len() {
                        continue;
                    }

                    if let Some(interceptor) = self.packet_interceptor.as_mut() {
                        interceptor.on_new_packet(self.peer_addr, &result);
                    }

                    return Ok(Async::Ready(Some(result)));
                }

                Ok(Async::NotReady) => {
                    if result.len() > 0 {
                        if let Some(interceptor) = self.packet_interceptor.as_mut() {
                            interceptor.on_new_packet(self.peer_addr, &result);
                        }

                        return Ok(Async::Ready(Some(result)));
                    }

                    return Ok(Async::NotReady);
                }

                Err(e) => {
                    error!("Can't read on socket: {}", e);

                    return Ok(Async::Ready(None));
                }
            }
        }

        Ok(Async::Ready(Some(result)))
    }
}

impl JetStream for TcpJetStream {
    fn nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read.load(Ordering::Relaxed)
    }

    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>) {
        self.packet_interceptor = Some(interceptor);
    }
}

struct TcpJetSink {
    stream: WriteHalf<TcpStreamWrapper>,
    nb_bytes_written: Arc<AtomicU64>,
    peer_addr: Option<SocketAddr>,
}

impl TcpJetSink {
    fn new(
        stream: WriteHalf<TcpStreamWrapper>,
        nb_bytes_written: Arc<AtomicU64>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        TcpJetSink {
            stream,
            nb_bytes_written,
            peer_addr,
        }
    }
}

impl Sink for TcpJetSink {
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    fn start_send(&mut self, mut item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        trace!(
            "{} bytes to write on {}",
            item.len(),
            self.peer_addr.map_or("Unknown".to_string(), |addr| addr.to_string())
        );
        match self.stream.poll_write(&item) {
            Ok(Async::Ready(len)) => {
                if len > 0 {
                    self.nb_bytes_written.fetch_add(len as u64, Ordering::SeqCst);
                    item.drain(..len);
                }
                trace!(
                    "{} bytes written on {}",
                    len,
                    self.peer_addr.map_or("Unknown".to_string(), |addr| addr.to_string())
                );

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
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_flush()
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl JetSink for TcpJetSink {
    fn nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written.load(Ordering::Relaxed)
    }
}
