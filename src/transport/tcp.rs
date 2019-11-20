use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use slog_scope::{error, trace};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio_io::{AsyncRead, AsyncWrite};
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

    pub fn shutdown(&self) -> std::io::Result<()> {
        match self {
            TcpStreamWrapper::Plain(stream) => TcpStream::shutdown(stream, std::net::Shutdown::Both),
            TcpStreamWrapper::Tls(stream) => stream.get_ref().0.shutdown(std::net::Shutdown::Both),
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

#[derive(Clone)]
pub struct TcpTransport {
    stream: Arc<Mutex<TcpStreamWrapper>>,
    nb_bytes_read: Arc<AtomicU64>,
    nb_bytes_written: Arc<AtomicU64>,
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> Self {
        TcpTransport {
            stream: Arc::new(Mutex::new(TcpStreamWrapper::Plain(stream))),
            nb_bytes_read: Arc::new(AtomicU64::new(0)),
            nb_bytes_written: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_tls(stream: TlsStream<TcpStream>) -> Self {
        TcpTransport {
            stream: Arc::new(Mutex::new(TcpStreamWrapper::Tls(stream))),
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

impl Read for TcpTransport {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.read(&mut buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "The stream is not ready")),
        }
    }
}

impl AsyncRead for TcpTransport {}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.write(&buf),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "The stream is not ready")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.flush(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "The stream is not ready")),
        }
    }
}

impl AsyncWrite for TcpTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self.stream.try_lock() {
            Ok(mut stream) => stream.async_shutdown(),
            Err(_) => Err(io::Error::new(io::ErrorKind::WouldBlock, "The stream is not ready")),
        }
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

    fn message_sink(&self) -> JetSinkType<Vec<u8>> {
        Box::new(TcpJetSink::new(self.stream.clone(), self.nb_bytes_written.clone()))
    }

    fn message_stream(&self) -> JetStreamType<Vec<u8>> {
        Box::new(TcpJetStream::new(self.stream.clone(), self.nb_bytes_read.clone()))
    }
}

struct TcpJetStream {
    stream: Arc<Mutex<TcpStreamWrapper>>,
    nb_bytes_read: Arc<AtomicU64>,
    packet_interceptor: Option<Box<dyn PacketInterceptor>>,
    buffer: Vec<u8>,
}

impl TcpJetStream {
    fn new(stream: Arc<Mutex<TcpStreamWrapper>>, nb_bytes_read: Arc<AtomicU64>) -> Self {
        TcpJetStream {
            stream,
            nb_bytes_read,
            packet_interceptor: None,
            buffer: vec![0; 8192],
        }
    }
}

impl Stream for TcpJetStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Ok(ref mut stream) = self.stream.try_lock() {
            let mut result = Vec::new();
            while result.len() <= TCP_READ_LEN {
                match stream.poll_read(&mut self.buffer) {
                    Ok(Async::Ready(0)) => {
                        if result.len() > 0 {
                            if let Some(interceptor) = self.packet_interceptor.as_mut() {
                                interceptor.on_new_packet(stream.peer_addr(), &result);
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
                            stream
                                .peer_addr()
                                .map_or("Unknown".to_string(), |addr| addr.to_string())
                        );

                        if len < self.buffer.len() {
                            result.extend_from_slice(&self.buffer[0..len]);
                        } else {
                            result.extend_from_slice(&self.buffer);

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

                        return Ok(Async::NotReady);
                    }

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

impl JetStream for TcpJetStream {
    fn shutdown(&mut self) -> std::io::Result<()> {
        let stream = self.stream.lock().unwrap();

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

struct TcpJetSink {
    stream: Arc<Mutex<TcpStreamWrapper>>,
    nb_bytes_written: Arc<AtomicU64>,
}

impl TcpJetSink {
    fn new(stream: Arc<Mutex<TcpStreamWrapper>>, nb_bytes_written: Arc<AtomicU64>) -> Self {
        TcpJetSink {
            stream,
            nb_bytes_written,
        }
    }
}

impl Sink for TcpJetSink {
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    fn start_send(&mut self, mut item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            trace!(
                "{} bytes to write on {}",
                item.len(),
                stream
                    .peer_addr()
                    .map_or("Unknown".to_string(), |addr| addr.to_string())
            );
            match stream.poll_write(&item) {
                Ok(Async::Ready(len)) => {
                    if len > 0 {
                        self.nb_bytes_written.fetch_add(len as u64, Ordering::SeqCst);
                        item.drain(0..len);
                    }
                    trace!(
                        "{} bytes written on {}",
                        len,
                        stream
                            .peer_addr()
                            .map_or("Unknown".to_string(), |addr| addr.to_string())
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
        } else {
            Ok(AsyncSink::NotReady(item))
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        if let Ok(mut stream) = self.stream.try_lock() {
            stream.poll_flush()
        } else {
            Ok(Async::NotReady)
        }
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl JetSink for TcpJetSink {
    fn shutdown(&mut self) -> std::io::Result<()> {
        let stream = self.stream.lock().unwrap();

        stream.shutdown()
    }

    fn nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written.load(Ordering::Relaxed)
    }
}
