use std::{
    io::{Read, Write},
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use futures::{Async, Future};
use spsc_bip_buffer::{BipBufferReader, BipBufferWriter};
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    net::tcp::TcpStream,
};
use tokio_rustls::{TlsConnector, TlsStream};
use url::Url;

use crate::{
    transport::{JetFuture, JetSinkImpl, JetSinkType, JetStreamImpl, JetStreamType, Transport},
    utils::{danger_transport, url_to_socket_arr},
};

#[allow(clippy::large_enum_variant)]
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
