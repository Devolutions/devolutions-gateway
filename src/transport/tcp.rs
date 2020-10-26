use std::{
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
    task::{Poll, Context},
    pin::Pin,
};

use spsc_bip_buffer::{BipBufferReader, BipBufferWriter};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{
    rustls,
    TlsConnector,
    TlsStream,
};
use url::Url;

use crate::{
    transport::{JetFuture, JetSinkImpl, JetSinkType, JetStreamImpl, JetStreamType, Transport},
    utils::{danger_transport, resolve_url_to_socket_arr},
};
use futures::{
    FutureExt,
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

    pub fn async_shutdown(mut self: Pin<&mut Self>,
                          cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TcpStreamWrapper::Plain(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
            TcpStreamWrapper::Tls(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl AsyncRead for TcpStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TcpStreamWrapper::Plain(ref mut stream) => {
                Pin::new(stream).poll_read(cx, buf)
            }
            TcpStreamWrapper::Tls(ref mut stream) => {
                Pin::new(stream).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for TcpStreamWrapper {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            TcpStreamWrapper::Plain(ref mut stream) => {
                Pin::new(stream).poll_write(cx, buf)
            }
            TcpStreamWrapper::Tls(ref mut stream) => {
                Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TcpStreamWrapper::Plain(ref mut stream) => {
                Pin::new(stream).poll_flush(cx)
            }
            TcpStreamWrapper::Tls(ref mut stream) => {
                Pin::new(stream).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TcpStreamWrapper::Plain(ref mut stream) => {
                Pin::new(stream).poll_shutdown(cx)
            }
            TcpStreamWrapper::Tls(ref mut stream) => {
                Pin::new(stream).poll_shutdown(cx)
            }
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

impl AsyncRead for TcpTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpTransport {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl TcpTransport {
    async fn create_connect_impl_future(url: Url) -> Result<TcpTransport, std::io::Error>
    {
        let socket_addr = resolve_url_to_socket_arr(&url).await
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("couldn't resolve {}", url)
                )
            })?;

        match url.scheme() {
            "tcp" => TcpStream::connect(&socket_addr).await.map(TcpTransport::new),
            "tls" => {
                let socket = TcpStream::connect(&socket_addr).await?;

                let mut client_config = tokio_rustls::rustls::ClientConfig::default();
                client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(danger_transport::NoCertificateVerification {}));
                let config_ref = Arc::new(client_config);
                // todo: update rustls repo
                let tls_connector = TlsConnector::from(config_ref);
                let dns_name = webpki::DNSNameRef::try_from_ascii_str("stub_string").unwrap();

                let tls_handshake = tls_connector.connect(dns_name, socket).await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                Ok(TcpTransport::new_tls(TlsStream::Client(tls_handshake)))
            }
            scheme => {
                panic!("Unsupported scheme: {}", scheme);
            }
        }
    }
}

impl Transport for TcpTransport {
    fn connect(addr: &Url) -> JetFuture<Self> {
        // TODO: figure out how to do that without cloning
        Box::new(Self::create_connect_impl_future(addr.clone()))
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
        let (reader, writer) = tokio::io::split(self.stream);

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
