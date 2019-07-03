use crate::interceptor::PacketInterceptor;
use crate::transport::tcp::TcpTransport;
use futures::{Async, Future, Sink, Stream};
use std::io::{Read, Write};
use std::net::SocketAddr;
use tokio::io;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::TcpStream;
use url::Url;

pub mod mcs;
pub mod tcp;
pub mod tsrequest;
pub mod x224;

pub type JetFuture<T> = Box<dyn Future<Item = T, Error = io::Error> + Send>;
pub type JetStreamType<T> = Box<dyn JetStream<Item = T, Error = io::Error> + Send>;
pub type JetSinkType<T> = Box<dyn JetSink<SinkItem = T, SinkError = io::Error> + Send>;

pub trait Transport {
    fn connect(addr: &Url) -> JetFuture<Self>
    where
        Self: Sized;
    fn message_sink(&self) -> JetSinkType<Vec<u8>>;
    fn message_stream(&self) -> JetStreamType<Vec<u8>>;
}

pub enum JetTransport {
    Tcp(TcpTransport),
}

impl JetTransport {
    pub fn new_tcp(stream: TcpStream) -> Self {
        JetTransport::Tcp(TcpTransport::new(stream))
    }
}

impl Clone for JetTransport {
    fn clone(&self) -> Self {
        match self {
            JetTransport::Tcp(tcp_transport) => JetTransport::Tcp(tcp_transport.clone()),
        }
    }
}

impl Transport for JetTransport {
    fn connect(_url: &Url) -> JetFuture<Self>
    where
        Self: Sized,
    {
        // TODO
        unimplemented!()
    }

    fn message_sink(&self) -> JetSinkType<Vec<u8>> {
        match self {
            JetTransport::Tcp(tcp_transport) => tcp_transport.message_sink(),
        }
    }

    fn message_stream(&self) -> JetStreamType<Vec<u8>> {
        match self {
            JetTransport::Tcp(tcp_transport) => tcp_transport.message_stream(),
        }
    }
}

impl Read for JetTransport {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self {
            JetTransport::Tcp(ref mut tcp_transport) => tcp_transport.read(&mut buf),
        }
    }
}
impl AsyncRead for JetTransport {}

impl Write for JetTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            JetTransport::Tcp(ref mut tcp_transport) => tcp_transport.write(&buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            JetTransport::Tcp(ref mut tcp_transport) => Write::flush(tcp_transport),
        }
    }
}

impl AsyncWrite for JetTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self {
            JetTransport::Tcp(ref mut tcp_transport) => AsyncWrite::shutdown(tcp_transport),
        }
    }
}

pub trait JetStream: Stream {
    fn shutdown(&self) -> std::io::Result<()>;
    fn peer_addr(&self) -> std::io::Result<SocketAddr>;
    fn nb_bytes_read(&self) -> u64;
    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>);
}

pub trait JetSink: Sink {
    fn shutdown(&self) -> std::io::Result<()>;
    fn nb_bytes_written(&self) -> u64;
}
