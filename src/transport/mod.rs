use std::io::{Read, Write};
use futures::{Async, Future, Sink, Stream};
use tokio::io;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::TcpStream;
use url::Url;

use crate::transport::tcp::TcpTransport;

pub mod tcp;

pub type JetFuture<T> = Box<Future<Item = T, Error = io::Error> + Send>;
pub type JetStream<T> = Box<Stream<Item = T, Error = io::Error> + Send>;
pub type JetSink<T> = Box<Sink<SinkItem = T, SinkError = io::Error> + Send>;

pub trait Transport {
    fn connect(addr: &Url) -> JetFuture<Self>
    where
        Self: Sized;
    fn message_sink(&self) -> JetSink<Vec<u8>>;
    fn message_stream(&self) -> JetStream<Vec<u8>>;
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
    fn connect(_addr: &Url) -> JetFuture<Self>
    where
        Self: Sized,
    {
        //TODO
        unimplemented!()
    }

    fn message_sink(&self) -> JetSink<Vec<u8>> {
        match self {
            JetTransport::Tcp(tcp_transport) => tcp_transport.message_sink(),
        }
    }

    fn message_stream(&self) -> JetStream<Vec<u8>> {
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
