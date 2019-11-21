use std::{
    io::{Read, Write},
    net::SocketAddr,
    sync::{atomic::AtomicU64, Arc},
};

use futures::{Async, Future, Sink, Stream};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio_tcp::TcpStream;
use url::Url;

use crate::interceptor::PacketInterceptor;
use crate::transport::tcp::TcpTransport;
use crate::transport::ws::WsTransport;

pub mod mcs;
pub mod tcp;
pub mod tsrequest;
pub mod ws;
pub mod x224;

pub type JetFuture<T> = Box<dyn Future<Item = T, Error = io::Error> + Send>;
pub type JetStreamType<T> = Box<dyn JetStream<Item = T, Error = io::Error> + Send>;
pub type JetSinkType<T> = Box<dyn JetSink<SinkItem = T, SinkError = io::Error> + Send>;

pub trait Transport {
    fn connect(addr: &Url) -> JetFuture<Self>
    where
        Self: Sized;
    fn peer_addr(&self) -> Option<SocketAddr>;
    fn split_transport(self) -> (JetStreamType<Vec<u8>>, JetSinkType<Vec<u8>>);
}

pub enum JetTransport {
    Tcp(TcpTransport),
    Ws(WsTransport),
}

impl JetTransport {
    pub fn new_tcp(stream: TcpStream) -> Self {
        JetTransport::Tcp(TcpTransport::new(stream))
    }

    pub fn clone_nb_bytes_read(&self) -> Arc<AtomicU64> {
        match self {
            JetTransport::Tcp(tcp_transport) => tcp_transport.clone_nb_bytes_read(),
            JetTransport::Ws(ws_transport) => ws_transport.clone_nb_bytes_read(),
        }
    }

    pub fn clone_nb_bytes_written(&self) -> Arc<AtomicU64> {
        match self {
            JetTransport::Tcp(tcp_transport) => tcp_transport.clone_nb_bytes_written(),
            JetTransport::Ws(ws_transport) => ws_transport.clone_nb_bytes_written(),
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

    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            JetTransport::Tcp(tcp_transport) => tcp_transport.peer_addr(),
            JetTransport::Ws(ws_transport) => ws_transport.peer_addr(),
        }
    }

    fn split_transport(self) -> (JetStreamType<Vec<u8>>, JetSinkType<Vec<u8>>) {
        match self {
            JetTransport::Tcp(tcp_transport) => tcp_transport.split_transport(),
            JetTransport::Ws(ws_transport) => ws_transport.split_transport(),
        }
    }
}

impl Read for JetTransport {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self {
            JetTransport::Tcp(ref mut tcp_transport) => tcp_transport.read(&mut buf),
            JetTransport::Ws(ref mut ws_transport) => ws_transport.read(&mut buf),
        }
    }
}

impl AsyncRead for JetTransport {}

impl Write for JetTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            JetTransport::Tcp(ref mut tcp_transport) => tcp_transport.write(&buf),
            JetTransport::Ws(ref mut ws_transport) => ws_transport.write(&buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            JetTransport::Tcp(ref mut tcp_transport) => Write::flush(tcp_transport),
            JetTransport::Ws(ref mut ws_transport) => Write::flush(ws_transport),
        }
    }
}

impl AsyncWrite for JetTransport {
    fn shutdown(&mut self) -> Result<Async<()>, std::io::Error> {
        match self {
            JetTransport::Tcp(ref mut tcp_transport) => AsyncWrite::shutdown(tcp_transport),
            JetTransport::Ws(ref mut ws_transport) => AsyncWrite::shutdown(ws_transport),
        }
    }
}

pub trait JetStream: Stream {
    fn nb_bytes_read(&self) -> u64;
    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>);
}

pub trait JetSink: Sink {
    fn nb_bytes_written(&self) -> u64;
}
