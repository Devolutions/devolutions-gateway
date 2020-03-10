use std::{
    io::{Read, Write},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use slog_scope::{error, trace};
use spsc_bip_buffer::{BipBufferReader, BipBufferWriter};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::tcp::TcpStream;
use url::Url;

use crate::interceptor::PacketInterceptor;
use crate::transport::{tcp::TcpTransport, ws::WsTransport};

pub mod fast_path;
pub mod mcs;
pub mod rdp;
pub mod tcp;
pub mod tsrequest;
pub mod ws;
pub mod x224;

pub type JetFuture<T> = Box<dyn Future<Item = T, Error = io::Error> + Send>;
pub type JetStreamType<T> = Box<dyn JetStream<Item = T, Error = io::Error> + Send>;
pub type JetSinkType<T> = Box<dyn JetSink<SinkItem = T, SinkError = io::Error> + Send>;

pub const BIP_BUFFER_LEN: usize = 8 * PART_LEN;
const PART_LEN: usize = 16 * 1024;

pub trait Transport {
    fn connect(addr: &Url) -> JetFuture<Self>
    where
        Self: Sized;
    fn peer_addr(&self) -> Option<SocketAddr>;
    fn split_transport(
        self,
        buffer_writer: BipBufferWriter,
        buffer_reader: BipBufferReader,
    ) -> (JetStreamType<usize>, JetSinkType<usize>);
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

    fn split_transport(
        self,
        buffer_writer: BipBufferWriter,
        buffer_reader: BipBufferReader,
    ) -> (JetStreamType<usize>, JetSinkType<usize>) {
        match self {
            JetTransport::Tcp(tcp_transport) => tcp_transport.split_transport(buffer_writer, buffer_reader),
            JetTransport::Ws(ws_transport) => ws_transport.split_transport(buffer_writer, buffer_reader),
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
    fn finished(&mut self) -> bool;
}

struct JetStreamImpl<T: AsyncRead> {
    stream: ReadHalf<T>,
    nb_bytes_read: Arc<AtomicU64>,
    packet_interceptor: Option<Box<dyn PacketInterceptor>>,
    peer_addr: Option<SocketAddr>,
    peer_addr_str: String,
    buffer: BipBufferWriter,
}

impl<T: AsyncRead> JetStreamImpl<T> {
    fn new(
        stream: ReadHalf<T>,
        nb_bytes_read: Arc<AtomicU64>,
        peer_addr: Option<SocketAddr>,
        buffer: BipBufferWriter,
    ) -> Self {
        Self {
            stream,
            nb_bytes_read,
            packet_interceptor: None,
            peer_addr,
            peer_addr_str: peer_addr.clone().map_or("Unknown".to_string(), |addr| addr.to_string()),
            buffer,
        }
    }
}

impl<T: AsyncRead> Stream for JetStreamImpl<T> {
    type Item = usize;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let peer_addr = &self.peer_addr_str;
        let mut written = 0;
        loop {
            if let Some(mut reservation) = self.buffer.reserve(PART_LEN) {
                match self.stream.poll_read(reservation.as_mut()) {
                    Ok(Async::Ready(0)) => {
                        return if written > 0 {
                            Ok(Async::Ready(Some(written)))
                        } else {
                            Ok(Async::Ready(None))
                        }
                    }
                    Ok(Async::Ready(len)) => {
                        if let Some(interceptor) = self.packet_interceptor.as_mut() {
                            interceptor.on_new_packet(self.peer_addr, &reservation[..len]);
                        }

                        written += len;
                        reservation.truncate(len);
                        reservation.send();
                        self.nb_bytes_read.fetch_add(len as u64, Ordering::SeqCst);

                        trace!("{} bytes read on {}", len, peer_addr);
                    }
                    Ok(Async::NotReady) => {
                        return if written > 0 {
                            Ok(Async::Ready(Some(written)))
                        } else {
                            Ok(Async::NotReady)
                        }
                    }
                    Err(e) => {
                        error!("Can't read on socket: {}", e);
                        return Ok(Async::Ready(None));
                    }
                }
            } else {
                return if written > 0 {
                    Ok(Async::Ready(Some(written)))
                } else {
                    error!("BipBuffer reader cannot read any byte. Closing Writer");

                    Ok(Async::Ready(None))
                };
            }
        }
    }
}

impl<T: AsyncRead> JetStream for JetStreamImpl<T> {
    fn nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read.load(Ordering::Relaxed)
    }

    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>) {
        self.packet_interceptor = Some(interceptor);
    }
}

struct JetSinkImpl<T: AsyncWrite> {
    stream: WriteHalf<T>,
    nb_bytes_written: Arc<AtomicU64>,
    peer_addr_str: String,
    buffer: BipBufferReader,
}

impl<T: AsyncWrite> JetSinkImpl<T> {
    fn new(
        stream: WriteHalf<T>,
        nb_bytes_written: Arc<AtomicU64>,
        peer_addr: Option<SocketAddr>,
        buffer: BipBufferReader,
    ) -> Self {
        Self {
            stream,
            nb_bytes_written,
            peer_addr_str: peer_addr.map_or("Unknown".to_string(), |addr| addr.to_string()),
            buffer,
        }
    }
}

impl<T: AsyncWrite> Sink for JetSinkImpl<T> {
    type SinkItem = usize;
    type SinkError = io::Error;

    fn start_send(&mut self, mut bytes_read: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        let peer_addr = &self.peer_addr_str;
        trace!("{} bytes to write on {}", bytes_read, peer_addr);

        loop {
            match self.stream.poll_write(self.buffer.valid()) {
                Ok(Async::Ready(len)) => {
                    if len > 0 {
                        self.buffer.consume(len);
                        self.nb_bytes_written.fetch_add(len as u64, Ordering::SeqCst);
                        bytes_read -= len;
                    }
                    trace!("{} bytes written on {}", len, peer_addr);

                    if bytes_read == 0 {
                        return Ok(AsyncSink::Ready);
                    }
                }
                Ok(Async::NotReady) => return Ok(AsyncSink::NotReady(bytes_read)),
                Err(e) => {
                    error!("Can't write on socket: {}", e);
                    return Err(io::Error::from(e));
                }
            }
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_flush()
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.shutdown()
    }
}

impl<T: AsyncWrite> JetSink for JetSinkImpl<T> {
    fn nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written.load(Ordering::Relaxed)
    }
    fn finished(&mut self) -> bool {
        self.buffer.valid().is_empty()
    }
}
