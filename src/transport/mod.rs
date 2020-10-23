use std::{
    io::{Read, Write},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc
    },
    rc::Rc,
    pin::Pin,
    task::{Context, Poll},
    cell::RefCell,
    ops::DerefMut,
};
use futures::{
    Future, Sink, Stream, pin_mut
};
use slog_scope::{error, trace};
use spsc_bip_buffer::{BipBufferReader, BipBufferWriter};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    net::TcpStream
};
use url::Url;

use crate::{
    interceptor::PacketInterceptor,
    //transport::{tcp::TcpTransport, ws::WsTransport},
};

/*
pub mod fast_path;
pub mod mcs;
pub mod rdp;
*/
//pub mod tcp;
/*
pub mod tsrequest;
pub mod ws;
pub mod x224;
*/

pub type JetFuture<T> = Box<dyn Future<Output = Result<T, io::Error>> + Send>;
pub type JetStreamType<T> = Box<dyn JetStream<Item = Result<T, io::Error>> + Send>;
pub type JetSinkType<T> = Box<dyn JetSink<T, Error = io::Error> + Send>;

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
/*
#[allow(clippy::large_enum_variant)]
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
*/
pub trait JetStream: Stream {
    fn nb_bytes_read(&self) -> u64;
    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>);
}

pub trait JetSink<SinkItem>: Sink<SinkItem> {
    fn nb_bytes_written(&self) -> u64;
    fn finished(&mut self) -> bool;
}

struct JetStreamImpl<T: AsyncRead> {
    stream: RefCell<ReadHalf<T>>,
    nb_bytes_read: Arc<AtomicU64>,
    packet_interceptor: RefCell<Option<Box<dyn PacketInterceptor>>>,
    peer_addr: Option<SocketAddr>,
    peer_addr_str: String,
    buffer: RefCell<BipBufferWriter>,
}

impl<T: AsyncRead + Unpin> JetStreamImpl<T> {
    fn new(
        stream: ReadHalf<T>,
        nb_bytes_read: Arc<AtomicU64>,
        peer_addr: Option<SocketAddr>,
        buffer: BipBufferWriter,
    ) -> Self {
        Self {
            stream: RefCell::new(stream),
            nb_bytes_read,
            packet_interceptor: RefCell::new(None),
            peer_addr,
            peer_addr_str: peer_addr.clone().map_or("Unknown".to_string(), |addr| addr.to_string()),
            buffer: RefCell::new(buffer),
        }
    }
}

impl<T: AsyncRead + Unpin> Stream for JetStreamImpl<T> {
    type Item = Result<usize, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut written = 0;
        let mut stream = self.stream.borrow_mut();
        let mut buffer = self.buffer.borrow_mut();
        let mut packet_interceptor = self.packet_interceptor.borrow_mut();

        loop {
            if let Some(mut reservation) = buffer.reserve(PART_LEN) {
                match Pin::new(stream.deref_mut()).poll_read(cx, reservation.as_mut()) {
                    Poll::Ready(Ok(0)) => {
                        reservation.cancel(); // equivalent to truncate(0)
                        return if written > 0 {
                            Poll::Ready(Some(Ok(written)))
                        } else {
                            Poll::Ready(None)
                        };
                    }
                    Poll::Ready(Ok(len)) => {
                        if let Some(interceptor) = packet_interceptor.deref_mut() {
                            interceptor.on_new_packet(self.peer_addr, &reservation[..len]);
                        }

                        written += len;
                        reservation.truncate(len);
                        reservation.send();
                        self.nb_bytes_read.fetch_add(len as u64, Ordering::SeqCst);

                        let peer_addr = &self.peer_addr_str;
                        trace!("{} bytes read on {}", len, peer_addr);
                    }
                    Poll::Pending => {
                        reservation.cancel();
                        return if written > 0 {
                            Poll::Ready(Some(Ok(written)))
                        } else {
                            Poll::Pending
                        };
                    }
                    Poll::Ready(Err(e)) => {
                        reservation.cancel();
                        error!("Can't read on socket: {}", e);
                        return Poll::Ready(None);
                    }
                }
            } else {
                return if written > 0 {
                    Poll::Ready(Some(Ok(written)))
                } else {
                    error!("BipBuffer writer cannot write any byte. Closing Writer");
                    Poll::Ready(None)
                };
            }
        };
    }
}

impl<T: AsyncRead + Unpin> JetStream for JetStreamImpl<T> {
    fn nb_bytes_read(&self) -> u64 {
        self.nb_bytes_read.load(Ordering::Relaxed)
    }

    fn set_packet_interceptor(&mut self, interceptor: Box<dyn PacketInterceptor>) {
        self.packet_interceptor = RefCell::new(Some(interceptor));
    }
}

struct JetSinkImpl<T: AsyncWrite> {
    stream: RefCell<WriteHalf<T>>,
    nb_bytes_written: Arc<AtomicU64>,
    bytes_to_write: RefCell<usize>,
    peer_addr_str: String,
    buffer: RefCell<BipBufferReader>,
}

impl<T: AsyncWrite> JetSinkImpl<T> {
    fn new(
        stream: WriteHalf<T>,
        nb_bytes_written: Arc<AtomicU64>,
        peer_addr: Option<SocketAddr>,
        buffer: BipBufferReader,
    ) -> Self {
        Self {
            stream: RefCell::new(stream),
            nb_bytes_written,
            bytes_to_write: RefCell::new(0),
            peer_addr_str: peer_addr.map_or("Unknown".to_string(), |addr| addr.to_string()),
            buffer: RefCell::new(buffer),
        }
    }
}

impl<T: AsyncWrite> Sink<usize> for JetSinkImpl<T> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let peer_addr = &self.peer_addr_str;

        let mut stream = self.stream.borrow_mut();
        let mut buffer = self.buffer.borrow_mut();
        let mut bytes_to_write = self.bytes_to_write.borrow_mut();
        trace!("{} bytes to write on {}", *bytes_to_write, peer_addr);

        loop {
            match Pin::new(stream.deref_mut()).poll_write(cx, buffer.valid()) {
                Poll::Ready(Ok(len)) => {
                    if len > 0 {
                        buffer.consume(len);
                        self.nb_bytes_written.fetch_add(len as u64, Ordering::SeqCst);
                        *bytes_to_write -= len;
                    }
                    trace!("{} bytes written on {}", len, peer_addr);

                    if *bytes_to_write == 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    error!("Can't write on socket: {}", e);
                    return Poll::Ready(Err(e));
                }
            }
        }
    }

    fn start_send(self: Pin<&mut Self>, bytes_read: usize) -> Result<(), Self::Error> {
        let mut bytes_to_write = self.bytes_to_write.borrow_mut();
        assert_eq!(*bytes_to_write, 0, "Sink still has not finished previous transmission");
        *bytes_to_write = bytes_read;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut stream = self.stream.borrow_mut();
        Pin::new(stream.deref_mut()).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut stream = self.stream.borrow_mut();
        Pin::new(stream.deref_mut()).poll_shutdown(cx)
    }
}

impl<T: AsyncWrite> JetSink<usize> for JetSinkImpl<T> {
    fn nb_bytes_written(&self) -> u64 {
        self.nb_bytes_written.load(Ordering::Relaxed)
    }
    fn finished(&mut self) -> bool {
        let mut buffer = self.buffer.borrow_mut();
        buffer.valid().is_empty()
    }
}
