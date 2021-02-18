use futures::{ready, Sink, Stream};
use slog_scope::{debug, error, trace};
use spsc_bip_buffer::{BipBufferReader, BipBufferWriter};
use std::future::Future;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use url::Url;

use crate::interceptor::PacketInterceptor;
use crate::transport::tcp::TcpTransport;
use crate::transport::ws::WsTransport;
use tokio::io::Error;

pub mod tcp;
pub mod ws;

pub mod fast_path;
pub mod mcs;
pub mod rdp;
pub mod tsrequest;
pub mod x224;

pub type JetFuture<T> = Pin<Box<dyn Future<Output = Result<T, io::Error>> + Send>>;
pub type JetStreamType<T> = Pin<Box<dyn JetStream<Item = Result<T, io::Error>> + Send>>;
pub type JetSinkType<T> = Pin<Box<dyn JetSink<T, Error = io::Error> + Send>>;

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
        unimplemented!("JetTransport::connect is not implemented yet for JetTransport")
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

impl AsyncRead for JetTransport {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            JetTransport::Tcp(ref mut tcp_transport) => Pin::new(tcp_transport).poll_read(cx, buf),
            JetTransport::Ws(ref mut ws_transport) => Pin::new(ws_transport).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for JetTransport {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            JetTransport::Tcp(ref mut tcp_transport) => Pin::new(tcp_transport).poll_write(cx, buf),
            JetTransport::Ws(ref mut ws_transport) => Pin::new(ws_transport).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            JetTransport::Tcp(ref mut tcp_transport) => Pin::new(tcp_transport).poll_flush(cx),
            JetTransport::Ws(ref mut ws_transport) => Pin::new(ws_transport).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            JetTransport::Tcp(ref mut tcp_transport) => Pin::new(tcp_transport).poll_shutdown(cx),
            JetTransport::Ws(ref mut ws_transport) => Pin::new(ws_transport).poll_shutdown(cx),
        }
    }
}

pub trait JetStream: Stream {
    fn nb_bytes_read(self: Pin<&Self>) -> u64;
    fn set_packet_interceptor(self: Pin<&mut Self>, interceptor: Box<dyn PacketInterceptor>);
}

pub trait JetSink<SinkItem>: Sink<SinkItem> {
    fn nb_bytes_written(self: Pin<&Self>) -> u64;
    fn finished(self: Pin<&mut Self>) -> bool;
}

struct JetStreamImpl<T: AsyncRead> {
    stream: ReadHalf<T>,
    nb_bytes_read: Arc<AtomicU64>,
    packet_interceptor: Option<Box<dyn PacketInterceptor>>,
    peer_addr: Option<SocketAddr>,
    peer_addr_str: String,
    buffer: BipBufferWriter,
}

impl<T: AsyncRead + Unpin> JetStreamImpl<T> {
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

impl<T: AsyncRead + Unpin> Stream for JetStreamImpl<T> {
    type Item = Result<usize, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut written = 0;

        loop {
            let Self {
                ref mut stream,
                buffer,
                packet_interceptor,
                peer_addr,
                nb_bytes_read,
                peer_addr_str,
                ..
            } = self.deref_mut();

            if let Some(mut reservation) = buffer.reserve(PART_LEN) {
                let mut read_buffer = ReadBuf::new(reservation.as_mut());
                match Pin::new(stream).poll_read(cx, &mut read_buffer) {
                    Poll::Ready(Ok(())) if read_buffer.filled().is_empty() => {
                        reservation.cancel(); // equivalent to truncate(0)
                        return if written > 0 {
                            Poll::Ready(Some(Ok(written)))
                        } else {
                            Poll::Ready(None)
                        };
                    }
                    Poll::Ready(Ok(())) => {
                        let len = read_buffer.filled().len();
                        if let Some(interceptor) = packet_interceptor {
                            interceptor.on_new_packet(*peer_addr, &reservation[..len]);
                        }

                        written += len;
                        reservation.truncate(len);
                        reservation.send();
                        nb_bytes_read.fetch_add(len as u64, Ordering::SeqCst);

                        trace!("{} bytes read on {}", len, peer_addr_str);
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
                    debug!("BipBuffer writer temporary cannot reserve {} bytes", PART_LEN);
                    cx.waker().clone().wake();
                    Poll::Pending
                };
            }
        }
    }
}

impl<T: AsyncRead + Unpin> JetStream for JetStreamImpl<T> {
    fn nb_bytes_read(self: Pin<&Self>) -> u64 {
        self.nb_bytes_read.load(Ordering::Relaxed)
    }

    fn set_packet_interceptor(mut self: Pin<&mut Self>, interceptor: Box<dyn PacketInterceptor>) {
        self.packet_interceptor = Some(interceptor);
    }
}

struct JetSinkImpl<T: AsyncWrite> {
    stream: WriteHalf<T>,
    nb_bytes_written: Arc<AtomicU64>,
    bytes_to_write: usize,
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
            bytes_to_write: 0,
            peer_addr_str: peer_addr.map_or("Unknown".to_string(), |addr| addr.to_string()),
            buffer,
        }
    }
}

impl<T: AsyncWrite> Sink<usize> for JetSinkImpl<T> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.bytes_to_write == 0 {
            Poll::Ready(Ok(()))
        } else {
            self.as_mut().poll_flush(cx)
        }
    }

    fn start_send(mut self: Pin<&mut Self>, bytes_read: usize) -> Result<(), Self::Error> {
        assert_eq!(
            self.bytes_to_write, 0,
            "Sink still has not finished previous transmission"
        );
        self.bytes_to_write += bytes_read;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let Self {
            peer_addr_str,
            bytes_to_write,
            ..
        } = self.deref_mut();

        if *bytes_to_write == 0 {
            return Poll::Ready(Ok(()));
        }

        trace!("{} bytes to write on {}", *bytes_to_write, peer_addr_str);

        let peer_addr = peer_addr_str.clone();

        loop {
            let Self {
                stream,
                bytes_to_write,
                nb_bytes_written,
                buffer,
                ..
            } = self.deref_mut();

            let chunk_size = buffer.valid().len().min(*bytes_to_write);

            match Pin::new(stream).poll_write(cx, &buffer.valid()[..chunk_size]) {
                Poll::Ready(Ok(len)) => {
                    if len > 0 {
                        buffer.consume(len);
                        nb_bytes_written.fetch_add(len as u64, Ordering::SeqCst);
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

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;

        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<T: AsyncWrite> JetSink<usize> for JetSinkImpl<T> {
    fn nb_bytes_written(self: Pin<&Self>) -> u64 {
        self.nb_bytes_written.load(Ordering::Relaxed)
    }
    fn finished(mut self: Pin<&mut Self>) -> bool {
        self.buffer.valid().is_empty()
    }
}
