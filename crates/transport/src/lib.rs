mod any;
mod forward;
mod ws;

pub use self::any::*;
pub use self::forward::*;
pub use self::ws::*;

use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::MaybeTlsStream;

pub type TcpStream = tokio::net::TcpStream;
pub type TlsStream = tokio_rustls::TlsStream<TcpStream>;
pub type WsStream = crate::WebSocketStream<tokio_tungstenite::WebSocketStream<TcpStream>>;
pub type WssStream = crate::WebSocketStream<tokio_tungstenite::WebSocketStream<TlsStream>>;
pub type MaybeWssStream = crate::WebSocketStream<tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>>;

pub type ErasedRead = Box<dyn AsyncRead + Send + Unpin>;
pub type ErasedWrite = Box<dyn AsyncWrite + Send + Unpin>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pub type ErasedReadWrite = Box<dyn AsyncReadWrite + Send + Unpin>;

pub struct Transport {
    pub stream: AnyStream,
    pub addr: SocketAddr,
}

impl Transport {
    pub fn new(stream: impl Into<AnyStream>, addr: SocketAddr) -> Self {
        Self {
            stream: stream.into(),
            addr,
        }
    }

    pub fn into_erased(self) -> ErasedReadWrite {
        map_any_stream!(self.stream, |stream| Box::new(stream) as ErasedReadWrite)
    }

    pub fn into_erased_split(self) -> (ErasedRead, ErasedWrite) {
        self.stream.split_erased()
    }
}

impl AsyncRead for Transport {
    #[inline]
    fn poll_read(
        mut self: ::core::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
        buf: &mut ::tokio::io::ReadBuf<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Transport {
    #[inline]
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
        buf: &[u8],
    ) -> ::core::task::Poll<::std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
