use crate::{ErasedRead, ErasedWrite, MaybeWssStream, TcpStream, TlsStream, WsStream, WssStream};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Utility macro to apply the same operation on all variants (static)
#[macro_export]
macro_rules! map_any_stream {
    ($stream:expr, $operation:expr) => {{
        match $stream {
            AnyStream::Tcp(stream) => $operation(stream),
            AnyStream::Tls(stream) => $operation(stream),
            AnyStream::Ws(stream) => $operation(stream),
            AnyStream::Wss(stream) => $operation(stream),
            AnyStream::MaybeWss(stream) => $operation(stream),
        }
    }};
}

#[allow(clippy::large_enum_variant)] // TODO: measure impact of boxing WssStream and TlsStream on performance
pub enum AnyStream {
    Tcp(TcpStream),
    Tls(TlsStream),
    Ws(WsStream),
    Wss(WssStream),
    MaybeWss(MaybeWssStream),
}

impl AnyStream {
    pub fn split_erased(self) -> (ErasedRead, ErasedWrite) {
        match self {
            AnyStream::Tcp(stream) => {
                let (reader, writer) = stream.into_split();
                (Box::new(reader), Box::new(writer))
            }
            AnyStream::Tls(stream) => {
                let (reader, writer) = tokio::io::split(stream);
                (Box::new(reader), Box::new(writer))
            }
            AnyStream::Ws(stream) => {
                let (reader, writer) = tokio::io::split(stream);
                (Box::new(reader), Box::new(writer))
            }
            AnyStream::Wss(stream) => {
                let (reader, writer) = tokio::io::split(stream);
                (Box::new(reader), Box::new(writer))
            }
            AnyStream::MaybeWss(stream) => {
                let (reader, writer) = tokio::io::split(stream);
                (Box::new(reader), Box::new(writer))
            }
        }
    }

    pub fn into_tcp(self) -> Result<TcpStream, Self> {
        if let AnyStream::Tcp(stream) = self {
            Ok(stream)
        } else {
            Err(self)
        }
    }

    pub fn into_tls(self) -> Result<TlsStream, Self> {
        if let AnyStream::Tls(stream) = self {
            Ok(stream)
        } else {
            Err(self)
        }
    }

    pub fn into_ws(self) -> Result<WsStream, Self> {
        if let AnyStream::Ws(stream) = self {
            Ok(stream)
        } else {
            Err(self)
        }
    }

    pub fn into_wss(self) -> Result<WssStream, Self> {
        if let AnyStream::Wss(stream) = self {
            Ok(stream)
        } else {
            Err(self)
        }
    }

    pub fn into_maybe_wss(self) -> Result<MaybeWssStream, Self> {
        if let AnyStream::MaybeWss(stream) = self {
            Ok(stream)
        } else {
            Err(self)
        }
    }
}

impl From<TcpStream> for AnyStream {
    fn from(s: TcpStream) -> Self {
        Self::Tcp(s)
    }
}

impl From<TlsStream> for AnyStream {
    fn from(s: TlsStream) -> Self {
        Self::Tls(s)
    }
}

impl From<WsStream> for AnyStream {
    fn from(s: WsStream) -> Self {
        Self::Ws(s)
    }
}

impl From<WssStream> for AnyStream {
    fn from(s: WssStream) -> Self {
        Self::Wss(s)
    }
}

impl From<MaybeWssStream> for AnyStream {
    fn from(s: MaybeWssStream) -> Self {
        Self::MaybeWss(s)
    }
}

impl AsyncRead for AnyStream {
    #[inline]
    fn poll_read(
        self: ::core::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
        buf: &mut ::tokio::io::ReadBuf<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        match self.get_mut() {
            AnyStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            AnyStream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            AnyStream::Ws(stream) => Pin::new(stream).poll_read(cx, buf),
            AnyStream::Wss(stream) => Pin::new(stream).poll_read(cx, buf),
            AnyStream::MaybeWss(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AnyStream {
    #[inline]
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
        buf: &[u8],
    ) -> ::core::task::Poll<::std::io::Result<usize>> {
        match self.get_mut() {
            AnyStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            AnyStream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            AnyStream::Ws(stream) => Pin::new(stream).poll_write(cx, buf),
            AnyStream::Wss(stream) => Pin::new(stream).poll_write(cx, buf),
            AnyStream::MaybeWss(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        match self.get_mut() {
            AnyStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            AnyStream::Tls(stream) => Pin::new(stream).poll_flush(cx),
            AnyStream::Ws(stream) => Pin::new(stream).poll_flush(cx),
            AnyStream::Wss(stream) => Pin::new(stream).poll_flush(cx),
            AnyStream::MaybeWss(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        match self.get_mut() {
            AnyStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            AnyStream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            AnyStream::Ws(stream) => Pin::new(stream).poll_shutdown(cx),
            AnyStream::Wss(stream) => Pin::new(stream).poll_shutdown(cx),
            AnyStream::MaybeWss(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
