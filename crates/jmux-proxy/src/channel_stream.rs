use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// The stream a JMUX channel forwards its payload over.
///
/// `Direct` is the common path: a concrete TCP socket split cheaply into owned halves. `Handled`
/// exists only when an [`crate::OutgoingStreamHandler`] took the channel over — it is the JMUX side
/// of the in-memory pipe shared with that handler.
pub(crate) enum ChannelStream {
    Direct(TcpStream),
    Handled(DuplexStream),
}

impl ChannelStream {
    pub(crate) fn into_split(self) -> (ChannelReader, ChannelWriter) {
        match self {
            ChannelStream::Direct(stream) => {
                let (reader, writer) = stream.into_split();
                (ChannelReader::Direct(reader), ChannelWriter::Direct(writer))
            }
            ChannelStream::Handled(stream) => {
                let (reader, writer) = tokio::io::split(stream);
                (ChannelReader::Handled(reader), ChannelWriter::Handled(writer))
            }
        }
    }
}

pub(crate) enum ChannelReader {
    Direct(OwnedReadHalf),
    Handled(ReadHalf<DuplexStream>),
}

impl AsyncRead for ChannelReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelReader::Direct(reader) => Pin::new(reader).poll_read(cx, buf),
            ChannelReader::Handled(reader) => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

pub(crate) enum ChannelWriter {
    Direct(OwnedWriteHalf),
    Handled(WriteHalf<DuplexStream>),
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ChannelWriter::Direct(writer) => Pin::new(writer).poll_write(cx, buf),
            ChannelWriter::Handled(writer) => Pin::new(writer).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelWriter::Direct(writer) => Pin::new(writer).poll_flush(cx),
            ChannelWriter::Handled(writer) => Pin::new(writer).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelWriter::Direct(writer) => Pin::new(writer).poll_shutdown(cx),
            ChannelWriter::Handled(writer) => Pin::new(writer).poll_shutdown(cx),
        }
    }
}
