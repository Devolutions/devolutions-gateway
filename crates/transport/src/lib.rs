mod forward;
mod ws;

pub use self::forward::*;
pub use self::ws::*;

use anyhow::Result;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

pub struct ReadableHalf<R = Box<dyn AsyncRead + Unpin + Send>>(pub R);

impl<R> ReadableHalf<R> {
    #[inline]
    pub fn new(reader: R) -> Self {
        Self(reader)
    }

    #[inline]
    pub fn into_inner(self) -> R {
        self.0
    }

    #[inline]
    pub fn as_inner(&self) -> &R {
        &self.0
    }

    #[inline]
    pub fn as_inner_mut(&mut self) -> &mut R {
        &mut self.0
    }
}

impl<S> ReadableHalf<ReadHalf<S>> {
    #[inline]
    pub fn is_pair_of(&self, other: &WriteableHalf<WriteHalf<S>>) -> bool {
        self.as_inner().is_pair_of(other.as_inner())
    }

    #[inline]
    pub fn unsplit(self, other: WriteableHalf<WriteHalf<S>>) -> Transport<S> {
        Transport::new(self.into_inner().unsplit(other.into_inner()))
    }
}

impl ReadableHalf<tokio::net::tcp::OwnedReadHalf> {
    #[inline]
    pub fn reunite(
        self,
        other: WriteableHalf<tokio::net::tcp::OwnedWriteHalf>,
    ) -> core::result::Result<Transport<tokio::net::TcpStream>, tokio::net::tcp::ReuniteError> {
        let stream = self.into_inner().reunite(other.into_inner())?;
        Ok(Transport::new(stream))
    }
}

impl<R> ReadableHalf<R>
where
    R: AsyncRead + Unpin + Send,
{
    #[inline]
    pub fn into_erased(self) -> ReadableHalf<Box<dyn AsyncRead + Unpin + Send>>
    where
        R: 'static,
    {
        ReadableHalf(Box::new(self.0))
    }
}

impl<R> AsyncRead for ReadableHalf<R>
where
    R: AsyncRead + Unpin + Send,
{
    #[inline]
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

pub struct WriteableHalf<W = Box<dyn AsyncWrite + Unpin + Send>>(pub W);

impl<W> WriteableHalf<W> {
    #[inline]
    pub fn new(reader: W) -> Self {
        Self(reader)
    }

    #[inline]
    pub fn into_inner(self) -> W {
        self.0
    }

    #[inline]
    pub fn as_inner(&self) -> &W {
        &self.0
    }

    #[inline]
    pub fn as_inner_mut(&mut self) -> &mut W {
        &mut self.0
    }
}

impl<W> WriteableHalf<W>
where
    W: AsyncWrite + Unpin + Send,
{
    #[inline]
    pub fn into_erased(self) -> WriteableHalf<Box<dyn AsyncWrite + Unpin + Send>>
    where
        W: 'static,
    {
        WriteableHalf(Box::new(self.0))
    }
}

impl<W> AsyncWrite for WriteableHalf<W>
where
    W: AsyncWrite + Unpin + Send,
{
    #[inline]
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pub struct Transport<S = Box<dyn AsyncReadWrite + Unpin + Send>>(pub S);

impl<S> Transport<S> {
    #[inline]
    pub fn new(stream: S) -> Self {
        Self(stream)
    }

    #[inline]
    pub fn into_inner(self) -> S {
        self.0
    }

    #[inline]
    pub fn as_inner(&self) -> &S {
        &self.0
    }

    #[inline]
    pub fn as_inner_mut(&mut self) -> &mut S {
        &mut self.0
    }
}

impl<S> Transport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    #[inline]
    pub fn split(self) -> (ReadableHalf<ReadHalf<S>>, WriteableHalf<WriteHalf<S>>) {
        let (reader, writer) = tokio::io::split(self.0);
        (ReadableHalf::new(reader), WriteableHalf::new(writer))
    }

    #[inline]
    pub fn split_erased(self) -> (ReadableHalf, WriteableHalf)
    where
        S: 'static,
    {
        let (reader, writer) = tokio::io::split(self.0);
        (
            ReadableHalf::new(reader).into_erased(),
            WriteableHalf::new(writer).into_erased(),
        )
    }

    #[inline]
    pub fn into_erased(self) -> Transport<Box<dyn AsyncReadWrite + Unpin + Send>>
    where
        S: 'static,
    {
        Transport(Box::new(self.0))
    }
}

impl<S> AsyncRead for Transport<S>
where
    S: AsyncRead + Unpin + Send,
{
    #[inline]
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for Transport<S>
where
    S: AsyncWrite + Unpin + Send,
{
    #[inline]
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
