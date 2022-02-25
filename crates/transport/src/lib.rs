mod forward;
mod ws;

pub use self::forward::*;
pub use self::ws::*;

use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

pin_project! {
    pub struct ReadableHalf<R = Box<dyn AsyncRead + Send + Unpin>> {
        #[pin]
        pub inner: R,
    }
}

impl<R> ReadableHalf<R> {
    #[inline]
    pub fn new(reader: R) -> Self {
        Self { inner: reader }
    }

    #[inline]
    pub fn into_inner(self) -> R {
        self.inner
    }

    #[inline]
    pub fn as_inner(&self) -> &R {
        &self.inner
    }

    #[inline]
    pub fn as_inner_mut(&mut self) -> &mut R {
        &mut self.inner
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
    R: AsyncRead + Send + Unpin,
{
    #[inline]
    pub fn into_erased(self) -> ReadableHalf<Box<dyn AsyncRead + Send + Unpin>>
    where
        R: 'static,
    {
        ReadableHalf::new(Box::new(self.inner))
    }
}

impl<R> AsyncRead for ReadableHalf<R>
where
    R: AsyncRead,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

pin_project! {
    pub struct WriteableHalf<W = Box<dyn AsyncWrite + Send + Unpin>> {
        #[pin]
        pub inner: W
    }
}

impl<W> WriteableHalf<W> {
    #[inline]
    pub fn new(reader: W) -> Self {
        Self { inner: reader }
    }

    #[inline]
    pub fn into_inner(self) -> W {
        self.inner
    }

    #[inline]
    pub fn as_inner(&self) -> &W {
        &self.inner
    }

    #[inline]
    pub fn as_inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

impl<W> WriteableHalf<W>
where
    W: AsyncWrite + Send + Unpin,
{
    #[inline]
    pub fn into_erased(self) -> WriteableHalf<Box<dyn AsyncWrite + Send + Unpin>>
    where
        W: 'static,
    {
        WriteableHalf::new(Box::new(self.inner))
    }
}

impl<W> AsyncWrite for WriteableHalf<W>
where
    W: AsyncWrite,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> task::Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

pin_project! {
    pub struct Transport<S = Box<dyn AsyncReadWrite + Send + Unpin>> {
        #[pin]
        pub inner: S,
    }
}

impl<S> Transport<S> {
    #[inline]
    pub fn new(stream: S) -> Self {
        Self { inner: stream }
    }

    #[inline]
    pub fn into_inner(self) -> S {
        self.inner
    }

    #[inline]
    pub fn as_inner(&self) -> &S {
        &self.inner
    }

    #[inline]
    pub fn as_inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S> Transport<S>
where
    S: AsyncRead + AsyncWrite,
{
    #[inline]
    pub fn split(self) -> (ReadableHalf<ReadHalf<S>>, WriteableHalf<WriteHalf<S>>) {
        let (reader, writer) = tokio::io::split(self.inner);
        (ReadableHalf::new(reader), WriteableHalf::new(writer))
    }

    #[inline]
    pub fn split_erased(self) -> (ReadableHalf, WriteableHalf)
    where
        S: Send + 'static,
    {
        let (reader, writer) = tokio::io::split(self.inner);
        (
            ReadableHalf::new(reader).into_erased(),
            WriteableHalf::new(writer).into_erased(),
        )
    }

    #[inline]
    pub fn into_erased(self) -> Transport<Box<dyn AsyncReadWrite + Send + Unpin>>
    where
        S: Send + Unpin + 'static,
    {
        Transport::new(Box::new(self.inner))
    }
}

impl<S> AsyncRead for Transport<S>
where
    S: AsyncRead,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for Transport<S>
where
    S: AsyncWrite,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> task::Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
