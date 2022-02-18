use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone)]
pub struct DummyStream(pub Vec<u8>);

impl AsyncWrite for DummyStream {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.poll_flush(cx)
    }
}

impl AsyncRead for DummyStream {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        buf.put_slice(&self.0);
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub struct AsyncStdIo<T: Send>(pub T);

impl<T: Send> Unpin for AsyncStdIo<T> {}

macro_rules! try_with_interrupt {
    ($e:expr) => {
        loop {
            match $e {
                Ok(e) => {
                    break e;
                }
                Err(ref e) if e.kind() == ::std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }
    };
}

impl<T> io::Write for AsyncStdIo<T>
where
    T: io::Write + Send,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.0.write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }

    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> io::Result<()> {
        self.0.write_fmt(fmt)
    }
}

impl<T> AsyncWrite for AsyncStdIo<T>
where
    T: io::Write + Send,
{
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(Ok(try_with_interrupt!(self.0.write(buf))))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        try_with_interrupt!(self.0.flush());
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.poll_flush(cx)
    }
}

impl<T> io::Read for AsyncStdIo<T>
where
    T: io::Read + Send,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.0.read_vectored(bufs)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.0.read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        self.0.read_to_string(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_exact(buf)
    }
}

impl<T> AsyncRead for AsyncStdIo<T>
where
    T: io::Read + Send,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = try_with_interrupt!(self.0.read(buf.initialize_unfilled()));
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}
