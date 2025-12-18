//! Mimics tokio API for network primitives, except it's not doing any actual networking operation.
//! This is loom-compatible using "--cfg loom".

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::LazyLock;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::sync::{Mutex, Notify, mpsc};

static LISTENERS: LazyLock<Mutex<HashMap<SocketAddr, mpsc::Sender<DuplexStream>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEW_LISTENER: LazyLock<Notify> = LazyLock::new(Notify::new);

#[derive(Debug)]
pub struct TcpListener(
    // Using a Mutex just because tokio API for `accept` is not borrowing mutably, but we need
    // mutable access to the receiver.
    Mutex<mpsc::Receiver<DuplexStream>>,
);

impl TcpListener {
    pub async fn bind<T: ToSocketAddrs>(addr: T) -> std::io::Result<TcpListener> {
        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::other("invalid address"))?;

        let (sender, receiver) = mpsc::channel(3);
        LISTENERS.lock().await.insert(addr, sender);
        NEW_LISTENER.notify_waiters();

        Ok(Self(Mutex::new(receiver)))
    }

    pub async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr)> {
        let stream = self
            .0
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("no more duplex sender"))?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        Ok((TcpStream(stream), addr))
    }
}

/// Wraps a `tokio::io::DuplexStream`
#[derive(Debug)]
pub struct TcpStream(pub DuplexStream);

impl TcpStream {
    pub async fn connect<T: ToSocketAddrs>(addr: T) -> std::io::Result<Self> {
        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::other("invalid address"))?;

        let sender = loop {
            if let Some(sender) = LISTENERS.lock().await.get(&addr) {
                break sender.clone();
            }

            NEW_LISTENER.notified().await;
        };

        let (one, two) = tokio::io::duplex(1024);
        sender
            .send(two)
            .await
            .map_err(|_| std::io::Error::other("couldn't connect to host (listener has been dropped)"))?;

        Ok(Self(one))
    }

    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 10808))
    }

    pub fn into_split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
        tokio::io::split(self)
    }
}

impl AsyncRead for TcpStream {
    #[inline]
    fn poll_read(
        self: ::core::pin::Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
        buf: &mut ::tokio::io::ReadBuf<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
        buf: &[u8],
    ) -> ::core::task::Poll<::std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut ::core::task::Context<'_>,
    ) -> ::core::task::Poll<::std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Underlying implementation is basically `ToSocketAddrs::to_socket_addrs`, we are mocking network anyway.
pub async fn lookup_host<T>(host: T) -> std::io::Result<impl Iterator<Item = SocketAddr>>
where
    T: ToSocketAddrs,
{
    host.to_socket_addrs()
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn dummy_to_dummy() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let server_handle = rt.spawn(async move {
            let listener = TcpListener::bind("127.0.0.0:8000").await.unwrap();

            let (mut stream, _addr) = listener.accept().await.unwrap();
            stream.write_all(&[0, 1, 2, 3, 5, 6]).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        rt.block_on(async {
            let mut stream = TcpStream::connect("127.0.0.0:8000").await.unwrap();

            let mut buf = [0; 6];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [0, 1, 2, 3, 5, 6]);

            server_handle.await.unwrap();
        });
    }
}
