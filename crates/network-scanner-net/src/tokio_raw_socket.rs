use std::{mem::MaybeUninit, sync::Arc, usize};

use socket2::SockAddr;
use std::result::Result::Ok;
use tokio::sync::Mutex;

/// A wrapper on raw socket that can be used with async tokio runtime
/// This currently only throws the blocking calls on a blocking thread pool
/// In the future, this should be replaced with a non-blocking implementation that takes advantage of OS specific async APIs
/// We are seeking to match the function signatures of socket2::Socket, but in async form
pub struct TokioRawSocket {
    socket: Arc<Mutex<socket2::Socket>>,
}

impl TokioRawSocket {
    pub fn new(
        domain: socket2::Domain,
        ty: socket2::Type,
        protocol: Option<socket2::Protocol>,
    ) -> std::io::Result<TokioRawSocket> {

        let socket = socket2::Socket::new(domain, ty, protocol)?;
        let socket = Arc::new(Mutex::new(socket));
        Ok(TokioRawSocket { socket })
    }

    pub async fn send_to(&self, data: &[u8], addr: socket2::SockAddr) -> std::io::Result<usize> {
        tracing::trace!(?data, ?addr, "send_to");
        let socket = self.socket.clone();
        let cloned_data = data.to_vec();
        let res = tokio::task::spawn_blocking(move || {
            let socket = socket.blocking_lock();
            tracing::trace!(
                "send_to blocking lock, sending data {:?} to addr {:?}",
                cloned_data,
                addr
            );
            socket.send_to(cloned_data.as_ref(), &addr)
        })
        .await??;

        Ok(res)
    }

    pub async fn recv_from(&self, buf: &mut [MaybeUninit<u8>]) -> std::io::Result<(usize, SockAddr)> {
        tracing::trace!("recv_from, buf len: {}", buf.len());
        let socket = self.socket.clone();
        let (rx, mut tx) = tokio::sync::mpsc::channel(1);
        let size = buf.len();
        let (len, socket_addr) = tokio::task::spawn_blocking(move || {
            let socket = socket.blocking_lock();
            let mut inner_buf = vec![MaybeUninit::uninit(); size];
            let (usize, socket_addr) = socket.recv_from(&mut inner_buf)?;
            rx.blocking_send(inner_buf)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Channel failed to send"))?;
            Ok::<(usize, SockAddr), std::io::Error>((usize, socket_addr))
        })
        .await??;

        let inner_buf = tx.recv().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Channel failed to receive",
        ))?;

        buf[..len].copy_from_slice(&inner_buf[..len]);

        Ok((len, socket_addr))
    }

    pub async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        let socket = self.socket.clone();
        let cloned_data = data.to_vec();
        let res = tokio::task::spawn_blocking(move || {
            let socket = socket.blocking_lock();
            socket.send(cloned_data.as_ref())
        })
        .await??;

        Ok(res)
    }

    pub async fn connect(&self, addr: socket2::SockAddr) -> std::io::Result<()> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || {
            let socket = socket.blocking_lock();
            socket.connect(&addr)
        })
        .await??;

        Ok(())
    }

    pub async fn bind(&self, addr: socket2::SockAddr) -> std::io::Result<()> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || {
            let socket = socket.blocking_lock();
            socket.bind(&addr)
        })
        .await??;

        Ok(())
    }

    pub async fn set_ttl(&self, ttl: u32) -> std::io::Result<()> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || {
            let socket = socket.blocking_lock();
            socket.set_ttl(ttl)
        })
        .await??;

        Ok(())
    }

    pub async fn set_read_timeout(&self, timeout: std::time::Duration) -> std::io::Result<()> {
        self.socket.lock().await.set_read_timeout(Some(timeout))?;

        Ok(())
    }

    #[inline]
    pub async fn set_broadcast(&self, broadcast: bool) -> std::io::Result<()> {
        self.socket.lock().await.set_broadcast(broadcast)
    }
}
