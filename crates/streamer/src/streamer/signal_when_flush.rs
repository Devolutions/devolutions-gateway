use std::{sync::Arc, task::Poll};

pub struct SignalWriter<W> {
    writer: W,
    pub notify: Arc<tokio::sync::Notify>,
}

impl<W> SignalWriter<W> {
    pub fn new(writer: W) -> Self {
        let notify = Arc::new(tokio::sync::Notify::new());
        Self { writer, notify }
    }
}

impl<W> tokio::io::AsyncWrite for SignalWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.writer), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let Poll::Ready(res) = tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.writer), cx) else {
            return Poll::Pending;
        };

        self.notify.notify_waiters();
        Poll::Ready(res)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.writer), cx)
    }
}
