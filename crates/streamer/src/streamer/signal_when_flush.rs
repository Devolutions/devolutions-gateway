use std::{future::Future, pin::Pin, task::Poll};

use tracing::{debug, warn};

pub struct SignalWriter<W> {
    writer: W,
    sender: tokio::sync::mpsc::Sender<()>,
}

impl<W> SignalWriter<W> {
    pub fn new(writer: W) -> (Self, tokio::sync::mpsc::Receiver<()>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        (Self { writer, sender }, receiver)
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

        let send_future = self.sender.send(());
        match Box::pin(send_future).as_mut().poll(cx) {
            Poll::Ready(Err(e)) => {
                debug!("error sending signal: {}", e);
            }
            Poll::Pending => {
                warn!("flushed but failed to send signal");
            }
            _ => {}
        };

        Poll::Ready(res)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.writer), cx)
    }
}
