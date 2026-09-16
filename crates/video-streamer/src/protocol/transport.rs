use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Context as _;
use bytes::Bytes;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};

use super::message::{ClientMessage, ServerMessage, UserFriendlyError, decode_client_message, encode_server_message};

#[derive(Debug)]
pub(super) enum ReceiveError<E> {
    Transport(E),
    Decode(anyhow::Error),
}

pub(super) struct CodecTransport<T> {
    inner: T,
}

impl<T> CodecTransport<T> {
    pub(super) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T, E> Stream for CodecTransport<T>
where
    T: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Error + Send + Sync + 'static,
{
    type Item = Result<ClientMessage, ReceiveError<E>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx).map(|incoming| {
            incoming.map(|result| match result {
                Ok(bytes) => decode_client_message(&bytes).map_err(ReceiveError::Decode),
                Err(error) => Err(ReceiveError::Transport(error)),
            })
        })
    }
}

impl<T, E> Sink<ServerMessage> for CodecTransport<T>
where
    T: Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, message: ServerMessage) -> Result<(), Self::Error> {
        Pin::new(&mut self.get_mut().inner).start_send(encode_server_message(message))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

pub(super) struct SessionTransport<T> {
    inner: T,
}

impl<T> SessionTransport<T> {
    pub(super) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T, E> SessionTransport<T>
where
    T: Stream<Item = Result<ClientMessage, ReceiveError<E>>> + Unpin,
    E: Error + Send + Sync + 'static,
{
    pub(super) async fn recv(&mut self) -> Option<Result<ClientMessage, ReceiveError<E>>> {
        self.inner.next().await
    }
}

impl<T, E> SessionTransport<T>
where
    T: Sink<ServerMessage, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    pub(super) async fn send(&mut self, message: ServerMessage) -> anyhow::Result<()> {
        self.inner
            .send(message)
            .await
            .map_err(anyhow::Error::new)
            .context("write server stream message")
    }

    pub(super) async fn reject(&mut self) {
        let _ = self
            .send(ServerMessage::Error(UserFriendlyError::UnexpectedError))
            .await;
    }
}
