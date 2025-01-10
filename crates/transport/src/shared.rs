use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_core::Stream;
use futures_sink::Sink;

use crate::PinnableMutex;

pub struct Shared<S> {
    inner: Pin<Arc<PinnableMutex<S>>>,
}

impl<S> Shared<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: Arc::pin(PinnableMutex::new(stream)),
        }
    }

    #[must_use]
    pub fn shared(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Stream for Shared<S>
where
    S: Stream<Item = T>,
{
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_ref().lock().as_mut().poll_next(cx)
    }
}

impl<S, T, E> Sink<T> for Shared<S>
where
    S: Sink<T, Error = E>,
{
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.as_ref().lock().as_mut().poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.inner.as_ref().lock().as_mut().start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.as_ref().lock().as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.as_ref().lock().as_mut().poll_close(cx)
    }
}
