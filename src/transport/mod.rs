use futures::Future;
use tokio::io;
use futures::{Stream, Sink};
use url::Url;

pub mod tcp;

pub type JetFuture<T> = Box<Future<Item = T, Error = io::Error> + Send>;
pub type JetStream<T> = Box<Stream<Item = T, Error = io::Error> + Send>;
pub type JetSink<T> = Box<Sink<SinkItem = T, SinkError = io::Error> + Send>;

pub trait Transport {
    fn connect(addr: &Url) -> JetFuture<Self>
    where
        Self: Sized;
    fn message_sink(&self) -> JetSink<Vec<u8>>;
    fn message_stream(&self) -> JetStream<Vec<u8>>;
}

