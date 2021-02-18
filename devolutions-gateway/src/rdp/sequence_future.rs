mod dvc_capabilities;
mod finalization;
mod mcs;
mod negotiation;
mod nla;
mod post_mcs;

pub use self::dvc_capabilities::{create_downgrade_dvc_capabilities_future, DowngradeDvcCapabilitiesFuture};
pub use self::finalization::Finalization;
pub use self::mcs::{McsFuture, McsFutureTransport, McsInitialFuture, StaticChannels};
pub use self::negotiation::{create_negotiation_request, NegotiationWithClientFuture, NegotiationWithServerFuture};
pub use self::nla::{NlaTransport, NlaWithClientFuture, NlaWithServerFuture};
pub use self::post_mcs::{PostMcs, PostMcsFutureTransport};

use std::io;
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{ready, Future, SinkExt, Stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};

type SendFuture<T, U> = Box<dyn Future<Output = Result<Framed<T, U>, io::Error>> + Send + 'static>;

pub trait SequenceFutureProperties<T, U, R>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: Decoder + Encoder<R> + Send + Unpin + 'static,
    R: 'static,
{
    type Item;

    fn process_pdu(&mut self, pdu: <U as Decoder>::Item) -> io::Result<Option<R>>;
    fn return_item(&mut self, client: Option<Framed<T, U>>, server: Option<Framed<T, U>>) -> Self::Item;
    fn next_sender(&self) -> NextStream;
    fn next_receiver(&self) -> NextStream;
    fn sequence_finished(&self, future_state: FutureState) -> bool;
}

pub struct SequenceFuture<F, T, U, R>
where
    F: SequenceFutureProperties<T, U, R> + Send + Unpin,
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: Decoder + Encoder<R> + Send + Unpin + 'static,
    R: Send + Unpin + 'static,
    <U as Decoder>::Item: Send + Unpin + 'static,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder<R>>::Error>,
{
    future: F,
    client: Option<Framed<T, U>>,
    server: Option<Framed<T, U>>,
    send_future: Option<Pin<SendFuture<T, U>>>,
    pdu: Option<<U as Decoder>::Item>,
    future_state: FutureState,
    phantom_data: PhantomData<R>,
}

impl<F, T, U, R> SequenceFuture<F, T, U, R>
where
    F: SequenceFutureProperties<T, U, R> + Send + Unpin + 'static,
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: Decoder + Encoder<R> + Send + Unpin + 'static,
    R: Send + Unpin + 'static,
    <U as Decoder>::Item: Send + Unpin + 'static,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder<R>>::Error>,
{
    pub fn with_get_state(future: F, args: GetStateArgs<T, U, R>) -> Self {
        Self {
            future,
            client: args.client,
            server: args.server,
            send_future: None,
            pdu: None,
            future_state: FutureState::GetMessage,
            phantom_data: PhantomData,
        }
    }

    pub fn with_parse_state(future: F, args: ParseStateArgs<T, U, R>) -> Self {
        Self {
            future,
            client: args.client,
            server: args.server,
            send_future: None,
            pdu: Some(args.pdu),
            future_state: FutureState::ParseMessage,
            phantom_data: PhantomData,
        }
    }

    pub fn with_send_state(future: F, args: SendStateArgs<T, U, R>) -> Self {
        Self {
            future,
            client: None,
            server: None,
            send_future: Some(Box::pin(args.send_future)),
            pdu: None,
            future_state: FutureState::SendMessage,
            phantom_data: PhantomData,
        }
    }

    fn next_future_state(&self) -> FutureState {
        if self.future.sequence_finished(self.future_state) {
            FutureState::Finished
        } else {
            match self.future_state {
                FutureState::GetMessage => FutureState::ParseMessage,
                FutureState::ParseMessage => FutureState::SendMessage,
                FutureState::SendMessage => FutureState::GetMessage,
                FutureState::Finished => {
                    panic!("next_future_state method cannot be fired in the Finished future state")
                }
            }
        }
    }

    async fn make_send_future(mut receiver: Framed<T, U>, item: R) -> Result<Framed<T, U>, io::Error> {
        Pin::new(&mut receiver).send(item).await?;
        Ok(receiver)
    }
}

impl<F, T, U, R> Future for SequenceFuture<F, T, U, R>
where
    F: SequenceFutureProperties<T, U, R> + Send + Unpin + 'static,
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: Decoder + Encoder<R> + Send + Unpin + 'static,
    <U as Decoder>::Item: Send + Unpin + 'static,
    R: Send + Unpin + 'static,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder<R>>::Error>,
{
    type Output = Result<F::Item, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.future_state {
                FutureState::GetMessage => {
                    let Self {
                        client,
                        server,
                        pdu,
                        future,
                        ..
                    } = self.deref_mut();

                    let prev_pdu = pdu;
                    let sender = match future.next_sender() {
                        NextStream::Client => client
                            .as_mut()
                            .expect("The client's stream must exist as the next sender"),
                        NextStream::Server => server
                            .as_mut()
                            .expect("The server's stream must exist as the next sender"),
                    };

                    // The following is safe, as sender ref will not be moved between single
                    // state polls of pinned Self (SequenceFuture)
                    let pinned_sender = unsafe { Pin::new_unchecked(sender) };

                    let pdu = ready!(pinned_sender.poll_next(cx)).transpose()?;

                    prev_pdu.replace(pdu.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "The stream was closed unexpectedly")
                    })?);
                }
                FutureState::ParseMessage => {
                    let pdu = self
                        .pdu
                        .take()
                        .expect("next_pdu must be present in the Parse message future state");
                    if let Some(next_pdu) = self.future.process_pdu(pdu)? {
                        let next_sender = match self.future.next_receiver() {
                            NextStream::Client => self
                                .client
                                .take()
                                .expect("The client's stream must exist as the next receiver"),
                            NextStream::Server => self
                                .server
                                .take()
                                .expect("The server's stream must exist as the next receiver"),
                        };

                        self.send_future = Some(Box::pin(Self::make_send_future(next_sender, next_pdu)));
                    };
                }
                FutureState::SendMessage => {
                    let Self {
                        client,
                        server,
                        future,
                        send_future,
                        ..
                    } = self.deref_mut();
                    let receiver = ready!(send_future
                        .as_mut()
                        .expect("Send message state cannot be fired without send_future")
                        .as_mut()
                        .poll(cx))?;

                    let next_receiver = match future.next_receiver() {
                        NextStream::Client => client,
                        NextStream::Server => server,
                    };
                    next_receiver.replace(receiver);
                    self.send_future = None;
                }
                FutureState::Finished => {
                    let Self {
                        client, server, future, ..
                    } = self.deref_mut();

                    return Poll::Ready(Ok(future.return_item(client.take(), server.take())));
                }
            };
            self.future_state = self.next_future_state();
        }
    }
}

#[derive(Copy, Clone)]
pub enum NextStream {
    Client,
    Server,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FutureState {
    GetMessage,
    ParseMessage,
    SendMessage,
    Finished,
}

pub struct GetStateArgs<T, U, P>
where
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder<P>,
{
    pub client: Option<Framed<T, U>>,
    pub server: Option<Framed<T, U>>,
    pub phantom_data: PhantomData<P>,
}

pub struct ParseStateArgs<T, U, P>
where
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder<P>,
{
    pub client: Option<Framed<T, U>>,
    pub server: Option<Framed<T, U>>,
    pub pdu: <U as Decoder>::Item,
    pub phantom_data: PhantomData<P>,
}

pub struct SendStateArgs<T, U, P>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
    U: Decoder + Encoder<P> + Send + Unpin,
{
    pub send_future: Pin<SendFuture<T, U>>,
    pub phantom_data: PhantomData<P>,
}
