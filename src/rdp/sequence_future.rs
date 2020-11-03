// mod dvc_capabilities;
// mod finalization;
// mod mcs;
// mod negotiation;
// mod nla;
// mod post_mcs;

// pub use self::{
//     dvc_capabilities::{create_downgrade_dvc_capabilities_future, DowngradeDvcCapabilitiesFuture},
//     finalization::Finalization,
//     mcs::{McsFuture, McsFutureTransport, McsInitialFuture, StaticChannels},
//     negotiation::{create_negotiation_request, NegotiationWithClientFuture, NegotiationWithServerFuture},
//     nla::{NlaTransport, NlaWithClientFuture, NlaWithServerFuture},
//     post_mcs::{PostMcs, PostMcsFutureTransport},
// };

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    marker::PhantomData,
    ops::DerefMut,
};

use futures::{
    SinkExt,
    sink::Send,
    Future,
    Stream,
    ready,
    pin_mut,
};
use tokio::io::{
    AsyncRead,
    AsyncWrite,
};
use tokio_util::codec::{Decoder, Encoder, Framed};


pub trait SequenceFutureProperties<T, U, P>
where
    T: AsyncRead + AsyncWrite + Unpin + 'static,
    U: Decoder + Encoder<P> + Unpin + 'static,
{
    type Item;

    fn process_pdu(&mut self, pdu: <U as Decoder>::Item) -> io::Result<Option<P>>;
    fn return_item(&mut self, client: Option<Framed<T, U>>, server: Option<Framed<T, U>>) -> Self::Item;
    fn next_sender(&self) -> NextStream;
    fn next_receiver(&self) -> NextStream;
    fn sequence_finished(&self, future_state: FutureState) -> bool;
}

pub struct SequenceFuture<F, T, U, P>
where
    F: SequenceFutureProperties<T, U, P> + Unpin + 'static,
    T: AsyncRead + AsyncWrite + Unpin + 'static,
    U: Decoder + Encoder<P> + Unpin + 'static,
    P: Unpin + 'static,
    <U as Decoder>::Item: Unpin + 'static,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder<P>>::Error>,
{
    future: F,
    client: Option<Framed<T, U>>,
    server: Option<Framed<T, U>>,
    send_future: Option<Pin<Box<dyn Future<Output = Result<Framed<T, U>, io::Error>>>>>,
    pdu: Option<<U as Decoder>::Item>,
    future_state: FutureState,
    phantom_data: PhantomData<P>,
}

impl<F, T, U, P> SequenceFuture<F, T, U, P>
where
    F: SequenceFutureProperties<T, U, P> + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
    U: Decoder + Encoder<P> + Unpin,
    P: Unpin,
    <U as Decoder>::Item: Unpin + 'static,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder<P>>::Error>,
{
    pub fn with_get_state(future: F, args: GetStateArgs<T, U, P>) -> Self {
        Self {
            future,
            client: args.client,
            server: args.server,
            send_future: None,
            pdu: None,
            future_state: FutureState::GetMessage,
            phantom_data: PhantomData::default(),
        }
    }

    pub fn with_parse_state(future: F, args: ParseStateArgs<T, U, P>) -> Self {
        Self {
            future,
            client: args.client,
            server: args.server,
            send_future: None,
            pdu: Some(args.pdu),
            future_state: FutureState::ParseMessage,
            phantom_data: PhantomData::default(),
        }
    }

    pub fn with_send_state(future: F, args: SendStateArgs<T, U, P>) -> Self {
        Self {
            future,
            client: None,
            server: None,
            send_future: Some(Box::pin(args.send_future)),
            pdu: None,
            future_state: FutureState::SendMessage,
            phantom_data: PhantomData::default(),
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

    async fn make_send_future(mut receiver: Framed<T, U>, item: P) -> Result<Framed<T, U>, io::Error> {
        Pin::new(&mut receiver).send(item).await?;
        Ok(receiver)
    }
}

impl<F, T, U, P> Future for SequenceFuture<F, T, U, P>
where
    F: SequenceFutureProperties<T, U, P> + Unpin + 'static,
    T: AsyncRead + AsyncWrite + Unpin + 'static,
    U: Decoder + Encoder<P> + Unpin + 'static,
    <U as Decoder>::Item: Unpin + 'static,
    P: Unpin,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder<P>>::Error>,
{
    type Output = Result<F::Item, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.future_state {
                FutureState::GetMessage => {
                    let (client, server, mut prev_pdu, future) = match self.deref_mut() {
                        Self {client, server, pdu, future, ..} => {
                            (client, server, pdu, future)
                        }
                    };

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
                        let mut next_sender = match self.future.next_receiver() {
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
                    let (client, server, future, mut send_future) = match self.deref_mut() {
                        Self {client, server, future, send_future, ..} => {
                            (client, server, future, send_future)
                        }
                    };

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
                    let (mut client, mut server, mut future) = match self.deref_mut() {
                        Self {client, server, future, ..} => {
                            (client, server, future)
                        }
                    };

                    return Poll::Ready(Ok(future.return_item(client.take(), client.take())));
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
    T: AsyncRead + AsyncWrite + Unpin,
    U: Decoder + Encoder<P> + Unpin,
{
    pub send_future: Pin<Box<dyn Future<Output = Result<Framed<T, U>, io::Error>>>>,
    pub phantom_data: PhantomData<P>,
}
