mod mcs;
mod negotiation;
mod nla;
mod post_mcs;

pub use self::{
    mcs::{McsFuture, McsFutureTransport, McsInitialFuture, StaticChannels},
    negotiation::{create_negotiation_request, NegotiationWithClientFuture, NegotiationWithServerFuture},
    nla::{NlaWithClientFuture, NlaWithServerFuture},
    post_mcs::PostMcs,
};

use std::io;

use futures::{sink::Send, try_ready, Async, Future, Stream};
use tokio::{
    codec::{Decoder, Encoder, Framed},
    prelude::*,
};

pub trait SequenceFutureProperties<T, U>
where
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder,
{
    type Item;

    fn process_pdu(&mut self, pdu: <U as Decoder>::Item) -> io::Result<Option<<U as Encoder>::Item>>;
    fn return_item(&mut self, client: Option<Framed<T, U>>, server: Option<Framed<T, U>>) -> Self::Item;
    fn next_sender(&self) -> NextStream;
    fn next_receiver(&self) -> NextStream;
    fn sequence_finished(&self, future_state: FutureState) -> bool;
}

pub struct SequenceFuture<F, T, U>
where
    F: SequenceFutureProperties<T, U>,
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder>::Error>,
{
    future: F,
    client: Option<Framed<T, U>>,
    server: Option<Framed<T, U>>,
    send_future: Option<Send<Framed<T, U>>>,
    pdu: Option<<U as Decoder>::Item>,
    future_state: FutureState,
}

impl<F, T, U> SequenceFuture<F, T, U>
where
    F: SequenceFutureProperties<T, U>,
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder>::Error>,
{
    pub fn with_get_state(future: F, args: GetStateArgs<T, U>) -> Self {
        Self {
            future,
            client: args.client,
            server: args.server,
            send_future: None,
            pdu: None,
            future_state: FutureState::GetMessage,
        }
    }
    pub fn with_parse_state(future: F, args: ParseStateArgs<T, U>) -> Self {
        Self {
            future,
            client: args.client,
            server: args.server,
            send_future: None,
            pdu: Some(args.pdu),
            future_state: FutureState::ParseMessage,
        }
    }
    pub fn with_send_state(future: F, args: SendStateArgs<T, U>) -> Self {
        Self {
            future,
            client: None,
            server: None,
            send_future: Some(args.send_future),
            pdu: None,
            future_state: FutureState::SendMessage,
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
}

impl<F, T, U> Future for SequenceFuture<F, T, U>
where
    F: SequenceFutureProperties<T, U>,
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder,
    io::Error: From<<U as Decoder>::Error>,
    io::Error: From<<U as Encoder>::Error>,
{
    type Item = F::Item;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.future_state {
                FutureState::GetMessage => {
                    let sender = match self.future.next_sender() {
                        NextStream::Client => self
                            .client
                            .as_mut()
                            .expect("The client's stream must exist as the next sender"),
                        NextStream::Server => self
                            .server
                            .as_mut()
                            .expect("The server's stream must exist as the next sender"),
                    };

                    let (pdu, _) = try_ready!(sender.into_future().map_err(|(e, _)| e).poll());
                    self.pdu = Some(pdu.ok_or_else(|| {
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
                        self.send_future = Some(next_sender.send(next_pdu));
                    };
                }
                FutureState::SendMessage => {
                    let receiver = try_ready!(self
                        .send_future
                        .as_mut()
                        .expect("Send message state cannot be fired without send_future")
                        .poll());
                    let next_receiver = match self.future.next_receiver() {
                        NextStream::Client => &mut self.client,
                        NextStream::Server => &mut self.server,
                    };
                    next_receiver.replace(receiver);
                    self.send_future = None;
                }
                FutureState::Finished => {
                    return Ok(Async::Ready(
                        self.future.return_item(self.client.take(), self.server.take()),
                    ));
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

pub struct GetStateArgs<T, U>
where
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder,
{
    pub client: Option<Framed<T, U>>,
    pub server: Option<Framed<T, U>>,
}

pub struct ParseStateArgs<T, U>
where
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder,
{
    pub client: Option<Framed<T, U>>,
    pub server: Option<Framed<T, U>>,
    pub pdu: <U as Decoder>::Item,
}

pub struct SendStateArgs<T, U>
where
    T: AsyncRead + AsyncWrite,
    U: Decoder + Encoder,
{
    pub send_future: Send<Framed<T, U>>,
}
