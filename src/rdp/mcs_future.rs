use std::{collections::HashMap, io};

use futures::{sink::Send, try_ready, Async, Future, Poll, Stream};
use slog::{debug, info};
use tokio::{codec::Framed, prelude::*};
use tokio_tcp::TcpStream;
use tokio_tls::TlsStream;

use crate::transport::mcs::McsTransport;
use ironrdp::McsPdu;

pub type StaticChannels = HashMap<u16, String>;

type McsFutureTransport = Framed<TlsStream<TcpStream>, McsTransport>;

pub const GLOBAL_CHANNEL_NAME: &str = "GLOBAL";

const USER_CHANNEL_NAME: &str = "USER";

pub struct McsFuture {
    client: Option<McsFutureTransport>,
    server: Option<McsFutureTransport>,
    send_future: Option<Send<McsFutureTransport>>,
    future_state: FutureState,
    sequence_state: SequenceState,
    channels_to_join: StaticChannels,
    joined_channels: StaticChannels,
    client_logger: slog::Logger,
}

impl McsFuture {
    pub fn new(
        client: McsFutureTransport,
        server: McsFutureTransport,
        channels_to_join: StaticChannels,
        client_logger: slog::Logger,
    ) -> Self {
        let joined_channels =
            StaticChannels::with_capacity_and_hasher(channels_to_join.len(), channels_to_join.hasher().clone());
        Self {
            client: Some(client),
            server: Some(server),
            send_future: None,
            future_state: FutureState::GetMessage,
            sequence_state: SequenceState::ErectDomainRequest,
            channels_to_join,
            joined_channels,
            client_logger,
        }
    }

    fn process_pdu(&mut self, mcs_pdu: McsPdu) -> io::Result<(Send<McsFutureTransport>, SequenceState)> {
        match (self.sequence_state, mcs_pdu) {
            (SequenceState::ErectDomainRequest, McsPdu::ErectDomainRequest(pdu)) => Ok((
                self.server
                    .take()
                    .expect("In ErectDomainRequest sequence state the server stream must exist")
                    .send(McsPdu::ErectDomainRequest(pdu)),
                SequenceState::AttachUserRequest,
            )),
            (SequenceState::AttachUserRequest, McsPdu::AttachUserRequest) => Ok((
                self.server
                    .take()
                    .expect("In AttachUserRequest sequence state the server stream must exist")
                    .send(McsPdu::AttachUserRequest),
                SequenceState::AttachUserConfirm,
            )),
            (SequenceState::AttachUserConfirm, McsPdu::AttachUserConfirm(pdu)) => {
                self.channels_to_join
                    .insert(pdu.user_id, String::from(USER_CHANNEL_NAME));

                Ok((
                    self.client
                        .take()
                        .expect("In AttachUserConfirm sequence state the client stream must exist")
                        .send(McsPdu::AttachUserConfirm(pdu)),
                    SequenceState::ChannelJoinRequest,
                ))
            }
            (SequenceState::ChannelJoinRequest, McsPdu::ChannelJoinRequest(pdu)) => Ok((
                self.server
                    .take()
                    .expect("In ChannelJoinRequest sequence state the server stream must exist")
                    .send(McsPdu::ChannelJoinRequest(pdu)),
                SequenceState::ChannelJoinConfirm,
            )),
            (SequenceState::ChannelJoinConfirm, McsPdu::ChannelJoinConfirm(pdu)) => {
                if let Some((channel_id, channel_name)) = self.channels_to_join.remove_entry(&pdu.channel_id) {
                    self.joined_channels.insert(channel_id, channel_name);

                    let sequence_state = if self.channels_to_join.is_empty() {
                        SequenceState::Finished
                    } else {
                        SequenceState::ChannelJoinRequest
                    };

                    Ok((
                        self.client
                            .take()
                            .expect("In ChannelJoinConfirm sequence state the client stream must exist")
                            .send(McsPdu::ChannelJoinConfirm(pdu)),
                        sequence_state,
                    ))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Got unknown channel id during MCS connection sequence: {}",
                            pdu.channel_id,
                        ),
                    ))
                }
            }
            (state, pdu) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "MCS Connection Sequence state ({:?}) does not match received PDU ({:?})",
                    state,
                    pdu.as_short_name(),
                ),
            )),
        }
    }

    fn next_sender(&mut self) -> &mut McsFutureTransport {
        match self.sequence_state {
            SequenceState::ErectDomainRequest
            | SequenceState::AttachUserRequest
            | SequenceState::ChannelJoinRequest  => self
                .client
                .as_mut()
                .expect("In ErectDomainRequest/AttachUserRequest/ChannelJoinRequest sequence state the client stream must exist"),
            SequenceState::AttachUserConfirm | SequenceState::ChannelJoinConfirm  => {
                self.server.as_mut().expect("In AttachUserConfirm/ChannelJoinConfirm sequence state the server stream must exist")
            }
            SequenceState::Finished => unreachable!("The future must not require a next sender in the Finished sequence state")
        }
    }

    fn next_receiver(&mut self) -> &mut Option<McsFutureTransport> {
        match self.sequence_state {
            SequenceState::AttachUserRequest | SequenceState::AttachUserConfirm | SequenceState::ChannelJoinConfirm => {
                &mut self.server
            }
            SequenceState::ChannelJoinRequest | SequenceState::Finished => &mut self.client,
            SequenceState::ErectDomainRequest => unreachable!(
                "The future must not require a next receiver in the first sequence state (ErectDomainRequest)"
            ),
        }
    }

    fn next_future_state(&self) -> FutureState {
        match self.future_state {
            FutureState::GetMessage => FutureState::SendMessage,
            FutureState::SendMessage => match self.sequence_state {
                SequenceState::Finished => FutureState::Finished,
                _ => FutureState::GetMessage,
            },
            FutureState::Finished => {
                unreachable!("Next future state method cannot be fired with Finished future state")
            }
        }
    }
}

impl Future for McsFuture {
    type Item = (McsFutureTransport, McsFutureTransport, StaticChannels);
    type Error = ironrdp::McsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.future_state {
                FutureState::GetMessage => {
                    let sender = self.next_sender();

                    let (rdp_pdu, _) = try_ready!(sender.into_future().map_err(|(e, _)| e).poll());
                    let rdp_pdu = rdp_pdu.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "The stream was closed unexpectedly")
                    })?;
                    info!(self.client_logger, "Got MCS Sequence PDU: {}", rdp_pdu.as_short_name());
                    debug!(self.client_logger, "Got MCS Sequence PDU: {:?}", rdp_pdu);

                    let (send_future, sequence_state) = self.process_pdu(rdp_pdu)?;
                    self.send_future = Some(send_future);
                    self.sequence_state = sequence_state;
                }
                FutureState::SendMessage => {
                    let receiver = try_ready!(self
                        .send_future
                        .as_mut()
                        .expect("Send message state cannot be fired without send_future")
                        .poll());
                    self.next_receiver().replace(receiver);
                    self.send_future = None;
                }
                FutureState::Finished => {
                    return Ok(Async::Ready((
                        self.client.take().expect("Client stream must exist in the Finished future state, and the future state cannot be fired multiple times"),
                        self.server.take().expect("Server stream must exist in the Finished future state, and the future state cannot be fired multiple times"),
                        self.joined_channels.clone(),
                    )));
                }
            };
            self.future_state = self.next_future_state();
        }
    }
}

enum FutureState {
    GetMessage,
    SendMessage,
    Finished,
}

#[derive(Copy, Clone, Debug)]
enum SequenceState {
    ErectDomainRequest,
    AttachUserRequest,
    AttachUserConfirm,
    ChannelJoinRequest,
    ChannelJoinConfirm,
    Finished,
}
