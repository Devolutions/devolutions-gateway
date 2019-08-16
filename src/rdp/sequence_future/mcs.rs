use std::{collections::HashMap, io, iter};

use bytes::BytesMut;
use ironrdp::{gcc, ConnectInitial, ConnectResponse, McsPdu, PduParsing};
use slog::{debug, info};
use tokio::codec::Framed;
use tokio_tcp::TcpStream;
use tokio_tls::TlsStream;

use super::{FutureState, NextStream, SequenceFutureProperties};
use crate::{
    rdp::filter::{Filter, FilterConfig},
    transport::{mcs::McsTransport, x224::DataTransport},
};

pub type StaticChannels = HashMap<u16, String>;
pub type McsFutureTransport = Framed<TlsStream<TcpStream>, McsTransport>;

type X224FutureTransport = Framed<TlsStream<TcpStream>, DataTransport>;

pub const GLOBAL_CHANNEL_NAME: &str = "GLOBAL";
pub const USER_CHANNEL_NAME: &str = "USER";

pub struct McsFuture {
    sequence_state: McsSequenceState,
    channels_to_join: StaticChannels,
    joined_channels: Option<StaticChannels>,
}

impl McsFuture {
    pub fn new(channels_to_join: StaticChannels) -> Self {
        let joined_channels =
            StaticChannels::with_capacity_and_hasher(channels_to_join.len(), channels_to_join.hasher().clone());
        Self {
            sequence_state: McsSequenceState::ErectDomainRequest,
            channels_to_join,
            joined_channels: Some(joined_channels),
        }
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, McsTransport> for McsFuture {
    type Item = (McsFutureTransport, McsFutureTransport, StaticChannels);

    fn process_pdu(&mut self, mcs_pdu: McsPdu, client_logger: &slog::Logger) -> io::Result<Option<McsPdu>> {
        info!(client_logger, "Got MCS Sequence PDU: {}", mcs_pdu.as_short_name());
        debug!(client_logger, "Got MCS Sequence PDU: {:?}", mcs_pdu);

        let (next_sequence_state, result) = match (self.sequence_state, mcs_pdu) {
            (McsSequenceState::ErectDomainRequest, McsPdu::ErectDomainRequest(pdu)) => {
                (McsSequenceState::AttachUserRequest, McsPdu::ErectDomainRequest(pdu))
            }
            (McsSequenceState::AttachUserRequest, McsPdu::AttachUserRequest) => {
                (McsSequenceState::AttachUserConfirm, McsPdu::AttachUserRequest)
            }
            (McsSequenceState::AttachUserConfirm, McsPdu::AttachUserConfirm(pdu)) => {
                self.channels_to_join
                    .insert(pdu.initiator_id, String::from(USER_CHANNEL_NAME));

                (McsSequenceState::ChannelJoinRequest, McsPdu::AttachUserConfirm(pdu))
            }
            (McsSequenceState::ChannelJoinRequest, McsPdu::ChannelJoinRequest(pdu)) => {
                (McsSequenceState::ChannelJoinConfirm, McsPdu::ChannelJoinRequest(pdu))
            }
            (McsSequenceState::ChannelJoinConfirm, McsPdu::ChannelJoinConfirm(pdu)) => {
                if let Some((channel_id, channel_name)) = self.channels_to_join.remove_entry(&pdu.channel_id) {
                    self.joined_channels
                        .as_mut()
                        .expect("Joined channels must exist in the ChannelJoinConfirm sequence state")
                        .insert(channel_id, channel_name);

                    let sequence_state = if self.channels_to_join.is_empty() {
                        McsSequenceState::Finished
                    } else {
                        McsSequenceState::ChannelJoinRequest
                    };

                    (sequence_state, McsPdu::ChannelJoinConfirm(pdu))
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Got unknown channel id during MCS connection sequence: {}",
                            pdu.channel_id,
                        ),
                    ));
                }
            }
            (state, pdu) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "MCS Connection Sequence state ({:?}) does not match received PDU ({:?})",
                        state,
                        pdu.as_short_name(),
                    ),
                ))
            }
        };

        self.sequence_state = next_sequence_state;

        Ok(Some(result))
    }
    fn return_item(
        &mut self,
        mut client: Option<McsFutureTransport>,
        mut server: Option<McsFutureTransport>,
        client_logger: &slog::Logger,
    ) -> Self::Item {
        info!(client_logger, "Successfully processed MCS Connection Sequence");

        (
            client.take().expect(
                "In MCS Connection Sequence, the client's stream must exist in a return_item method, and the method cannot be fired multiple times",
            ),
            server.take().expect(
                "In MCS Connection Sequence, the server's stream must exist in a return_item method, and the method cannot be fired multiple times",
            ),
            self.joined_channels.take().expect(
                "In MCS Connection Sequence, joined channels must exist in a return_item method, and the method cannot be fired multiple times",
            ),
        )
    }
    fn next_sender(&self) -> NextStream {
        match self.sequence_state {
            McsSequenceState::ErectDomainRequest
            | McsSequenceState::AttachUserRequest
            | McsSequenceState::ChannelJoinRequest => NextStream::Client,
            McsSequenceState::AttachUserConfirm | McsSequenceState::ChannelJoinConfirm => NextStream::Server,
            McsSequenceState::Finished => unreachable!(
                "In MCS Connection Sequence, the future must not require a next sender in the Finished sequence state"
            ),
        }
    }
    fn next_receiver(&self) -> NextStream {
        match self.sequence_state {
            McsSequenceState::AttachUserRequest
            | McsSequenceState::AttachUserConfirm
            | McsSequenceState::ChannelJoinConfirm => NextStream::Server,
            McsSequenceState::ChannelJoinRequest | McsSequenceState::Finished => NextStream::Client,
            McsSequenceState::ErectDomainRequest => unreachable!(
                "The future must not require a next receiver in the first sequence state (ErectDomainRequest)"
            ),
        }
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        future_state == FutureState::SendMessage && self.sequence_state == McsSequenceState::Finished
    }
}

#[derive(Copy, Clone, PartialEq)]
enum McsInitialSequenceState {
    ConnectInitial,
    ConnectResponse,
    Finished,
}

pub struct McsInitialFuture {
    sequence_state: McsInitialSequenceState,
    filter_config: Option<FilterConfig>,
    channel_names: Option<Vec<gcc::Channel>>,
    channel_ids: Option<Vec<u16>>,
    global_channel_id: u16,
}

impl McsInitialFuture {
    pub fn new(filter_config: FilterConfig) -> Self {
        Self {
            sequence_state: McsInitialSequenceState::ConnectInitial,
            filter_config: Some(filter_config),
            channel_names: None,
            channel_ids: None,
            global_channel_id: 0,
        }
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, DataTransport> for McsInitialFuture {
    type Item = (X224FutureTransport, X224FutureTransport, FilterConfig, StaticChannels);

    fn process_pdu(&mut self, data: BytesMut, client_logger: &slog::Logger) -> io::Result<Option<BytesMut>> {
        let (next_sequence_state, result) = match self.sequence_state {
            McsInitialSequenceState::ConnectInitial => {
                let mut connect_initial = ConnectInitial::from_buffer(data.as_ref())?;
                info!(client_logger, "Got MCS Connect Initial PDU");
                debug!(client_logger, "Got MCS Connect Initial PDU: {:?}", connect_initial);

                connect_initial.filter(
                    self.filter_config
                        .as_ref()
                        .expect("The filter config must exist for filtering the Connect Initial PDU"),
                );
                debug!(client_logger, "Filtered Connect Initial PDU: {:?}", connect_initial);

                let mut connect_initial_buffer = BytesMut::with_capacity(connect_initial.buffer_length());
                connect_initial_buffer.resize(connect_initial.buffer_length(), 0x00);
                connect_initial.to_buffer(connect_initial_buffer.as_mut())?;

                self.channel_names = Some(connect_initial.channel_names());

                (McsInitialSequenceState::ConnectResponse, connect_initial_buffer)
            }
            McsInitialSequenceState::ConnectResponse => {
                let mut connect_response = ConnectResponse::from_buffer(data.as_ref())?;
                info!(client_logger, "Got MCS Connect Response PDU");
                debug!(client_logger, "Got MCS Connect Response PDU: {:?}", connect_response);

                connect_response.filter(
                    self.filter_config
                        .as_ref()
                        .expect("The filter config must exist for filtering the Connect Response PDU"),
                );
                debug!(client_logger, "Filtered Connect Response PDU: {:?}", connect_response);

                let mut connect_response_buffer = BytesMut::new();
                connect_response_buffer.resize(connect_response.buffer_length(), 0);
                connect_response.to_buffer(connect_response_buffer.as_mut())?;

                self.channel_ids = Some(connect_response.channel_ids());
                self.global_channel_id = connect_response.global_channel_id();

                (McsInitialSequenceState::Finished, connect_response_buffer)
            }
            McsInitialSequenceState::Finished => {
                unreachable!("The McsInitialFuture process_pdu method must not be fired in Finished state")
            }
        };

        self.sequence_state = next_sequence_state;

        Ok(Some(result))
    }
    fn return_item(
        &mut self,
        mut client: Option<X224FutureTransport>,
        mut server: Option<X224FutureTransport>,
        client_logger: &slog::Logger,
    ) -> Self::Item {
        info!(client_logger, "Successfully processed MCS initial PDUs");

        let channel_names = self
            .channel_names
            .take()
            .expect("In MCS Connect Initial PDU processing, the channel names must be set during process_pdu method");
        let channel_ids = self
            .channel_ids
            .take()
            .expect("In MCS Connect Response PDU processing, the channel ids must be set in the process_pdu method");
        let global_channel_id = self.global_channel_id;

        let static_channels = channel_ids
            .into_iter()
            .zip(channel_names.into_iter().map(|v| v.name))
            .chain(iter::once((global_channel_id, GLOBAL_CHANNEL_NAME.to_string())))
            .collect::<StaticChannels>();
        debug!(client_logger, "Static channels: {:?}", static_channels);

        (
        client.take().expect(
            "In MCS initial PDUs processing, the client's stream must exist in a return_item method, and the method cannot be fired multiple times",
        ),
        server.take().expect(
            "In MCS initial PDUs processing, the server's stream must exist in a return_item method, and the method cannot be fired multiple times",
        ),
            self.filter_config.take().expect(
                "In MCS initial PDUs processing, the filter config must exist in a return_item method, and the method cannot be fired multiple times",
            ),
            static_channels,
        )
    }
    fn next_sender(&self) -> NextStream {
        match self.sequence_state {
            McsInitialSequenceState::ConnectInitial => NextStream::Client,
            McsInitialSequenceState::ConnectResponse => NextStream::Server,
            McsInitialSequenceState::Finished => unreachable!(
                "In MCS initial PDUs processing, the future must not require a next sender in the Finished sequence state"
            ),
        }
    }
    fn next_receiver(&self) -> NextStream {
        match self.sequence_state {
            McsInitialSequenceState::ConnectResponse => NextStream::Server,
            McsInitialSequenceState::Finished => NextStream::Client,
            McsInitialSequenceState::ConnectInitial => {
                unreachable!("The future must not require a next receiver in the first sequence state (ConnectInitial)")
            }
        }
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        future_state == FutureState::SendMessage && self.sequence_state == McsInitialSequenceState::Finished
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum McsSequenceState {
    ErectDomainRequest,
    AttachUserRequest,
    AttachUserConfirm,
    ChannelJoinRequest,
    ChannelJoinConfirm,
    Finished,
}
