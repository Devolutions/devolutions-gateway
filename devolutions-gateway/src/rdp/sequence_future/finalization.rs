use std::io;

use ironrdp::mcs::SendDataContext;
use ironrdp::{ControlAction, McsPdu, PduParsing, ShareControlHeader, ShareControlPdu, ShareDataHeader, ShareDataPdu};
use slog_scope::debug;
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_util::codec::Framed;

use super::{FutureState, NextStream, SequenceFutureProperties};
use crate::transport::rdp::{RdpPdu, RdpTransport};

type FinalizationTransport = Framed<TlsStream<TcpStream>, RdpTransport>;

pub struct Finalization {
    sequence_state: SequenceState,
}

impl Finalization {
    pub fn new() -> Self {
        Self {
            sequence_state: SequenceState::Finalization(FinalizationState::ClientSynchronize),
        }
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, RdpTransport, RdpPdu> for Finalization {
    type Item = (FinalizationTransport, FinalizationTransport);

    fn process_pdu(&mut self, rdp_pdu: RdpPdu) -> io::Result<Option<RdpPdu>> {
        let sequence_state = match self.sequence_state {
            SequenceState::Finalization(state)
            | SequenceState::OutOfSequence {
                previous_finalization_state: state,
            } => state,
        };

        let next_sequence_state = match rdp_pdu {
            RdpPdu::Data(ref data) => {
                let mcs_pdu = McsPdu::from_buffer(data.as_ref())?;

                match mcs_pdu {
                    McsPdu::SendDataRequest(SendDataContext { pdu_length, .. })
                    | McsPdu::SendDataIndication(SendDataContext { pdu_length, .. }) => {
                        let share_control_header = ShareControlHeader::from_buffer(&data[(data.len() - pdu_length)..])?;

                        if let ShareControlPdu::Data(ShareDataHeader { share_data_pdu, .. }) =
                            share_control_header.share_control_pdu
                        {
                            debug!("Got Finalization PDU: {:?}", share_data_pdu);

                            SequenceState::Finalization(next_finalization_state(sequence_state, &share_data_pdu)?)
                        } else {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "Got unexpected server's Share Control Header PDU: {:?}",
                                    share_control_header.share_control_pdu.as_short_name()
                                ),
                            ));
                        }
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Got MCS PDU during Finalization sequence: {}", mcs_pdu.as_short_name()),
                        ))
                    }
                }
            }
            RdpPdu::FastPathBytes(_) => SequenceState::OutOfSequence {
                previous_finalization_state: sequence_state,
            },
        };

        self.sequence_state = next_sequence_state;

        Ok(Some(rdp_pdu))
    }
    fn return_item(
        &mut self,
        mut client: Option<FinalizationTransport>,
        mut server: Option<FinalizationTransport>,
    ) -> Self::Item {
        debug!("Successfully processed Finalization sequence");

        (
            client.take().expect("The client's stream must exists"),
            server.take().expect("The server's stream must exists"),
        )
    }
    fn next_sender(&self) -> NextStream {
        match self.sequence_state {
            SequenceState::Finalization(state)
            | SequenceState::OutOfSequence {
                previous_finalization_state: state,
            } => match state {
                FinalizationState::ClientSynchronize
                | FinalizationState::ClientControlCooperate
                | FinalizationState::ClientRequestControl
                | FinalizationState::ClientFontList => NextStream::Client,
                FinalizationState::ServerSynchronize
                | FinalizationState::ServerControlCooperate
                | FinalizationState::ServerGrantedControl
                | FinalizationState::ServerFontMap => NextStream::Server,
                FinalizationState::Finished => {
                    panic!("The future must not require a next sender in the Finished sequence state")
                }
            },
        }
    }
    fn next_receiver(&self) -> NextStream {
        match self.sequence_state {
            SequenceState::Finalization(state) => match state {
                FinalizationState::ServerSynchronize
                | FinalizationState::ServerControlCooperate
                | FinalizationState::ServerGrantedControl
                | FinalizationState::ServerFontMap => NextStream::Server,
                FinalizationState::ClientControlCooperate
                | FinalizationState::ClientRequestControl
                | FinalizationState::ClientFontList
                | FinalizationState::Finished => NextStream::Client,
                FinalizationState::ClientSynchronize => unreachable!(
                    "The future must not require a next receiver in the first sequence state (ClientSynchronize)"
                ),
            },
            SequenceState::OutOfSequence {
                previous_finalization_state,
            } => match previous_finalization_state {
                FinalizationState::ServerSynchronize
                | FinalizationState::ServerControlCooperate
                | FinalizationState::ServerGrantedControl
                | FinalizationState::ServerFontMap => NextStream::Client,
                FinalizationState::ClientControlCooperate
                | FinalizationState::ClientRequestControl
                | FinalizationState::ClientFontList
                | FinalizationState::ClientSynchronize => NextStream::Server,
                FinalizationState::Finished => unreachable!(
                    "The future must not require a next receiver in the last sequence state for an out of sequence PDU"
                ),
            },
        }
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        match self.sequence_state {
            SequenceState::Finalization(state) => {
                future_state == FutureState::SendMessage && state == FinalizationState::Finished
            }
            SequenceState::OutOfSequence { .. } => false,
        }
    }
}

fn next_finalization_state(state: FinalizationState, share_data_pdu: &ShareDataPdu) -> io::Result<FinalizationState> {
    match (state, &share_data_pdu) {
        (FinalizationState::ClientSynchronize, ShareDataPdu::Synchronize(_)) => {
            Ok(FinalizationState::ServerSynchronize)
        }
        (FinalizationState::ServerSynchronize, ShareDataPdu::Synchronize(_)) => {
            Ok(FinalizationState::ClientControlCooperate)
        }
        (FinalizationState::ClientRequestControl, ShareDataPdu::Control(control_pdu))
            if control_pdu.action == ControlAction::RequestControl =>
        {
            Ok(FinalizationState::ServerGrantedControl)
        }
        (FinalizationState::ClientControlCooperate, ShareDataPdu::Control(control_pdu))
            if control_pdu.action == ControlAction::Cooperate =>
        {
            Ok(FinalizationState::ServerControlCooperate)
        }
        (FinalizationState::ServerControlCooperate, ShareDataPdu::Control(control_pdu))
            if control_pdu.action == ControlAction::Cooperate =>
        {
            Ok(FinalizationState::ClientRequestControl)
        }
        (FinalizationState::ServerGrantedControl, ShareDataPdu::Control(control_pdu))
            if control_pdu.action == ControlAction::GrantedControl =>
        {
            Ok(FinalizationState::ClientFontList)
        }
        (FinalizationState::ClientFontList, ShareDataPdu::FontList(_)) => Ok(FinalizationState::ServerFontMap),
        (FinalizationState::ServerFontMap, ShareDataPdu::FontMap(_)) => Ok(FinalizationState::Finished),
        (state, pdu) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Got Finalization PDU ({:?}) in invalid sequence state ({:?})",
                pdu.as_short_name(),
                state
            ),
        )),
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum FinalizationState {
    ClientSynchronize,
    ServerSynchronize,
    ClientControlCooperate,
    ServerControlCooperate,
    ClientRequestControl,
    ServerGrantedControl,
    ClientFontList,
    ServerFontMap,
    Finished,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum SequenceState {
    Finalization(FinalizationState),
    OutOfSequence {
        previous_finalization_state: FinalizationState,
    },
}
