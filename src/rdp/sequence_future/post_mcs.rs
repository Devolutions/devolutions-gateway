use std::io;

use ironrdp::{
    mcs::SendDataContext, ClientInfoPdu, ClientLicensePdu, ControlAction, McsPdu, PduParsing, ShareControlHeader,
    ShareControlPdu, ShareDataHeader, ShareDataPdu,
};
use slog::{debug, info};
use tokio::codec::Framed;
use tokio_tcp::TcpStream;
use tokio_tls::TlsStream;

use super::{FutureState, NextStream, SequenceFutureProperties};
use crate::{
    rdp::filter::{Filter, FilterConfig},
    transport::mcs::McsTransport,
};

type McsFutureTransport = Framed<TlsStream<TcpStream>, McsTransport>;

pub struct PostMcs {
    sequence_state: SequenceState,
    filter: Option<FilterConfig>,
}

impl PostMcs {
    pub fn new(filter: FilterConfig) -> Self {
        Self {
            sequence_state: SequenceState::ClientInfo,
            filter: Some(filter),
        }
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, McsTransport> for PostMcs {
    type Item = (McsFutureTransport, McsFutureTransport, FilterConfig);

    fn process_pdu(&mut self, mcs_pdu: McsPdu, client_logger: &slog::Logger) -> io::Result<Option<McsPdu>> {
        let client_logger = client_logger.clone();
        let filter = self.filter.as_ref().expect(
            "The filter must exist in the client's RDP Connection Sequence, and must be taken only in the Finished state",
        );

        let (next_sequence_state, result) = match mcs_pdu {
            McsPdu::SendDataRequest(SendDataContext {
                pdu,
                initiator_id,
                channel_id,
            }) => {
                let (next_sequence_state, pdu) =
                    process_send_data_request_pdu(pdu, self.sequence_state, client_logger, filter)?;

                (
                    next_sequence_state,
                    McsPdu::SendDataRequest(SendDataContext {
                        pdu,
                        initiator_id,
                        channel_id,
                    }),
                )
            }

            McsPdu::SendDataIndication(SendDataContext {
                pdu,
                initiator_id,
                channel_id,
            }) => {
                let (next_sequence_state, pdu) =
                    process_send_data_indication_pdu(pdu, self.sequence_state, client_logger, filter)?;

                (
                    next_sequence_state,
                    McsPdu::SendDataIndication(SendDataContext {
                        pdu,
                        initiator_id,
                        channel_id,
                    }),
                )
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Got MCS PDU during RDP Connection Sequence: {}",
                        mcs_pdu.as_short_name()
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
        info!(client_logger, "Successfully processed RDP Connection Sequence");

        (
            client.take().expect(
                "In RDP Connection Sequence, the client's stream must exist in a return_item method, and the method cannot be fired multiple times"),
            server.take().expect(
                "In RDP Connection Sequence, the server's stream must exist in a return_item method, and the method cannot be fired multiple times"),
            self.filter.take().expect(
                "In RDP Connection Sequence, the filter must exist in a return_item method, and the method cannot be fired multiple times"),
        )
    }
    fn next_sender(&self) -> NextStream {
        match self.sequence_state {
            SequenceState::ClientInfo
            | SequenceState::ClientConfirmActive
            | SequenceState::ClientSynchronize
            | SequenceState::ClientControlCooperate
            | SequenceState::ClientRequestControl
            | SequenceState::ClientFontList => NextStream::Client,
            SequenceState::Licensing
            | SequenceState::ServerDemandActive
            | SequenceState::ServerSynchronize
            | SequenceState::ServerControlCooperate
            | SequenceState::ServerGrantedControl
            | SequenceState::ServerFontMap => NextStream::Server,
            SequenceState::Finished => unreachable!(
                "In RDP Connection Sequence, the future must not require a next sender in the Finished sequence state"
            ),
        }
    }
    fn next_receiver(&self) -> NextStream {
        match self.sequence_state {
            SequenceState::Licensing
            | SequenceState::ClientSynchronize
            | SequenceState::ServerSynchronize
            | SequenceState::ServerControlCooperate
            | SequenceState::ServerGrantedControl
            | SequenceState::ServerFontMap => NextStream::Server,
            SequenceState::ServerDemandActive
            | SequenceState::ClientConfirmActive
            | SequenceState::ClientControlCooperate
            | SequenceState::ClientRequestControl
            | SequenceState::ClientFontList
            | SequenceState::Finished => NextStream::Client,
            SequenceState::ClientInfo => {
                unreachable!("The future must not require a next receiver in the first sequence state (ClientInfo)")
            }
        }
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        future_state == FutureState::SendMessage && self.sequence_state == SequenceState::Finished
    }
}

fn process_send_data_request_pdu(
    pdu: Vec<u8>,
    sequence_state: SequenceState,
    client_logger: slog::Logger,
    filter_config: &FilterConfig,
) -> io::Result<(SequenceState, Vec<u8>)> {
    match sequence_state {
        SequenceState::ClientInfo => {
            let mut client_info_pdu = ClientInfoPdu::from_buffer(pdu.as_slice())?;
            debug!(client_logger, "Got Client Info PDU: {:?}", client_info_pdu);

            client_info_pdu.filter(filter_config);

            let mut client_info_pdu_buffer = Vec::with_capacity(client_info_pdu.buffer_length());
            client_info_pdu.to_buffer(&mut client_info_pdu_buffer)?;

            Ok((SequenceState::Licensing, client_info_pdu_buffer))
        }
        SequenceState::ClientConfirmActive
        | SequenceState::ClientSynchronize
        | SequenceState::ClientControlCooperate
        | SequenceState::ClientRequestControl
        | SequenceState::ClientFontList => {
            let mut share_control_header = ShareControlHeader::from_buffer(pdu.as_slice())?;
            let next_sequence_state = match (sequence_state, &mut share_control_header.share_control_pdu) {
                (SequenceState::ClientConfirmActive, ShareControlPdu::ClientConfirmActive(client_confirm_active)) => {
                    client_confirm_active.pdu.filter(filter_config);
                    debug!(
                        client_logger,
                        "Got Client Confirm Active PDU: {:?}", client_confirm_active
                    );

                    SequenceState::ClientSynchronize
                }
                (_, ShareControlPdu::Data(ShareDataHeader { share_data_pdu, .. })) => {
                    debug!(client_logger, "Got Client Finalization PDU: {:?}", share_data_pdu);

                    match (sequence_state, share_data_pdu) {
                        (SequenceState::ClientSynchronize, ShareDataPdu::Synchronize(_)) => {
                            SequenceState::ServerSynchronize
                        }
                        (SequenceState::ClientControlCooperate, ShareDataPdu::Control(control_pdu))
                            if control_pdu.action == ControlAction::Cooperate =>
                        {
                            SequenceState::ServerControlCooperate
                        }
                        (SequenceState::ClientRequestControl, ShareDataPdu::Control(control_pdu))
                            if control_pdu.action == ControlAction::RequestControl =>
                        {
                            SequenceState::ServerGrantedControl
                        }
                        (SequenceState::ClientFontList, ShareDataPdu::FontList(_)) => SequenceState::ServerFontMap,
                        (state, _) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "Got Client PDU in invalid sequence state ({:?}) during Finalization Sequence",
                                    state
                                ),
                            ))
                        }
                    }
                }
                (_, share_control_pdu) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Got invalid client's Share Control Header PDU: {:?}", share_control_pdu),
                    ))
                }
            };

            let mut share_control_header_buffer = Vec::with_capacity(share_control_header.buffer_length());
            share_control_header.to_buffer(&mut share_control_header_buffer)?;

            Ok((next_sequence_state, share_control_header_buffer))
        }
        state => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Got invalid sequence state ({:?}) in the client's RDP Connection Sequence",
                state
            ),
        )),
    }
}

fn process_send_data_indication_pdu(
    pdu: Vec<u8>,
    sequence_state: SequenceState,
    client_logger: slog::Logger,
    filter_config: &FilterConfig,
) -> io::Result<(SequenceState, Vec<u8>)> {
    match sequence_state {
        SequenceState::Licensing => {
            let client_license_pdu = ClientLicensePdu::from_buffer(pdu.as_slice())?;
            debug!(client_logger, "Got Client License PDU: {:?}", client_license_pdu);

            let mut client_license_buffer = Vec::with_capacity(client_license_pdu.buffer_length());
            client_license_pdu.to_buffer(&mut client_license_buffer)?;

            Ok((SequenceState::ServerDemandActive, client_license_buffer))
        }
        SequenceState::ServerDemandActive
        | SequenceState::ServerSynchronize
        | SequenceState::ServerControlCooperate
        | SequenceState::ServerGrantedControl
        | SequenceState::ServerFontMap => {
            let mut share_control_header = ShareControlHeader::from_buffer(pdu.as_slice())?;
            let next_sequence_state = match (sequence_state, &mut share_control_header.share_control_pdu) {
                (SequenceState::ServerDemandActive, ShareControlPdu::ServerDemandActive(server_demand_active)) => {
                    server_demand_active.pdu.filter(filter_config);
                    debug!(
                        client_logger,
                        "Got Server Demand Active PDU: {:?}", server_demand_active
                    );

                    SequenceState::ClientConfirmActive
                }
                (_, ShareControlPdu::Data(ShareDataHeader { share_data_pdu, .. })) => {
                    debug!(client_logger, "Got Server Finalization PDU: {:?}", share_data_pdu);

                    match (sequence_state, share_data_pdu) {
                        (SequenceState::ServerSynchronize, ShareDataPdu::Synchronize(_)) => {
                            SequenceState::ClientControlCooperate
                        }
                        (SequenceState::ServerControlCooperate, ShareDataPdu::Control(control_pdu))
                            if control_pdu.action == ControlAction::Cooperate =>
                        {
                            SequenceState::ClientRequestControl
                        }
                        (SequenceState::ServerGrantedControl, ShareDataPdu::Control(control_pdu))
                            if control_pdu.action == ControlAction::GrantedControl =>
                        {
                            SequenceState::ClientFontList
                        }
                        (SequenceState::ServerFontMap, ShareDataPdu::FontMap(_)) => SequenceState::Finished,
                        (state, _) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "Got Server PDU in invalid sequence state ({:?}) during Finalization Sequence",
                                    state
                                ),
                            ))
                        }
                    }
                }
                (_, share_control_pdu) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Got invalid server's Share Control Header PDU: {:?}", share_control_pdu),
                    ))
                }
            };

            let mut share_control_header_buffer = Vec::with_capacity(share_control_header.buffer_length());
            share_control_header.to_buffer(&mut share_control_header_buffer)?;

            Ok((next_sequence_state, share_control_header_buffer))
        }
        state => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Got invalid sequence state ({:?}) in the server's RDP Connection Sequence",
                state
            ),
        )),
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum SequenceState {
    ClientInfo,
    Licensing,
    ServerDemandActive,
    ClientConfirmActive,
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
