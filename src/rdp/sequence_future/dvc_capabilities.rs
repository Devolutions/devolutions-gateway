use std::io;

use ironrdp::{
    mcs::SendDataContext,
    rdp::vc::{self, dvc},
    McsPdu, PduParsing,
};
use slog_scope::debug;
use tokio::{codec::Framed, net::tcp::TcpStream};
use tokio_rustls::TlsStream;

use super::{FutureState, GetStateArgs, NextStream, SequenceFuture, SequenceFutureProperties};
use crate::transport::rdp::{RdpPdu, RdpTransport};

type DvcCapabilitiesTransport = Framed<TlsStream<TcpStream>, RdpTransport>;

pub fn create_downgrade_dvc_capabilities_future(
    client_transport: Framed<TlsStream<TcpStream>, RdpTransport>,
    server_transport: Framed<TlsStream<TcpStream>, RdpTransport>,
    drdynvc_channel_id: u16,
) -> SequenceFuture<DowngradeDvcCapabilitiesFuture, TlsStream<TcpStream>, RdpTransport> {
    SequenceFuture::with_get_state(
        DowngradeDvcCapabilitiesFuture::new(drdynvc_channel_id),
        GetStateArgs {
            client: Some(client_transport),
            server: Some(server_transport),
        },
    )
}

pub struct DowngradeDvcCapabilitiesFuture {
    sequence_state: SequenceState,
    drdynvc_channel_id: u16,
}

impl DowngradeDvcCapabilitiesFuture {
    pub fn new(drdynvc_channel_id: u16) -> Self {
        Self {
            sequence_state: SequenceState::DvcCapabilities(DvcCapabilitiesState::ServerDvcCapabilities),
            drdynvc_channel_id,
        }
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, RdpTransport> for DowngradeDvcCapabilitiesFuture {
    type Item = (DvcCapabilitiesTransport, DvcCapabilitiesTransport);

    fn process_pdu(&mut self, rdp_pdu: RdpPdu) -> io::Result<Option<RdpPdu>> {
        let sequence_state = match self.sequence_state {
            SequenceState::DvcCapabilities(state)
            | SequenceState::OutOfSequence {
                previous_dvc_state: state,
            } => state,
        };

        let (next_sequence_state, next_rdp_pdu) = match rdp_pdu {
            RdpPdu::Data(mut data) => {
                let mcs_pdu = McsPdu::from_buffer(data.as_ref())?;

                match mcs_pdu {
                    // if RDP server/client sends data not according to the documentation,
                    // then redirect them
                    McsPdu::SendDataRequest(SendDataContext { channel_id, .. })
                    | McsPdu::SendDataIndication(SendDataContext { channel_id, .. })
                        if channel_id != self.drdynvc_channel_id =>
                    {
                        (
                            SequenceState::OutOfSequence {
                                previous_dvc_state: sequence_state,
                            },
                            RdpPdu::Data(data),
                        )
                    }
                    mcs_pdu => {
                        let (next_state, next_mcs_pdu) = match mcs_pdu {
                            McsPdu::SendDataRequest(send_data_context) => {
                                let send_data_context = handle_send_data_request(send_data_context)?;

                                (
                                    DvcCapabilitiesState::Finished,
                                    McsPdu::SendDataRequest(send_data_context),
                                )
                            }
                            McsPdu::SendDataIndication(send_data_context) => {
                                let send_data_context = handle_send_data_indication(send_data_context)?;

                                (
                                    DvcCapabilitiesState::ClientDvcCapabilities,
                                    McsPdu::SendDataIndication(send_data_context),
                                )
                            }
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "Got MCS PDU during downgrading of the DVC capabilities: {}",
                                        mcs_pdu.as_short_name()
                                    ),
                                ))
                            }
                        };

                        data.resize(next_mcs_pdu.buffer_length(), 0);
                        next_mcs_pdu.to_buffer(data.as_mut())?;

                        (SequenceState::DvcCapabilities(next_state), RdpPdu::Data(data))
                    }
                }
            }
            RdpPdu::FastPathBytes(bytes) => (
                SequenceState::OutOfSequence {
                    previous_dvc_state: sequence_state,
                },
                RdpPdu::FastPathBytes(bytes),
            ),
        };

        self.sequence_state = next_sequence_state;

        Ok(Some(next_rdp_pdu))
    }
    fn return_item(
        &mut self,
        mut client: Option<DvcCapabilitiesTransport>,
        mut server: Option<DvcCapabilitiesTransport>,
    ) -> Self::Item {
        debug!("Successfully downgraded DVC capabilities");

        (
            client.take().expect("The client's stream must exists"),
            server.take().expect("The server's stream must exists"),
        )
    }
    fn next_sender(&self) -> NextStream {
        match self.sequence_state {
            SequenceState::DvcCapabilities(state)
            | SequenceState::OutOfSequence {
                previous_dvc_state: state,
            } => match state {
                DvcCapabilitiesState::ClientDvcCapabilities => NextStream::Client,
                DvcCapabilitiesState::ServerDvcCapabilities => NextStream::Server,
                DvcCapabilitiesState::Finished => {
                    panic!("The future must not require a next sender in the Finished sequence state")
                }
            },
        }
    }
    fn next_receiver(&self) -> NextStream {
        match self.sequence_state {
            SequenceState::DvcCapabilities(state) => match state {
                DvcCapabilitiesState::ClientDvcCapabilities => NextStream::Client,
                DvcCapabilitiesState::Finished => NextStream::Server,
                DvcCapabilitiesState::ServerDvcCapabilities => {
                    unreachable!("The future must not require a next receiver in the first sequence state")
                }
            },
            SequenceState::OutOfSequence { previous_dvc_state } => match previous_dvc_state {
                DvcCapabilitiesState::ServerDvcCapabilities => NextStream::Client,
                DvcCapabilitiesState::ClientDvcCapabilities => NextStream::Server,
                DvcCapabilitiesState::Finished => unreachable!(
                    "The future must not require a next receiver in the last sequence state for an out of sequence PDU"
                ),
            },
        }
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        match self.sequence_state {
            SequenceState::DvcCapabilities(state) => {
                future_state == FutureState::SendMessage && state == DvcCapabilitiesState::Finished
            }
            SequenceState::OutOfSequence { .. } => false,
        }
    }
}

fn handle_send_data_request(
    SendDataContext {
        pdu,
        initiator_id,
        channel_id,
    }: SendDataContext,
) -> io::Result<SendDataContext> {
    let dvc_pdu_buffer = map_dvc_pdu(pdu, |dvc_data| match dvc::ClientPdu::from_buffer(dvc_data)? {
        dvc::ClientPdu::CapabilitiesResponse(capabilities) => {
            debug!("Got client's DVC Capabilities Response PDU: {:?}", capabilities);

            let response_v1 = dvc::CapabilitiesResponsePdu {
                version: dvc::CapsVersion::V1,
            };

            if capabilities != response_v1 {
                debug!("Downgrading client's DVC Capabilities Response PDU to V1");
            }

            Ok(dvc::ClientPdu::CapabilitiesResponse(response_v1))
        }
        client_dvc_pdu => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Received unexpected DVC Client PDU ({:?}) while was expected the Capabilities Response PDU",
                client_dvc_pdu.as_short_name()
            ),
        )),
    })?;

    Ok(SendDataContext {
        pdu: dvc_pdu_buffer,
        initiator_id,
        channel_id,
    })
}

fn handle_send_data_indication(
    SendDataContext {
        pdu,
        initiator_id,
        channel_id,
    }: SendDataContext,
) -> io::Result<SendDataContext> {
    let dvc_pdu_buffer = map_dvc_pdu(pdu, |dvc_data| match dvc::ServerPdu::from_buffer(dvc_data)? {
        dvc::ServerPdu::CapabilitiesRequest(capabilities) => {
            debug!("Got server's DVC Capabilities Request PDU: {:?}", capabilities);

            if capabilities != dvc::CapabilitiesRequestPdu::V1 {
                debug!("Downgrading server's DVC Capabilities Request PDU to V1");
            }

            Ok(dvc::ServerPdu::CapabilitiesRequest(dvc::CapabilitiesRequestPdu::V1))
        }
        server_dvc_pdu => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Received unexpected DVC Server PDU ({:?}) while was expected the Capabilities Request PDU",
                server_dvc_pdu.as_short_name()
            ),
        )),
    })?;

    Ok(SendDataContext {
        pdu: dvc_pdu_buffer,
        initiator_id,
        channel_id,
    })
}

fn map_dvc_pdu<T, F>(mut pdu: Vec<u8>, f: F) -> io::Result<Vec<u8>>
where
    F: FnOnce(&[u8]) -> io::Result<T>,
    T: PduParsing,
    io::Error: From<T::Error>,
{
    let mut svc_header = vc::ChannelPduHeader::from_buffer(pdu.as_slice())?;
    let dvc_data = &pdu[svc_header.buffer_length()..];

    if svc_header.total_length as usize != dvc_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Received invalid VC header total length: {} != {}",
                svc_header.total_length,
                dvc_data.len(),
            ),
        ));
    }

    let dvc_pdu = f(dvc_data)?;

    svc_header.total_length = dvc_pdu.buffer_length() as u32;
    pdu.resize(dvc_pdu.buffer_length() + svc_header.buffer_length(), 0);
    svc_header.to_buffer(&mut pdu[..])?;
    dvc_pdu.to_buffer(&mut pdu[svc_header.buffer_length()..])?;

    Ok(pdu)
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum SequenceState {
    DvcCapabilities(DvcCapabilitiesState),
    OutOfSequence { previous_dvc_state: DvcCapabilitiesState },
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum DvcCapabilitiesState {
    ServerDvcCapabilities,
    ClientDvcCapabilities,
    Finished,
}
