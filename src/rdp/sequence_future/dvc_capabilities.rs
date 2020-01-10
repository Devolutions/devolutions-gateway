use std::io;

use ironrdp::{
    mcs::SendDataContext,
    rdp::vc::{
        self,
        dvc::{self, gfx},
    },
    McsPdu, PduParsing,
};
use slog_scope::debug;
use tokio::{codec::Framed, net::tcp::TcpStream};
use tokio_rustls::TlsStream;

use super::{FutureState, GetStateArgs, NextStream, SequenceFuture, SequenceFutureProperties};
use crate::{
    interceptor::PduSource,
    rdp::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME},
    transport::rdp::{RdpPdu, RdpTransport},
};

type DvcCapabilitiesTransport = Framed<TlsStream<TcpStream>, RdpTransport>;

pub fn create_downgrade_dvc_capabilities_future(
    client_transport: Framed<TlsStream<TcpStream>, RdpTransport>,
    server_transport: Framed<TlsStream<TcpStream>, RdpTransport>,
    drdynvc_channel_id: u16,
    dvc_manager: DvcManager,
) -> SequenceFuture<DowngradeDvcCapabilitiesFuture, TlsStream<TcpStream>, RdpTransport> {
    SequenceFuture::with_get_state(
        DowngradeDvcCapabilitiesFuture::new(drdynvc_channel_id, dvc_manager),
        GetStateArgs {
            client: Some(client_transport),
            server: Some(server_transport),
        },
    )
}

pub struct DowngradeDvcCapabilitiesFuture {
    sequence_state: SequenceState,
    drdynvc_channel_id: u16,
    dvc_manager: Option<DvcManager>,
}

impl DowngradeDvcCapabilitiesFuture {
    pub fn new(drdynvc_channel_id: u16, dvc_manager: DvcManager) -> Self {
        Self {
            sequence_state: SequenceState::DvcCapabilities(DvcCapabilitiesState::ServerDvcCapabilitiesRequest),
            drdynvc_channel_id,
            dvc_manager: Some(dvc_manager),
        }
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, RdpTransport> for DowngradeDvcCapabilitiesFuture {
    type Item = (DvcCapabilitiesTransport, DvcCapabilitiesTransport, DvcManager);

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
                                let (next_state, send_data_context) = handle_send_data_request(
                                    send_data_context,
                                    sequence_state,
                                    self.dvc_manager.as_mut().unwrap(),
                                )?;

                                (next_state, McsPdu::SendDataRequest(send_data_context))
                            }
                            McsPdu::SendDataIndication(send_data_context) => {
                                let (next_state, send_data_context) = handle_send_data_indication(
                                    send_data_context,
                                    sequence_state,
                                    self.dvc_manager.as_mut().unwrap(),
                                )?;

                                (next_state, McsPdu::SendDataIndication(send_data_context))
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
            self.dvc_manager.take().expect("The DVC manager must exists"),
        )
    }
    fn next_sender(&self) -> NextStream {
        match self.sequence_state {
            SequenceState::DvcCapabilities(state)
            | SequenceState::OutOfSequence {
                previous_dvc_state: state,
            } => match state {
                DvcCapabilitiesState::ClientDvcCapabilitiesResponse
                | DvcCapabilitiesState::ClientCreateResponse
                | DvcCapabilitiesState::ClientGfxCapabilitiesRequest => NextStream::Client,
                DvcCapabilitiesState::ServerDvcCapabilitiesRequest | DvcCapabilitiesState::ServerCreateRequest => {
                    NextStream::Server
                }
                DvcCapabilitiesState::Finished => {
                    panic!("The future must not require a next sender in the Finished sequence state")
                }
            },
        }
    }
    fn next_receiver(&self) -> NextStream {
        match self.sequence_state {
            SequenceState::DvcCapabilities(state) => match state {
                DvcCapabilitiesState::ClientDvcCapabilitiesResponse | DvcCapabilitiesState::ClientCreateResponse => {
                    NextStream::Client
                }
                DvcCapabilitiesState::ServerCreateRequest
                | DvcCapabilitiesState::ClientGfxCapabilitiesRequest
                | DvcCapabilitiesState::Finished => NextStream::Server,
                DvcCapabilitiesState::ServerDvcCapabilitiesRequest => {
                    unreachable!("The future must not require a next receiver in the first sequence state")
                }
            },
            SequenceState::OutOfSequence { previous_dvc_state } => match previous_dvc_state {
                DvcCapabilitiesState::ServerDvcCapabilitiesRequest | DvcCapabilitiesState::ServerCreateRequest => {
                    NextStream::Client
                }
                DvcCapabilitiesState::ClientDvcCapabilitiesResponse
                | DvcCapabilitiesState::ClientCreateResponse
                | DvcCapabilitiesState::ClientGfxCapabilitiesRequest => NextStream::Server,
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
    sequence_state: DvcCapabilitiesState,
    dvc_manager: &mut DvcManager,
) -> io::Result<(DvcCapabilitiesState, SendDataContext)> {
    let (next_state, dvc_pdu_buffer) = map_dvc_pdu(pdu, |dvc_data| {
        match (sequence_state, dvc::ClientPdu::from_buffer(dvc_data)?) {
            (
                DvcCapabilitiesState::ClientDvcCapabilitiesResponse,
                dvc::ClientPdu::CapabilitiesResponse(capabilities),
            ) => {
                debug!("Got client's DVC Capabilities Response PDU: {:?}", capabilities);

                let response_v1 = dvc::CapabilitiesResponsePdu {
                    version: dvc::CapsVersion::V1,
                };

                if capabilities != response_v1 {
                    debug!("Downgrading client's DVC Capabilities Response PDU to V1");
                }

                Ok((
                    DvcCapabilitiesState::ServerCreateRequest,
                    dvc::ClientPdu::CapabilitiesResponse(response_v1),
                ))
            }
            (DvcCapabilitiesState::ClientCreateResponse, dvc::ClientPdu::CreateResponse(create_response_pdu)) => {
                debug!("Got client's DVC Create Response PDU: {:?}", create_response_pdu);

                dvc_manager.handle_create_response_pdu(&create_response_pdu);

                let next_state = match dvc_manager.channel_name(create_response_pdu.channel_id) {
                    Some(RDP8_GRAPHICS_PIPELINE_NAME) => DvcCapabilitiesState::ClientGfxCapabilitiesRequest,
                    _ => DvcCapabilitiesState::ServerCreateRequest,
                };

                Ok((next_state, dvc::ClientPdu::CreateResponse(create_response_pdu)))
            }
            (DvcCapabilitiesState::ClientGfxCapabilitiesRequest, dvc::ClientPdu::Data(data_pdu)) => {
                let channel_id_type = data_pdu.channel_id_type;
                let channel_id = data_pdu.channel_id;
                let mut dvc_data = dvc_manager
                    .handle_data_pdu(PduSource::Client, data_pdu)
                    .expect("First GFX PDU must be complete data");
                let gfx_capabilities = if let gfx::ClientPdu::CapabilitiesAdvertise(gfx_capabilities) =
                    gfx::ClientPdu::from_buffer(dvc_data.as_slice()).map_err(map_graphics_pipeline_error)?
                {
                    gfx_capabilities
                } else {
                    unreachable!("First GFX PDU must be capabilities advertise");
                };

                debug!("Got client's GFX Capabilities Advertise PDU: {:?}", gfx_capabilities);

                if gfx_capabilities.0.len() > 1 {
                    debug!("Downgrading client's GFX capabilities to V8 without flags");
                }

                let gfx_capabilities = gfx::ClientPdu::CapabilitiesAdvertise(gfx::CapabilitiesAdvertisePdu(vec![
                    gfx::CapabilitySet::V8 {
                        flags: gfx::CapabilitiesV8Flags::empty(),
                    },
                ]));

                dvc_data.clear();
                gfx_capabilities
                    .to_buffer(&mut dvc_data)
                    .map_err(|e| map_graphics_pipeline_error(gfx::GraphicsPipelineError::from(e)))?;

                Ok((
                    DvcCapabilitiesState::Finished,
                    dvc::ClientPdu::Data(dvc::DataPdu {
                        channel_id_type,
                        channel_id,
                        dvc_data,
                    }),
                ))
            }
            (state, client_dvc_pdu) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Received unexpected DVC Client PDU ({:?}) in {:?} state",
                    client_dvc_pdu.as_short_name(),
                    state,
                ),
            )),
        }
    })?;

    Ok((
        next_state,
        SendDataContext {
            pdu: dvc_pdu_buffer,
            initiator_id,
            channel_id,
        },
    ))
}

fn handle_send_data_indication(
    SendDataContext {
        pdu,
        initiator_id,
        channel_id,
    }: SendDataContext,
    sequence_state: DvcCapabilitiesState,
    dvc_manager: &mut DvcManager,
) -> io::Result<(DvcCapabilitiesState, SendDataContext)> {
    let (next_state, dvc_pdu_buffer) = map_dvc_pdu(pdu, |dvc_data| {
        match (sequence_state, dvc::ServerPdu::from_buffer(dvc_data)?) {
            (DvcCapabilitiesState::ServerDvcCapabilitiesRequest, dvc::ServerPdu::CapabilitiesRequest(capabilities)) => {
                debug!("Got server's DVC Capabilities Request PDU: {:?}", capabilities);

                if capabilities != dvc::CapabilitiesRequestPdu::V1 {
                    debug!("Downgrading server's DVC Capabilities Request PDU to V1");
                }

                Ok((
                    DvcCapabilitiesState::ClientDvcCapabilitiesResponse,
                    dvc::ServerPdu::CapabilitiesRequest(dvc::CapabilitiesRequestPdu::V1),
                ))
            }
            (DvcCapabilitiesState::ServerCreateRequest, dvc::ServerPdu::CreateRequest(create_request_pdu)) => {
                debug!("Got server's DVC Create Request PDU: {:?}", create_request_pdu);

                dvc_manager.handle_create_request_pdu(&create_request_pdu);

                Ok((
                    DvcCapabilitiesState::ClientCreateResponse,
                    dvc::ServerPdu::CreateRequest(create_request_pdu),
                ))
            }
            (state, server_dvc_pdu) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Received unexpected DVC Server PDU ({:?}) in {:?} state",
                    server_dvc_pdu.as_short_name(),
                    state
                ),
            )),
        }
    })?;

    Ok((
        next_state,
        SendDataContext {
            pdu: dvc_pdu_buffer,
            initiator_id,
            channel_id,
        },
    ))
}

fn map_dvc_pdu<T, F>(mut pdu: Vec<u8>, f: F) -> io::Result<(DvcCapabilitiesState, Vec<u8>)>
where
    F: FnOnce(&[u8]) -> io::Result<(DvcCapabilitiesState, T)>,
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

    let (next_state, dvc_pdu) = f(dvc_data)?;

    svc_header.total_length = dvc_pdu.buffer_length() as u32;
    pdu.resize(dvc_pdu.buffer_length() + svc_header.buffer_length(), 0);
    svc_header.to_buffer(&mut pdu[..])?;
    dvc_pdu.to_buffer(&mut pdu[svc_header.buffer_length()..])?;

    Ok((next_state, pdu))
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum SequenceState {
    DvcCapabilities(DvcCapabilitiesState),
    OutOfSequence { previous_dvc_state: DvcCapabilitiesState },
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum DvcCapabilitiesState {
    ServerDvcCapabilitiesRequest,
    ClientDvcCapabilitiesResponse,
    ServerCreateRequest,
    ClientCreateResponse,
    ClientGfxCapabilitiesRequest,
    Finished,
}

fn map_graphics_pipeline_error(e: gfx::GraphicsPipelineError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("GFX error: {}", e))
}
