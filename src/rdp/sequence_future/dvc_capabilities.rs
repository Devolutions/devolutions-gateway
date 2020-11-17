use std::{io, marker::PhantomData};

use bytes::{Buf, BytesMut};
use ironrdp::{
    mcs::SendDataContext,
    rdp::vc::{
        self,
        dvc::{self, gfx},
    },
    McsPdu, PduParsing,
};
use slog_scope::debug;
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_util::codec::Framed;

use super::{FutureState, GetStateArgs, NextStream, SequenceFuture, SequenceFutureProperties};
use crate::{
    interceptor::PduSource,
    rdp::{DvcManager, RDP8_GRAPHICS_PIPELINE_NAME},
    transport::rdp::{RdpPdu, RdpTransport},
};

type DvcCapabilitiesTransport = Framed<TlsStream<TcpStream>, RdpTransport>;

pub fn create_downgrade_dvc_capabilities_future<'a>(
    client_transport: Framed<TlsStream<TcpStream>, RdpTransport>,
    server_transport: Framed<TlsStream<TcpStream>, RdpTransport>,
    drdynvc_channel_id: u16,
    dvc_manager: DvcManager,
) -> SequenceFuture<'a, DowngradeDvcCapabilitiesFuture, TlsStream<TcpStream>, RdpTransport, RdpPdu> {
    SequenceFuture::with_get_state(
        DowngradeDvcCapabilitiesFuture::new(drdynvc_channel_id, dvc_manager),
        GetStateArgs {
            client: Some(client_transport),
            server: Some(server_transport),
            phantom_data: PhantomData,
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

impl<'a> SequenceFutureProperties<'a, TlsStream<TcpStream>, RdpTransport, RdpPdu> for DowngradeDvcCapabilitiesFuture {
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
                        let (next_state, next_mcs_pdu, pdu_data) = match mcs_pdu {
                            McsPdu::SendDataRequest(mut send_data_context) => {
                                data.advance(data.len() - send_data_context.pdu_length);
                                let (next_state, pdu_data) =
                                    handle_send_data_request(data, sequence_state, self.dvc_manager.as_mut().unwrap())?;

                                send_data_context.pdu_length = pdu_data.len();

                                (next_state, McsPdu::SendDataRequest(send_data_context), pdu_data)
                            }
                            McsPdu::SendDataIndication(mut send_data_context) => {
                                data.advance(data.len() - send_data_context.pdu_length);
                                let (next_state, pdu_data) = handle_send_data_indication(
                                    data,
                                    sequence_state,
                                    self.dvc_manager.as_mut().unwrap(),
                                )?;

                                send_data_context.pdu_length = pdu_data.len();

                                (next_state, McsPdu::SendDataIndication(send_data_context), pdu_data)
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

                        let mut data = BytesMut::with_capacity(next_mcs_pdu.buffer_length() + pdu_data.len());
                        data.resize(next_mcs_pdu.buffer_length() + pdu_data.len(), 0);
                        next_mcs_pdu.to_buffer(data.as_mut())?;
                        (&mut data[next_mcs_pdu.buffer_length()..]).clone_from_slice(&pdu_data);

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
    pdu: BytesMut,
    sequence_state: DvcCapabilitiesState,
    dvc_manager: &mut DvcManager,
) -> io::Result<(DvcCapabilitiesState, BytesMut)> {
    let (next_state, dvc_pdu_buffer) = map_dvc_pdu(pdu, |mut dvc_data| {
        match (
            sequence_state,
            dvc::ClientPdu::from_buffer(dvc_data.as_ref(), dvc_data.len())?,
        ) {
            (
                DvcCapabilitiesState::ClientDvcCapabilitiesResponse,
                dvc::ClientPdu::CapabilitiesResponse(capabilities),
            ) => {
                debug!("Got client's DVC Capabilities Response PDU: {:?}", capabilities);

                let caps_response_pdu = dvc::ClientPdu::CapabilitiesResponse(capabilities);

                dvc_data.resize(caps_response_pdu.buffer_length(), 0);
                caps_response_pdu.to_buffer(dvc_data.as_mut())?;

                Ok((DvcCapabilitiesState::ServerCreateRequest, dvc_data))
            }
            (DvcCapabilitiesState::ClientCreateResponse, dvc::ClientPdu::CreateResponse(create_response_pdu)) => {
                debug!("Got client's DVC Create Response PDU: {:?}", create_response_pdu);

                dvc_manager.handle_create_response_pdu(&create_response_pdu);

                let next_state = match dvc_manager.channel_name(create_response_pdu.channel_id) {
                    Some(RDP8_GRAPHICS_PIPELINE_NAME) => DvcCapabilitiesState::ClientGfxCapabilitiesRequest,
                    _ => DvcCapabilitiesState::ServerCreateRequest,
                };

                Ok((next_state, dvc_data))
            }
            (DvcCapabilitiesState::ClientGfxCapabilitiesRequest, dvc::ClientPdu::Data(data_pdu)) => {
                let channel_id_type = data_pdu.channel_id_type;
                let channel_id = data_pdu.channel_id;
                let complete_dvc_data = dvc_manager
                    .handle_data_pdu(PduSource::Client, data_pdu, dvc_data.as_ref())
                    .expect("First GFX PDU must be complete data");

                let gfx_capabilities = if let gfx::ClientPdu::CapabilitiesAdvertise(gfx_capabilities) =
                    gfx::ClientPdu::from_buffer(complete_dvc_data.as_slice()).map_err(map_graphics_pipeline_error)?
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

                let data_pdu = dvc::ClientPdu::Data(dvc::DataPdu {
                    channel_id_type,
                    channel_id,
                    data_size: gfx_capabilities.buffer_length(),
                });

                dvc_data.resize(data_pdu.buffer_length() + gfx_capabilities.buffer_length(), 0);

                data_pdu.to_buffer(dvc_data.as_mut())?;
                gfx_capabilities
                    .to_buffer(&mut dvc_data[data_pdu.buffer_length()..])
                    .map_err(map_graphics_pipeline_error)?;

                Ok((DvcCapabilitiesState::Finished, dvc_data))
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

    Ok((next_state, dvc_pdu_buffer))
}

fn handle_send_data_indication(
    pdu: BytesMut,
    sequence_state: DvcCapabilitiesState,
    dvc_manager: &mut DvcManager,
) -> io::Result<(DvcCapabilitiesState, BytesMut)> {
    let (next_state, dvc_pdu_buffer) = map_dvc_pdu(pdu, |mut dvc_data| {
        match (
            sequence_state,
            dvc::ServerPdu::from_buffer(dvc_data.as_ref(), dvc_data.len())?,
        ) {
            (DvcCapabilitiesState::ServerDvcCapabilitiesRequest, dvc::ServerPdu::CapabilitiesRequest(capabilities)) => {
                debug!("Got server's DVC Capabilities Request PDU: {:?}", capabilities);

                let caps_request_pdu = dvc::ServerPdu::CapabilitiesRequest(capabilities);

                dvc_data.resize(caps_request_pdu.buffer_length(), 0);
                caps_request_pdu.to_buffer(dvc_data.as_mut())?;

                Ok((DvcCapabilitiesState::ClientDvcCapabilitiesResponse, dvc_data))
            }
            (DvcCapabilitiesState::ServerCreateRequest, dvc::ServerPdu::CreateRequest(create_request_pdu)) => {
                debug!("Got server's DVC Create Request PDU: {:?}", create_request_pdu);

                dvc_manager.handle_create_request_pdu(&create_request_pdu);

                Ok((DvcCapabilitiesState::ClientCreateResponse, dvc_data))
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

    Ok((next_state, dvc_pdu_buffer))
}

fn map_dvc_pdu<F>(mut pdu: BytesMut, f: F) -> io::Result<(DvcCapabilitiesState, BytesMut)>
where
    F: FnOnce(BytesMut) -> io::Result<(DvcCapabilitiesState, BytesMut)>,
{
    let mut svc_header = vc::ChannelPduHeader::from_buffer(pdu.as_ref())?;
    pdu.advance(svc_header.buffer_length());

    if svc_header.total_length as usize != pdu.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Received invalid VC header total length: {} != {}",
                svc_header.total_length,
                pdu.len(),
            ),
        ));
    }

    let (next_state, dvc_pdu_buffer) = f(pdu)?;

    svc_header.total_length = dvc_pdu_buffer.len() as u32;

    let mut pdu = BytesMut::with_capacity(svc_header.buffer_length() + dvc_pdu_buffer.len());
    pdu.resize(svc_header.buffer_length() + dvc_pdu_buffer.len(), 0);
    svc_header.to_buffer(pdu.as_mut())?;
    (&mut pdu[svc_header.buffer_length()..]).clone_from_slice(&dvc_pdu_buffer);

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
