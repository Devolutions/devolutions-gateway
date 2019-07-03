use std::io;

use futures::{sink::Send, try_ready, Async, Future, Poll, Stream};
use slog::debug;
use tokio::{codec::Framed, prelude::*};
use tokio_tcp::TcpStream;
use tokio_tls::TlsStream;

use crate::{
    rdp::filter::{Filter, FilterConfig},
    transport::mcs::McsTransport,
};
use rdp_proto::{ClientInfoPdu, ClientLicensePdu, McsPdu, PduParsing, SendDataContext};

type McsFutureTransport = Framed<TlsStream<TcpStream>, McsTransport>;

pub struct RdpFuture {
    client: Option<McsFutureTransport>,
    server: Option<McsFutureTransport>,
    send_future: Option<Send<McsFutureTransport>>,
    filter: Option<FilterConfig>,
    future_state: FutureState,
    sequence_state: SequenceState,
    client_logger: slog::Logger,
}

impl RdpFuture {
    pub fn new(
        client: McsFutureTransport,
        server: McsFutureTransport,
        filter: FilterConfig,
        client_logger: slog::Logger,
    ) -> Self {
        Self {
            client: Some(client),
            server: Some(server),
            send_future: None,
            filter: Some(filter),
            future_state: FutureState::GetMessage,
            sequence_state: SequenceState::ClientInfo,
            client_logger,
        }
    }

    fn process_pdu(&mut self, mcs_pdu: McsPdu) -> io::Result<(Send<McsFutureTransport>, SequenceState)> {
        match mcs_pdu {
            McsPdu::SendDataRequest(SendDataContext {
                pdu,
                initiator_id,
                channel_id,
            }) => {
                let (next_sequence_state, pdu) = match self.sequence_state {
                    SequenceState::ClientInfo => {
                        let mut client_info_pdu = ClientInfoPdu::from_buffer(pdu.as_slice())?;
                        debug!(self.client_logger, "Got Client Info PDU: {:?}", client_info_pdu);

                        client_info_pdu.filter(
                            &self
                                .filter
                                .as_mut()
                                .expect("Filter must be taken only in the Finished state"),
                        );

                        let mut client_info_buffer = Vec::with_capacity(client_info_pdu.buffer_length());
                        client_info_pdu.to_buffer(&mut client_info_buffer)?;

                        (SequenceState::ClientLicense, client_info_buffer)
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Got Send Data Request MCS Domain Request with invalid PDU",
                        ))
                    }
                };

                Ok((
                    self.server
                        .take()
                        .expect("The server stream must exist in process_pdu method")
                        .send(McsPdu::SendDataRequest(SendDataContext {
                            pdu,
                            initiator_id,
                            channel_id,
                        })),
                    next_sequence_state,
                ))
            }

            McsPdu::SendDataIndication(SendDataContext {
                pdu,
                initiator_id,
                channel_id,
            }) => {
                let (next_sequence_state, pdu) = match self.sequence_state {
                    SequenceState::ClientLicense => {
                        let client_license_pdu = ClientLicensePdu::from_buffer(pdu.as_slice())?;
                        debug!(self.client_logger, "Got Client License PDU: {:?}", client_license_pdu);

                        let mut client_license_buffer = Vec::with_capacity(client_license_pdu.buffer_length());
                        client_license_pdu.to_buffer(&mut client_license_buffer)?;

                        (SequenceState::Finished, client_license_buffer)
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Server's RDP Connection Sequence state ({:?}) does not match received PDU ({:?})",
                        ))
                    }
                };

                Ok((
                    self.client
                        .take()
                        .expect("The client stream must exist in process_pdu method")
                        .send(McsPdu::SendDataIndication(SendDataContext {
                            pdu,
                            initiator_id,
                            channel_id,
                        })),
                    next_sequence_state,
                ))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Got MCS PDU during RDP Connection Sequence: {}",
                    mcs_pdu.as_short_name()
                ),
            )),
        }
    }

    fn next_sender(&mut self) -> &mut McsFutureTransport {
        match self.sequence_state {
            SequenceState::ClientInfo => self
                .client
                .as_mut()
                .expect("In ClientInfo sequence state the client stream must exist"),
            SequenceState::ClientLicense => self
                .server
                .as_mut()
                .expect("In ClientLicense sequence state the server stream must exist"),
            SequenceState::Finished => {
                unreachable!("The future must not require a next sender in the Finished sequence state")
            }
        }
    }

    fn next_receiver(&mut self) -> &mut Option<McsFutureTransport> {
        match self.sequence_state {
            SequenceState::ClientLicense => &mut self.server,
            SequenceState::Finished => &mut self.client,
            SequenceState::ClientInfo => {
                unreachable!("The future must not require a next receiver in the first sequence state (ClientInfo)")
            }
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

impl Future for RdpFuture {
    type Item = (McsFutureTransport, McsFutureTransport, FilterConfig);
    type Error = rdp_proto::McsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.future_state {
                FutureState::GetMessage => {
                    let sender = self.next_sender();

                    let (rdp_pdu, _) = try_ready!(sender.into_future().map_err(|(e, _)| e).poll());
                    let rdp_pdu = rdp_pdu.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "The stream was closed unexpectedly")
                    })?;

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
                        self.filter.take().expect("Filter must exist in the Finished future state, and the future state cannot be fired multiple times"),
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
    ClientInfo,
    ClientLicense,
    Finished,
}
