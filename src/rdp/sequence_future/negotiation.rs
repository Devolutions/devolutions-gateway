use std::io;

use bytes::BytesMut;
use ironrdp::{NegotiationRequestFlags, NegotiationResponseFlags, SecurityProtocol, X224TPDUType};
use slog::info;
use sspi::Credentials;
use tokio::codec::Framed;
use tokio_tcp::TcpStream;

use super::{FutureState, NextStream, SequenceFutureProperties};
use crate::transport::x224::X224Transport;

type NegotiationTransport = Framed<TcpStream, X224Transport>;

pub struct NegotiationWithClientFuture {
    client_request_protocol: SecurityProtocol,
    client_request_flags: NegotiationRequestFlags,
    client_response_protocol: SecurityProtocol,
}

impl NegotiationWithClientFuture {
    pub fn new() -> Self {
        Self {
            client_request_protocol: SecurityProtocol::empty(),
            client_request_flags: NegotiationRequestFlags::empty(),
            client_response_protocol: SecurityProtocol::empty(),
        }
    }
}

impl SequenceFutureProperties<TcpStream, X224Transport> for NegotiationWithClientFuture {
    type Item = NegotiationWithClientFutureResponse;

    fn process_pdu(
        &mut self,
        pdu: (X224TPDUType, BytesMut),
        client_logger: &slog::Logger,
    ) -> io::Result<Option<(X224TPDUType, BytesMut)>> {
        let (code, buf) = pdu;
        let (negotiation_data, request_protocol, request_flags) =
            ironrdp::parse_negotiation_request(code, buf.as_ref())?;
        let (routing_token, cookie) = match negotiation_data {
            Some(ironrdp::NegoData::RoutingToken(routing_token)) => (Some(routing_token), None),
            Some(ironrdp::NegoData::Cookie(cookie)) => (None, Some(cookie)),
            None => (None, None),
        };
        info!(
            client_logger,
            "Processing request (routing_token: {:?}, cookie: {:?}, protocol: {:?}, flags: {:?})",
            routing_token,
            cookie,
            request_protocol,
            request_flags
        );

        let response_flags = ironrdp::NegotiationResponseFlags::DYNVC_GFX_PROTOCOL_SUPPORTED
            | ironrdp::NegotiationResponseFlags::RDP_NEG_RSP_RESERVED
            | ironrdp::NegotiationResponseFlags::RESTRICTED_ADMIN_MODE_SUPPORTED
            | ironrdp::NegotiationResponseFlags::REDIRECTED_AUTHENTICATION_MODE_SUPPORTED;
        let response_protocol = if request_protocol.contains(ironrdp::SecurityProtocol::HYBRID_EX) {
            ironrdp::SecurityProtocol::HYBRID_EX
        } else {
            ironrdp::SecurityProtocol::HYBRID
        };

        let mut response_data = BytesMut::new();
        response_data.resize(ironrdp::NEGOTIATION_RESPONSE_LEN, 0);
        ironrdp::write_negotiation_response(response_data.as_mut(), response_flags, response_protocol)?;

        self.client_request_protocol = request_protocol;
        self.client_request_flags = request_flags;
        self.client_response_protocol = response_protocol;

        Ok(Some((X224TPDUType::ConnectionConfirm, response_data)))
    }
    fn return_item(
        &mut self,
        mut client: Option<NegotiationTransport>,
        _server: Option<NegotiationTransport>,
        client_logger: &slog::Logger,
    ) -> Self::Item {
        info!(client_logger, "Successfully negotiated with the client");

        NegotiationWithClientFutureResponse {
            transport: client.take().expect(
                "After negotiation with client, the client's stream must exist in a return_item method, and the method cannot be fired multiple times"),
            client_request_protocol: self.client_request_protocol,
            client_request_flags: self.client_request_flags,
            client_response_protocol: self.client_response_protocol,
        }
    }
    fn next_sender(&self) -> NextStream {
        NextStream::Client
    }
    fn next_receiver(&self) -> NextStream {
        NextStream::Client
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        future_state == FutureState::SendMessage
    }
}

pub struct NegotiationWithClientFutureResponse {
    pub transport: NegotiationTransport,
    pub client_request_protocol: SecurityProtocol,
    pub client_request_flags: NegotiationRequestFlags,
    pub client_response_protocol: SecurityProtocol,
}

pub struct NegotiationWithServerFuture {
    server_response_protocol: SecurityProtocol,
    server_response_flags: NegotiationResponseFlags,
}

impl NegotiationWithServerFuture {
    pub fn new() -> Self {
        Self {
            server_response_protocol: SecurityProtocol::empty(),
            server_response_flags: NegotiationResponseFlags::empty(),
        }
    }
}

impl SequenceFutureProperties<TcpStream, X224Transport> for NegotiationWithServerFuture {
    type Item = (NegotiationTransport, SecurityProtocol, NegotiationResponseFlags);

    fn process_pdu(
        &mut self,
        pdu: (X224TPDUType, BytesMut),
        client_logger: &slog::Logger,
    ) -> io::Result<Option<(X224TPDUType, BytesMut)>> {
        let (code, buf) = pdu;

        if buf.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid negotiation response",
            ))
        } else {
            match ironrdp::parse_negotiation_response(code, buf.as_ref()) {
                Ok((response_protocol, response_flags)) => {
                    info!(
                        client_logger,
                        "Received negotiation response from server (protocol: {:?}, flags: {:?})",
                        response_protocol,
                        response_flags,
                    );

                    match response_protocol {
                        SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX => {
                            self.server_response_protocol = response_protocol;
                            self.server_response_flags = response_flags;

                            Ok(None)
                        }
                        _ => Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("Got unsupported security protocol: {:?}", response_protocol),
                        )),
                    }
                }
                Err(ironrdp::NegotiationError::NegotiationFailure(code)) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Received negotiation failure from server (code: {:?})", code),
                )),
                Err(ironrdp::NegotiationError::IOError(e)) => Err(e),
            }
        }
    }
    fn return_item(
        &mut self,
        _client: Option<NegotiationTransport>,
        mut server: Option<NegotiationTransport>,
        client_logger: &slog::Logger,
    ) -> Self::Item {
        info!(client_logger, "Successfully negotiated with the server");

        (
            server.take().expect(
                "After negotiation with server, the server's stream must exist in a return_item method, and the method cannot be fired multiple times"),
            self.server_response_protocol,
            self.server_response_flags,
        )
    }
    fn next_sender(&self) -> NextStream {
        NextStream::Server
    }
    fn next_receiver(&self) -> NextStream {
        NextStream::Server
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        future_state == FutureState::ParseMessage
    }
}

pub fn create_negotiation_request(
    credentials: Credentials,
    request_protocol: SecurityProtocol,
    request_flags: NegotiationRequestFlags,
) -> io::Result<(X224TPDUType, BytesMut)> {
    let cookie: &str = credentials.username.as_ref();
    let mut request_data = BytesMut::new();
    request_data.resize(ironrdp::NEGOTIATION_REQUEST_LEN + cookie.len(), 0);
    ironrdp::write_negotiation_request(request_data.as_mut(), cookie, request_protocol, request_flags)?;

    Ok((X224TPDUType::ConnectionRequest, request_data))
}
