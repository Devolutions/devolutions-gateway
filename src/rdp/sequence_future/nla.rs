use std::io;

use bytes::BytesMut;
use futures::{sink::Send, stream::StreamFuture, try_ready, Future, Poll};
use ironrdp::nego;
use slog::{debug, info};
use sspi::{
    CredSsp, CredSspClient, CredSspResult, CredSspServer, Credentials, EarlyUserAuthResult, TsRequest,
    EARLY_USER_AUTH_RESULT_PDU_SIZE,
};
use tokio::{
    codec::{Decoder, Encoder, Framed},
    prelude::*,
};
use tokio_tcp::TcpStream;
use tokio_tls::{Accept, Connect, TlsAcceptor, TlsConnector, TlsStream};

use crate::{
    rdp::identities_proxy::{IdentitiesProxy, RdpIdentity, RdpIdentityGetter},
    rdp::sequence_future::{FutureState, NextStream, SequenceFuture, SequenceFutureProperties},
    transport::tsrequest::TsRequestTransport,
    utils,
};

type TsRequestFutureTransport = Framed<TlsStream<TcpStream>, TsRequestTransport>;
type EarlyUserAuthResultFutureTransport = Framed<TlsStream<TcpStream>, EarlyUserAuthResultTransport>;

pub struct NlaWithClientFuture {
    state: NlaWithClientFutureState,
    client_response_protocol: nego::SecurityProtocol,
    tls_proxy_pubkey: Option<Vec<u8>>,
    identities_proxy: Option<IdentitiesProxy>,
    rdp_identity: Option<RdpIdentity>,
    client_logger: slog::Logger,
}

impl NlaWithClientFuture {
    pub fn new(
        client: TcpStream,
        client_response_protocol: nego::SecurityProtocol,
        tls_proxy_pubkey: Vec<u8>,
        identities_proxy: IdentitiesProxy,
        tls_acceptor: TlsAcceptor,
        client_logger: slog::Logger,
    ) -> Self {
        Self {
            state: NlaWithClientFutureState::Tls(tls_acceptor.accept(client)),
            client_response_protocol,
            tls_proxy_pubkey: Some(tls_proxy_pubkey),
            identities_proxy: Some(identities_proxy),
            rdp_identity: None,
            client_logger,
        }
    }
}

impl Future for NlaWithClientFuture {
    type Item = (TlsStream<TcpStream>, RdpIdentity);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match &mut self.state {
                NlaWithClientFutureState::Tls(accept_tls_future) => {
                    let client_tls = try_ready!(accept_tls_future
                        .map_err(move |e| {
                            io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("Failed to accept a client connection: {}", e),
                            )
                        })
                        .poll());

                    let client_transport = TsRequestTransport::default().framed(client_tls);
                    self.state = NlaWithClientFutureState::CredSsp(Box::new(SequenceFuture {
                        future: CredSspWithClientFuture::new(
                            self.tls_proxy_pubkey
                                .take()
                                .expect("The TLS proxy public key must be set in the constructor"),
                            self.identities_proxy
                                .take()
                                .expect("The identities proxy must be set in the constructor"),
                        )?,
                        client: Some(client_transport),
                        server: None,
                        send_future: None,
                        pdu: None,
                        future_state: FutureState::GetMessage,
                        client_logger: self.client_logger.clone(),
                    }));
                }
                NlaWithClientFutureState::CredSsp(cred_ssp_future) => {
                    let (client_transport, rdp_identity) = try_ready!(cred_ssp_future.poll());

                    let client_tls = client_transport.into_inner();

                    if self
                        .client_response_protocol
                        .contains(nego::SecurityProtocol::HYBRID_EX)
                    {
                        self.rdp_identity = Some(rdp_identity);

                        self.state = NlaWithClientFutureState::EarlyUserAuthResult(
                            EarlyUserAuthResultTransport::default()
                                .framed(client_tls)
                                .send(EarlyUserAuthResult::Success),
                        );
                    } else {
                        return Ok(Async::Ready((client_tls, rdp_identity)));
                    }
                }
                NlaWithClientFutureState::EarlyUserAuthResult(early_user_auth_result_future) => {
                    let transport = try_ready!(early_user_auth_result_future.poll());

                    let client_tls = transport.into_inner();

                    return Ok(Async::Ready((
                        client_tls,
                        self.rdp_identity
                            .take()
                            .expect("For NLA with client future, RDP identity must be set during CredSSP phase"),
                    )));
                }
            }
        }
    }
}

pub struct NlaWithServerFuture {
    state: NlaWithServerFutureState,
    client_request_flags: nego::RequestFlags,
    server_response_protocol: nego::SecurityProtocol,
    target_credentials: Credentials,
    client_logger: slog::Logger,
}

impl NlaWithServerFuture {
    pub fn new(
        server: TcpStream,
        client_request_flags: nego::RequestFlags,
        server_response_protocol: nego::SecurityProtocol,
        target_credentials: Credentials,
        accept_invalid_certs_and_host_names: bool,
        client_logger: slog::Logger,
    ) -> io::Result<Self> {
        let tls_connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(accept_invalid_certs_and_host_names)
            .danger_accept_invalid_hostnames(accept_invalid_certs_and_host_names)
            .build()
            .expect("Tls connector builder cannot fail");
        let tls_connector = TlsConnector::from(tls_connector);

        Ok(Self {
            state: NlaWithServerFutureState::Tls(
                tls_connector.connect(server.peer_addr()?.ip().to_string().as_ref(), server),
            ),
            client_request_flags,
            server_response_protocol,
            target_credentials,
            client_logger,
        })
    }
}

impl Future for NlaWithServerFuture {
    type Item = TlsStream<TcpStream>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match &mut self.state {
                NlaWithServerFutureState::Tls(connect_tls_future) => {
                    let server_tls = try_ready!(connect_tls_future
                        .map_err(move |e| {
                            io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("Failed to handshake with a server: {}", e),
                            )
                        })
                        .poll());

                    let client_public_key = utils::get_tls_peer_pubkey(&server_tls)?;
                    let server_transport = TsRequestTransport::default().framed(server_tls);

                    self.state = NlaWithServerFutureState::CredSsp(Box::new(SequenceFuture {
                        future: CredSspWithServerFuture::new(
                            client_public_key,
                            self.client_request_flags,
                            self.target_credentials.clone(),
                        )?,
                        client: None,
                        server: Some(server_transport),
                        send_future: None,
                        pdu: Some(TsRequest::default()),
                        future_state: FutureState::ParseMessage,
                        client_logger: self.client_logger.clone(),
                    }));
                }
                NlaWithServerFutureState::CredSsp(cred_ssp_future) => {
                    let server_transport = try_ready!(cred_ssp_future.poll());

                    let server_tls = server_transport.into_inner();

                    if self
                        .server_response_protocol
                        .contains(nego::SecurityProtocol::HYBRID_EX)
                    {
                        self.state = NlaWithServerFutureState::EarlyUserAuthResult(
                            EarlyUserAuthResultTransport::default().framed(server_tls).into_future(),
                        );
                    } else {
                        return Ok(Async::Ready(server_tls));
                    }
                }
                NlaWithServerFutureState::EarlyUserAuthResult(early_user_auth_result_future) => {
                    let (early_user_auth_result, transport) =
                        try_ready!(early_user_auth_result_future.map_err(|(e, _)| e).poll());

                    if let Some(early_user_auth_result) = early_user_auth_result {
                        if let EarlyUserAuthResult::Success = early_user_auth_result {
                            let server_tls = transport.into_inner();

                            return Ok(Async::Ready(server_tls));
                        } else {
                            return Err(io::Error::new(io::ErrorKind::Other, "The server failed CredSSP phase"));
                        }
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "The stream was closed unexpectedly",
                        ));
                    }
                }
            }
        }
    }
}

pub struct CredSspWithClientFuture {
    cred_ssp_server: sspi::CredSspServer<IdentitiesProxy>,
    sequence_state: SequenceState,
}

impl CredSspWithClientFuture {
    pub fn new(tls_proxy_pubkey: Vec<u8>, identities_proxy: IdentitiesProxy) -> io::Result<Self> {
        let cred_ssp_server = CredSspServer::with_default_version(tls_proxy_pubkey, identities_proxy)?;

        Ok(Self {
            cred_ssp_server,
            sequence_state: SequenceState::CredSspSequence,
        })
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, TsRequestTransport> for CredSspWithClientFuture {
    type Item = (TsRequestFutureTransport, RdpIdentity);

    fn process_pdu(&mut self, pdu: TsRequest, client_logger: &slog::Logger) -> io::Result<Option<TsRequest>> {
        debug!(client_logger, "Got client's TSRequest: {:?}", pdu);
        let response = self.cred_ssp_server.process(pdu)?;

        let (next_sequence_state, result) = match response {
            CredSspResult::ReplyNeeded(ts_request) => (SequenceState::CredSspSequence, Some(ts_request)),
            CredSspResult::WithError(ts_request) | CredSspResult::FinalMessage(ts_request) => {
                (SequenceState::FinalMessage, Some(ts_request))
            }
            CredSspResult::ClientCredentials(read_credentials) => {
                let expected_credentials = &self.cred_ssp_server.credentials.get_rdp_identity().proxy;
                if expected_credentials.username == read_credentials.username
                    && expected_credentials.password == read_credentials.password
                {
                    (SequenceState::Finished, None)
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        String::from("Got invalid credentials from the client"),
                    ));
                }
            }
            _ => unreachable!(),
        };

        self.sequence_state = next_sequence_state;

        Ok(result)
    }
    fn return_item(
        &mut self,
        mut client: Option<TsRequestFutureTransport>,
        _server: Option<TsRequestFutureTransport>,
        client_logger: &slog::Logger,
    ) -> Self::Item {
        info!(client_logger, "Successfully processed CredSSP with the server");

        (
            client.take().expect(
            "In CredSSP Connection Sequence, the client's stream must exist in a return_item method, and the method cannot be fired multiple times"),
            self.cred_ssp_server.credentials.get_rdp_identity(),
        )
    }
    fn next_sender(&self) -> NextStream {
        NextStream::Client
    }
    fn next_receiver(&self) -> NextStream {
        NextStream::Client
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        match (future_state, self.sequence_state) {
            (FutureState::ParseMessage, SequenceState::Finished)
            | (FutureState::SendMessage, SequenceState::FinalMessage) => true,
            _ => false,
        }
    }
}

pub struct CredSspWithServerFuture {
    cred_ssp_client: CredSspClient,
    sequence_state: SequenceState,
}

impl CredSspWithServerFuture {
    pub fn new(
        public_key: Vec<u8>,
        request_flags: nego::RequestFlags,
        target_credentials: Credentials,
    ) -> Result<Self, sspi::SspiError> {
        let cred_ssp_mode = if request_flags.contains(nego::RequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED) {
            sspi::CredSspMode::CredentialLess
        } else {
            sspi::CredSspMode::WithCredentials
        };
        let cred_ssp_client = CredSspClient::with_default_version(public_key, target_credentials, cred_ssp_mode)?;

        Ok(Self {
            cred_ssp_client,
            sequence_state: SequenceState::CredSspSequence,
        })
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, TsRequestTransport> for CredSspWithServerFuture {
    type Item = TsRequestFutureTransport;

    fn process_pdu(&mut self, pdu: TsRequest, client_logger: &slog::Logger) -> io::Result<Option<TsRequest>> {
        debug!(client_logger, "Got server's TSRequest: {:?}", pdu);
        let response = self.cred_ssp_client.process(pdu)?;

        let ts_request = match response {
            CredSspResult::ReplyNeeded(ts_request) => ts_request,
            CredSspResult::FinalMessage(ts_request) => {
                self.sequence_state = SequenceState::FinalMessage;

                ts_request
            }
            _ => unreachable!(),
        };

        Ok(Some(ts_request))
    }
    fn return_item(
        &mut self,
        _client: Option<TsRequestFutureTransport>,
        mut server: Option<TsRequestFutureTransport>,
        client_logger: &slog::Logger,
    ) -> Self::Item {
        info!(client_logger, "Successfully processed CredSSP with the client");

        server.take().expect(
            "In CredSSP Connection Sequence, the server's stream must exist in a return_item method, and the method cannot be fired multiple times",
        )
    }
    fn next_sender(&self) -> NextStream {
        NextStream::Server
    }
    fn next_receiver(&self) -> NextStream {
        NextStream::Server
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        future_state == FutureState::SendMessage && self.sequence_state == SequenceState::FinalMessage
    }
}

#[derive(Default)]
pub struct EarlyUserAuthResultTransport;

impl Decoder for EarlyUserAuthResultTransport {
    type Item = EarlyUserAuthResult;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() < EARLY_USER_AUTH_RESULT_PDU_SIZE {
            Ok(None)
        } else {
            let result = io_try!(EarlyUserAuthResult::from_buffer(buf.as_ref()));

            Ok(Some(result))
        }
    }
}

impl Encoder for EarlyUserAuthResultTransport {
    type Item = EarlyUserAuthResult;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.resize(EARLY_USER_AUTH_RESULT_PDU_SIZE, 0);

        item.to_buffer(buf.as_mut())
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum SequenceState {
    CredSspSequence,
    FinalMessage,
    Finished,
}

enum NlaWithClientFutureState {
    Tls(Accept<TcpStream>),
    CredSsp(Box<SequenceFuture<CredSspWithClientFuture, TlsStream<TcpStream>, TsRequestTransport>>),
    EarlyUserAuthResult(Send<EarlyUserAuthResultFutureTransport>),
}

enum NlaWithServerFutureState {
    Tls(Connect<TcpStream>),
    CredSsp(Box<SequenceFuture<CredSspWithServerFuture, TlsStream<TcpStream>, TsRequestTransport>>),
    EarlyUserAuthResult(StreamFuture<EarlyUserAuthResultFutureTransport>),
}
