use std::{io, sync::Arc};

use bytes::BytesMut;
use futures::{sink::Send, stream::StreamFuture, try_ready, Future, Poll};
use ironrdp::nego;

use slog_scope::{debug, error, info};
use sspi::{
    internal::{
        CredSspClient, CredSspMode, CredSspResult, CredSspServer, EarlyUserAuthResult, TsRequest,
        EARLY_USER_AUTH_RESULT_PDU_SIZE,
    },
    AuthIdentity,
};
use tokio::{
    codec::{Decoder, Encoder, Framed},
    prelude::*,
};
use tokio_rustls::{Accept, Connect, TlsAcceptor, TlsConnector, TlsStream};
use tokio_tcp::TcpStream;

use crate::{
    io_try,
    rdp::identities_proxy::{IdentitiesProxy, RdpIdentity, RdpIdentityGetter},
    rdp::sequence_future::{
        FutureState, GetStateArgs, NextStream, ParseStateArgs, SequenceFuture, SequenceFutureProperties,
    },
    transport::tsrequest::TsRequestTransport,
    utils,
};

type TsRequestFutureTransport = Framed<TlsStream<TcpStream>, TsRequestTransport>;
type EarlyUserAuthResultFutureTransport = Framed<TlsStream<TcpStream>, EarlyUserAuthResultTransport>;

pub enum NlaTransport {
    TsRequest(TsRequestFutureTransport),
    EarlyUserAuthResult(EarlyUserAuthResultFutureTransport),
}

pub struct NlaWithClientFuture {
    state: NlaWithClientFutureState,
    client_response_protocol: nego::SecurityProtocol,
    tls_proxy_pubkey: Option<Vec<u8>>,
    identities_proxy: Option<IdentitiesProxy>,
    rdp_identity: Option<RdpIdentity>,
}

impl NlaWithClientFuture {
    pub fn new(
        client: TcpStream,
        client_response_protocol: nego::SecurityProtocol,
        tls_proxy_pubkey: Vec<u8>,
        identities_proxy: IdentitiesProxy,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        Self {
            state: NlaWithClientFutureState::Tls(tls_acceptor.accept(client)),
            client_response_protocol,
            tls_proxy_pubkey: Some(tls_proxy_pubkey),
            identities_proxy: Some(identities_proxy),
            rdp_identity: None,
        }
    }
}

impl Future for NlaWithClientFuture {
    type Item = (NlaTransport, RdpIdentity);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match &mut self.state {
                NlaWithClientFutureState::Tls(accept_tls_future) => {
                    let client_tls = try_ready!(accept_tls_future
                        .map_err(move |e| {
                            io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!("Failed to accept the client TLS connection: {}", e),
                            )
                        })
                        .poll());
                    info!("TLS connection has been established with the client");

                    let client_transport =
                        TsRequestTransport::default().framed(tokio_rustls::TlsStream::Server(client_tls));
                    self.state = NlaWithClientFutureState::CredSsp(Box::new(SequenceFuture::with_get_state(
                        CredSspWithClientFuture::new(
                            self.tls_proxy_pubkey
                                .take()
                                .expect("The TLS proxy public key must be set in the constructor"),
                            self.identities_proxy
                                .take()
                                .expect("The identities proxy must be set in the constructor"),
                        )?,
                        GetStateArgs {
                            client: Some(client_transport),
                            server: None,
                        },
                    )));
                }
                NlaWithClientFutureState::CredSsp(cred_ssp_future) => {
                    let (client_transport, rdp_identity) = try_ready!(cred_ssp_future.poll());

                    if self
                        .client_response_protocol
                        .contains(nego::SecurityProtocol::HYBRID_EX)
                    {
                        self.rdp_identity = Some(rdp_identity);

                        self.state = NlaWithClientFutureState::EarlyUserAuthResult(
                            utils::update_framed_codec(client_transport, EarlyUserAuthResultTransport::default())
                                .send(EarlyUserAuthResult::Success),
                        );
                    } else {
                        return Ok(Async::Ready((NlaTransport::TsRequest(client_transport), rdp_identity)));
                    }
                }
                NlaWithClientFutureState::EarlyUserAuthResult(early_user_auth_result_future) => {
                    let transport = try_ready!(early_user_auth_result_future.poll());

                    debug!("Success Early User Authorization Result PDU sent to the client");
                    info!("NLA phase has been finished with the client");

                    return Ok(Async::Ready((
                        NlaTransport::EarlyUserAuthResult(transport),
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
    target_credentials: AuthIdentity,
}

impl NlaWithServerFuture {
    pub fn new(
        server: TcpStream,
        client_request_flags: nego::RequestFlags,
        server_response_protocol: nego::SecurityProtocol,
        target_credentials: AuthIdentity,
        accept_invalid_certs_and_host_names: bool,
    ) -> io::Result<Self> {
        let mut client_config = rustls::ClientConfig::default();
        if accept_invalid_certs_and_host_names {
            client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(utils::danger_transport::NoCertificateVerification {}));
        }
        let config_ref = Arc::new(client_config);
        let tls_connector = TlsConnector::from(config_ref);
        let dns_name = webpki::DNSNameRef::try_from_ascii_str("stub_string").unwrap();

        Ok(Self {
            state: NlaWithServerFutureState::Tls(tls_connector.connect(dns_name, server)),
            client_request_flags,
            server_response_protocol,
            target_credentials,
        })
    }
}

impl Future for NlaWithServerFuture {
    type Item = NlaTransport;
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
                    info!("TLS connection has been established with the server");

                    let client_tls = tokio_rustls::TlsStream::Client(server_tls);
                    let client_public_key = utils::get_tls_peer_pubkey(&client_tls)?;
                    let server_transport = TsRequestTransport::default().framed(client_tls);

                    let credssp_future = CredSspWithServerFuture::new(
                        client_public_key,
                        self.client_request_flags,
                        self.target_credentials.clone(),
                    )?;
                    let parse_args = ParseStateArgs {
                        client: None,
                        server: Some(server_transport),
                        pdu: TsRequest::default(),
                    };

                    self.state = NlaWithServerFutureState::CredSsp(Box::new(SequenceFuture::with_parse_state(
                        credssp_future,
                        parse_args,
                    )));
                }
                NlaWithServerFutureState::CredSsp(cred_ssp_future) => {
                    let server_transport = try_ready!(cred_ssp_future.poll());

                    if self
                        .server_response_protocol
                        .contains(nego::SecurityProtocol::HYBRID_EX)
                    {
                        self.state = NlaWithServerFutureState::EarlyUserAuthResult(
                            utils::update_framed_codec(server_transport, EarlyUserAuthResultTransport::default())
                                .into_future(),
                        );
                    } else {
                        return Ok(Async::Ready(NlaTransport::TsRequest(server_transport)));
                    }
                }
                NlaWithServerFutureState::EarlyUserAuthResult(early_user_auth_result_future) => {
                    let (early_user_auth_result, transport) =
                        try_ready!(early_user_auth_result_future.map_err(|(e, _)| e).poll());

                    match early_user_auth_result {
                        Some(EarlyUserAuthResult::Success) => {
                            debug!("Got Success Early User Authorization Result from the server");
                            info!("NLA phase has been finished with the server");

                            return Ok(Async::Ready(NlaTransport::EarlyUserAuthResult(transport)));
                        }
                        Some(EarlyUserAuthResult::AccessDenied) => {
                            debug!("The server has denied access via Early User Authorization Result PDU");

                            return Err(io::Error::new(io::ErrorKind::Other, "The server failed CredSSP phase"));
                        }
                        None => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "The stream was closed unexpectedly",
                            ))
                        }
                    }
                }
            }
        }
    }
}

pub struct CredSspWithClientFuture {
    cred_ssp_server: CredSspServer<IdentitiesProxy>,
    sequence_state: SequenceState,
}

impl CredSspWithClientFuture {
    pub fn new(tls_proxy_pubkey: Vec<u8>, identities_proxy: IdentitiesProxy) -> io::Result<Self> {
        let cred_ssp_server = CredSspServer::new(tls_proxy_pubkey, identities_proxy)?;

        Ok(Self {
            cred_ssp_server,
            sequence_state: SequenceState::CredSspSequence,
        })
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, TsRequestTransport> for CredSspWithClientFuture {
    type Item = (TsRequestFutureTransport, RdpIdentity);

    fn process_pdu(&mut self, pdu: TsRequest) -> io::Result<Option<TsRequest>> {
        debug!("Got client's TSRequest: {:x?}", pdu);

        match self.sequence_state {
            SequenceState::CredSspSequence => {
                let response = self.cred_ssp_server.process(pdu);

                let (next_sequence_state, ts_request) = match response {
                    Ok(CredSspResult::ReplyNeeded(ts_request)) => {
                        debug!("Sending TSRequest to the client: {:x?}", ts_request);

                        (SequenceState::CredSspSequence, Some(ts_request))
                    }
                    Ok(CredSspResult::FinalMessage(ts_request)) => {
                        debug!("Sending last TSRequest to the client: {:x?}", ts_request);

                        (SequenceState::FinalMessage, Some(ts_request))
                    }
                    Ok(CredSspResult::ClientCredentials(read_credentials)) => {
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
                    Err(ts_request) => {
                        error!(
                            "Error happened in CredSSP server, error code: {}",
                            ts_request.error_code.unwrap()
                        );

                        (SequenceState::SendingError, Some(ts_request))
                    }
                    _ => unreachable!(),
                };
                debug!("Sending TSRequest to the client: {:x?}", ts_request);

                self.sequence_state = next_sequence_state;

                Ok(ts_request)
            }
            SequenceState::SendingError => Err(io::Error::new(io::ErrorKind::Other, "CredSsp server error")),
            SequenceState::FinalMessage | SequenceState::Finished => {
                unreachable!("CredSspWithClientFuture must not be fired in FinalMessage/Finished state")
            }
        }
    }
    fn return_item(
        &mut self,
        mut client: Option<TsRequestFutureTransport>,
        _server: Option<TsRequestFutureTransport>,
    ) -> Self::Item {
        info!("Successfully processed CredSSP with the client");

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
        target_credentials: AuthIdentity,
    ) -> Result<Self, sspi::Error> {
        let cred_ssp_mode = if request_flags.contains(nego::RequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED) {
            CredSspMode::CredentialLess
        } else {
            CredSspMode::WithCredentials
        };
        let cred_ssp_client = CredSspClient::new(public_key, target_credentials, cred_ssp_mode)?;

        Ok(Self {
            cred_ssp_client,
            sequence_state: SequenceState::CredSspSequence,
        })
    }
}

impl SequenceFutureProperties<TlsStream<TcpStream>, TsRequestTransport> for CredSspWithServerFuture {
    type Item = TsRequestFutureTransport;

    fn process_pdu(&mut self, pdu: TsRequest) -> io::Result<Option<TsRequest>> {
        debug!("Got server's TSRequest: {:x?}", pdu);
        let response = self.cred_ssp_client.process(pdu)?;

        let ts_request = match response {
            CredSspResult::ReplyNeeded(ts_request) => ts_request,
            CredSspResult::FinalMessage(ts_request) => {
                self.sequence_state = SequenceState::FinalMessage;

                ts_request
            }
            _ => unreachable!(),
        };
        debug!("Sending TSRequest to the server: {:x?}", ts_request);

        Ok(Some(ts_request))
    }
    fn return_item(
        &mut self,
        _client: Option<TsRequestFutureTransport>,
        mut server: Option<TsRequestFutureTransport>,
    ) -> Self::Item {
        info!("Successfully processed CredSSP with the server");

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
    SendingError,
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
