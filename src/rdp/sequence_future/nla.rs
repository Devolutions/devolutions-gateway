use std::{
    future::Future,
    io,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use futures::{ready, SinkExt, StreamExt};
use ironrdp::nego;

use slog_scope::{debug, error, trace};
use sspi::{
    internal::credssp::{
        self, CredSspClient, CredSspMode, CredSspServer, EarlyUserAuthResult, TsRequest,
        EARLY_USER_AUTH_RESULT_PDU_SIZE,
    },
    AuthIdentity,
};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder, Framed};

use tokio_rustls::{rustls, Accept, Connect, TlsAcceptor, TlsConnector, TlsStream};

use crate::{
    io_try,
    rdp::{
        sequence_future::{
            FutureState, GetStateArgs, NextStream, ParseStateArgs, SequenceFuture, SequenceFutureProperties,
        },
        RdpIdentity,
    },
    transport::tsrequest::TsRequestTransport,
    utils,
};

type TsRequestFutureTransport = Framed<TlsStream<TcpStream>, TsRequestTransport>;
type EarlyUserAuthResultFutureTransport = Framed<TlsStream<TcpStream>, EarlyUserAuthResultTransport>;
type EarlyClientUserAuthResultFuture =
    Box<dyn Future<Output = Result<EarlyUserAuthResultFutureTransport, io::Error>> + 'static>;
type EarlyServerUserAuthResultFuture = Box<
    dyn Future<
            Output = (
                Option<Result<EarlyUserAuthResult, io::Error>>,
                EarlyUserAuthResultFutureTransport,
            ),
        > + 'static,
>;
type NlaWithClientFutureT =
    Pin<Box<SequenceFuture<'static, CredSspWithClientFuture, TlsStream<TcpStream>, TsRequestTransport, TsRequest>>>;
type CredSspWithServerFutureT =
    Pin<Box<SequenceFuture<'static, CredSspWithServerFuture, TlsStream<TcpStream>, TsRequestTransport, TsRequest>>>;

pub enum NlaTransport {
    TsRequest(TsRequestFutureTransport),
    EarlyUserAuthResult(EarlyUserAuthResultFutureTransport),
}

pub struct NlaWithClientFuture {
    state: NlaWithClientFutureState,
    client_response_protocol: nego::SecurityProtocol,
    tls_proxy_pubkey: Option<Vec<u8>>,
    identity: RdpIdentity,
}

impl NlaWithClientFuture {
    pub fn new(
        client: TcpStream,
        client_response_protocol: nego::SecurityProtocol,
        tls_proxy_pubkey: Vec<u8>,
        identity: RdpIdentity,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        Self {
            state: NlaWithClientFutureState::Tls(tls_acceptor.accept(client)),
            client_response_protocol,
            tls_proxy_pubkey: Some(tls_proxy_pubkey),
            identity,
        }
    }
}

impl Future for NlaWithClientFuture {
    type Output = Result<NlaTransport, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.state {
                NlaWithClientFutureState::Tls(accept_tls_future) => {
                    let client_tls = ready!(Pin::new(accept_tls_future).poll(cx)).map_err(move |e| {
                        io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("Failed to accept the client TLS connection: {}", e),
                        )
                    })?;
                    debug!("TLS connection has been established with the client");

                    let client_transport =
                        TsRequestTransport::default().framed(tokio_rustls::TlsStream::Server(client_tls));
                    self.state = NlaWithClientFutureState::CredSsp(Box::pin(SequenceFuture::with_get_state(
                        CredSspWithClientFuture::new(
                            self.tls_proxy_pubkey
                                .take()
                                .expect("The TLS proxy public key must be set in the constructor"),
                            self.identity.clone(),
                        )?,
                        GetStateArgs {
                            client: Some(client_transport),
                            server: None,
                            phantom_data: PhantomData,
                        },
                    )));
                }
                NlaWithClientFutureState::CredSsp(cred_ssp_future) => {
                    let client_transport = ready!(Pin::new(cred_ssp_future).poll(cx))?;

                    if self
                        .client_response_protocol
                        .contains(nego::SecurityProtocol::HYBRID_EX)
                    {
                        let transport =
                            utils::update_framed_codec(client_transport, EarlyUserAuthResultTransport::default());
                        let future = Box::pin(make_client_early_user_auth_future(transport));
                        self.state = NlaWithClientFutureState::EarlyUserAuthResult(future);
                    } else {
                        return Poll::Ready(Ok(NlaTransport::TsRequest(client_transport)));
                    }
                }
                NlaWithClientFutureState::EarlyUserAuthResult(early_user_auth_result_future) => {
                    let transport = ready!(early_user_auth_result_future.as_mut().poll(cx))?;

                    debug!("Success Early User Authorization Result PDU sent to the client");
                    debug!("NLA phase has been finished with the client");

                    return Poll::Ready(Ok(NlaTransport::EarlyUserAuthResult(transport)));
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
    type Output = Result<NlaTransport, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match &mut self.state {
                NlaWithServerFutureState::Tls(connect_tls_future) => {
                    let server_tls = ready!(Pin::new(connect_tls_future).poll(cx)).map_err(move |e| {
                        io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("Failed to handshake with a server: {}", e),
                        )
                    })?;
                    debug!("TLS connection has been established with the server");

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
                        phantom_data: PhantomData,
                    };

                    self.state = NlaWithServerFutureState::CredSsp(Box::pin(SequenceFuture::with_parse_state(
                        credssp_future,
                        parse_args,
                    )));
                }
                NlaWithServerFutureState::CredSsp(cred_ssp_future) => {
                    let server_transport = ready!(cred_ssp_future.as_mut().poll(cx))?;

                    if self
                        .server_response_protocol
                        .contains(nego::SecurityProtocol::HYBRID_EX)
                    {
                        let transport =
                            utils::update_framed_codec(server_transport, EarlyUserAuthResultTransport::default());
                        self.state = NlaWithServerFutureState::EarlyUserAuthResult(Box::pin(
                            make_server_early_user_auth_future(transport),
                        ));
                    } else {
                        return Poll::Ready(Ok(NlaTransport::TsRequest(server_transport)));
                    }
                }
                NlaWithServerFutureState::EarlyUserAuthResult(early_user_auth_result_future) => {
                    let (early_user_auth_result, transport) = ready!(early_user_auth_result_future.as_mut().poll(cx));

                    let early_user_auth_result = early_user_auth_result.transpose()?;

                    match early_user_auth_result {
                        Some(EarlyUserAuthResult::Success) => {
                            debug!("Got Success Early User Authorization Result from the server");
                            debug!("NLA phase has been finished with the server");

                            return Poll::Ready(Ok(NlaTransport::EarlyUserAuthResult(transport)));
                        }
                        Some(EarlyUserAuthResult::AccessDenied) => {
                            debug!("The server has denied access via Early User Authorization Result PDU");

                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                "The server failed CredSSP phase",
                            )));
                        }
                        None => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "The stream was closed unexpectedly",
                            )));
                        }
                    }
                }
            }
        }
    }
}

pub struct CredSspWithClientFuture {
    cred_ssp_server: CredSspServer<RdpIdentity>,
    identity: RdpIdentity,
    sequence_state: SequenceState,
}

impl CredSspWithClientFuture {
    pub fn new(tls_proxy_pubkey: Vec<u8>, identity: RdpIdentity) -> io::Result<Self> {
        let cred_ssp_server = CredSspServer::new(tls_proxy_pubkey, identity.clone())?;

        Ok(Self {
            cred_ssp_server,
            identity,
            sequence_state: SequenceState::CredSspSequence,
        })
    }
}

impl<'a> SequenceFutureProperties<'a, TlsStream<TcpStream>, TsRequestTransport, TsRequest> for CredSspWithClientFuture {
    type Item = TsRequestFutureTransport;

    fn process_pdu(&mut self, pdu: TsRequest) -> io::Result<Option<TsRequest>> {
        trace!("Got client's TSRequest: {:x?}", pdu);

        match self.sequence_state {
            SequenceState::CredSspSequence => {
                let response = self.cred_ssp_server.process(pdu);

                let (next_sequence_state, ts_request) = match response {
                    Ok(credssp::ServerState::ReplyNeeded(ts_request)) => {
                        trace!("Sending TSRequest to the client: {:x?}", ts_request);

                        (SequenceState::CredSspSequence, Some(ts_request))
                    }
                    Ok(credssp::ServerState::Finished(read_credentials)) => {
                        if self.identity.proxy.username == read_credentials.username
                            && self.identity.proxy.password == read_credentials.password
                        {
                            (SequenceState::Finished, None)
                        } else {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "Got invalid credentials from the client",
                            ));
                        }
                    }
                    Err(credssp::ServerError { ts_request, error }) => {
                        error!("Error happened in the CredSSP server: {:?}", error);

                        (SequenceState::SendingError, Some(ts_request))
                    }
                };
                trace!("Sending TSRequest to the client: {:x?}", ts_request);

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
        debug!("Successfully processed CredSSP with the client");
        client.take().expect(
            "In CredSSP Connection Sequence, the client's stream must exist in a return_item method,\
             and the method cannot be fired multiple times",
        )
    }

    fn next_sender(&self) -> NextStream {
        NextStream::Client
    }

    fn next_receiver(&self) -> NextStream {
        NextStream::Client
    }

    fn sequence_finished(&self, future_state: FutureState) -> bool {
        matches!(
            (future_state, self.sequence_state),
            (FutureState::ParseMessage, SequenceState::Finished)
                | (FutureState::SendMessage, SequenceState::FinalMessage)
        )
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

impl<'a> SequenceFutureProperties<'a, TlsStream<TcpStream>, TsRequestTransport, TsRequest> for CredSspWithServerFuture {
    type Item = TsRequestFutureTransport;

    fn process_pdu(&mut self, pdu: TsRequest) -> io::Result<Option<TsRequest>> {
        trace!("Got server's TSRequest: {:x?}", pdu);
        let response = self.cred_ssp_client.process(pdu)?;

        let ts_request = match response {
            credssp::ClientState::ReplyNeeded(ts_request) => ts_request,
            credssp::ClientState::FinalMessage(ts_request) => {
                self.sequence_state = SequenceState::FinalMessage;

                ts_request
            }
        };
        trace!("Sending TSRequest to the server: {:x?}", ts_request);

        Ok(Some(ts_request))
    }
    fn return_item(
        &mut self,
        _client: Option<TsRequestFutureTransport>,
        mut server: Option<TsRequestFutureTransport>,
    ) -> Self::Item {
        debug!("Successfully processed CredSSP with the server");

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
            buf.advance(result.buffer_len());
            Ok(Some(result))
        }
    }
}

impl Encoder<EarlyUserAuthResult> for EarlyUserAuthResultTransport {
    type Error = io::Error;

    fn encode(&mut self, item: EarlyUserAuthResult, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let len = buf.len();
        buf.resize(len + EARLY_USER_AUTH_RESULT_PDU_SIZE, 0);

        item.to_buffer(&mut buf[len..])
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
    CredSsp(NlaWithClientFutureT),
    EarlyUserAuthResult(Pin<EarlyClientUserAuthResultFuture>),
}


enum NlaWithServerFutureState {
    Tls(Connect<TcpStream>),
    CredSsp(CredSspWithServerFutureT),
    EarlyUserAuthResult(Pin<EarlyServerUserAuthResultFuture>),
}

async fn make_client_early_user_auth_future(
    mut transport: EarlyUserAuthResultFutureTransport,
) -> Result<EarlyUserAuthResultFutureTransport, io::Error> {
    Pin::new(&mut transport).send(EarlyUserAuthResult::Success).await?;
    Ok(transport)
}

async fn make_server_early_user_auth_future(
    transport: EarlyUserAuthResultFutureTransport,
) -> (
    Option<Result<EarlyUserAuthResult, io::Error>>,
    EarlyUserAuthResultFutureTransport,
) {
    transport.into_future().await
}
