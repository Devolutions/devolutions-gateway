use std::io;

use futures::{try_ready, Async, Future, Poll, Stream};
use tokio::{codec::Framed, prelude::*};
use tokio_tcp::TcpStream;
use tokio_tls::TlsStream;

use crate::{
    rdp::identities_proxy::{RdpIdentity, RdpIdentityGetter},
    transport::tsrequest::TsRequestTransport,
};
use rdp_proto::CredSsp;

pub struct CredSspClientFuture {
    cred_ssp_client: rdp_proto::CredSspClient,
    ts_request: Option<rdp_proto::TsRequest>,
    stream: Option<Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>>,
    send_future: Option<futures::sink::Send<Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>>>,
    state: CredSspFutureState,
}

pub struct CredSspServerFuture<C: rdp_proto::CredentialsProxy + RdpIdentityGetter> {
    cred_ssp_server: rdp_proto::CredSspServer<C>,
    ts_request: Option<rdp_proto::TsRequest>,
    stream: Option<Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>>,
    send_future: Option<futures::sink::Send<Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>>>,
    state: CredSspFutureState,
    client_credentials: Option<rdp_proto::Credentials>,
}

#[derive(Copy, Clone, PartialEq)]
enum CredSspFutureState {
    GetMessage,
    ParseMessage,
    SendMessage,
    SendFinalMessage,
    SendAndFail,
    Finished,
}

impl CredSspClientFuture {
    pub fn new(
        stream: Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>,
        cred_ssp_context: rdp_proto::CredSspClient,
    ) -> Self {
        Self {
            cred_ssp_client: cred_ssp_context,
            ts_request: Some(rdp_proto::TsRequest::default()),
            stream: Some(stream),
            send_future: None,
            state: CredSspFutureState::ParseMessage,
        }
    }
}

impl<C: rdp_proto::CredentialsProxy + RdpIdentityGetter> CredSspServerFuture<C> {
    pub fn new(
        stream: Framed<TlsStream<TcpStream>, TsRequestTransport>,
        cred_ssp_server: rdp_proto::CredSspServer<C>,
    ) -> Self {
        Self {
            cred_ssp_server,
            ts_request: None,
            stream: Some(stream),
            send_future: None,
            state: CredSspFutureState::GetMessage,
            client_credentials: None,
        }
    }
}

impl Future for CredSspClientFuture {
    type Item = Framed<TlsStream<TcpStream>, TsRequestTransport>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                CredSspFutureState::GetMessage => {
                    let (read_ts_request, _) = try_ready!(self
                        .stream
                        .as_mut()
                        .expect("the stream must exist in the GetMessage state")
                        .into_future()
                        .map_err(|(e, _)| e)
                        .poll());
                    self.ts_request = read_ts_request;
                    self.state = get_next_state(self.state, None);
                }
                CredSspFutureState::ParseMessage => {
                    let response = self.cred_ssp_client.process(
                        self.ts_request
                            .take()
                            .expect("the ts_request must be set in the previous state"),
                    )?;

                    // we first set state to avoid clone() for the response
                    self.state = get_next_state(self.state, Some(&response));
                    match response {
                        rdp_proto::CredSspResult::ReplyNeeded(ts_request)
                        | rdp_proto::CredSspResult::FinalMessage(ts_request) => {
                            self.send_future = Some(
                                self.stream
                                    .take()
                                    .expect("the stream must exist in the ParseMessage state")
                                    .send(ts_request),
                            );
                        }
                        rdp_proto::CredSspResult::Finished => (),
                        _ => unreachable!(),
                    };
                }
                CredSspFutureState::SendMessage | CredSspFutureState::SendFinalMessage => {
                    self.stream = Some(try_ready!(self
                        .send_future
                        .as_mut()
                        .expect("the 'Send' future must exist in SendMessage state")
                        .poll()));
                    self.send_future = None;
                    self.state = get_next_state(self.state, None);
                }
                CredSspFutureState::Finished => {
                    return Ok(Async::Ready(
                        self.stream
                            .take()
                            .expect("Finished state cannot be fired without the stream"),
                    ));
                }
                _ => unreachable!(),
            };
        }
    }
}

impl<C: rdp_proto::CredentialsProxy + RdpIdentityGetter> Future for CredSspServerFuture<C> {
    type Item = (
        Framed<TlsStream<TcpStream>, TsRequestTransport>,
        RdpIdentity,
        rdp_proto::Credentials,
    );
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.state {
                CredSspFutureState::GetMessage => {
                    let (read_ts_request, _) = try_ready!(self
                        .stream
                        .as_mut()
                        .expect("the stream must exist in the GetMessage state")
                        .into_future()
                        .map_err(|(e, _)| e)
                        .poll());
                    self.ts_request = read_ts_request;
                    self.state = get_next_state(self.state, None);
                }
                CredSspFutureState::ParseMessage => {
                    let response = self.cred_ssp_server.process(
                        self.ts_request
                            .take()
                            .expect("the ts_request must be set in the previous state"),
                    )?;

                    // we first set state to avoid clone() for the response
                    self.state = get_next_state(self.state, Some(&response));
                    match response {
                        rdp_proto::CredSspResult::ReplyNeeded(ts_request)
                        | rdp_proto::CredSspResult::FinalMessage(ts_request)
                        | rdp_proto::CredSspResult::WithError(ts_request) => {
                            self.send_future = Some(
                                self.stream
                                    .take()
                                    .expect("the stream must exist in the ParseMessage state")
                                    .send(ts_request),
                            );
                        }
                        rdp_proto::CredSspResult::ClientCredentials(client_credentials) => {
                            self.client_credentials = Some(client_credentials);
                        }
                        rdp_proto::CredSspResult::Finished => (),
                    };
                }
                CredSspFutureState::SendMessage
                | CredSspFutureState::SendFinalMessage
                | CredSspFutureState::SendAndFail => {
                    self.stream = Some(try_ready!(self
                        .send_future
                        .as_mut()
                        .expect("the 'Send' future must exist in SendMessage state")
                        .poll()));
                    self.send_future = None;

                    if self.state == CredSspFutureState::SendAndFail {
                        return Err(rdp_proto::SspiError::new(
                            rdp_proto::SspiErrorType::InternalError,
                            String::from("CredSSP finished with error"),
                        )
                        .into());
                    }
                    self.state = get_next_state(self.state, None);
                }
                CredSspFutureState::Finished => {
                    return Ok(Async::Ready((
                        self.stream
                            .take()
                            .expect("Finished state cannot be fired without the stream"),
                        self.cred_ssp_server.credentials.get_rdp_identity(),
                        self.client_credentials
                            .take()
                            .expect("The state cannot be finished without a client credentials"),
                    )));
                }
            };
        }
    }
}

fn get_next_state(
    current_state: CredSspFutureState,
    cred_ssp_result: Option<&rdp_proto::CredSspResult>,
) -> CredSspFutureState {
    match current_state {
        CredSspFutureState::GetMessage => CredSspFutureState::ParseMessage,
        CredSspFutureState::SendMessage => CredSspFutureState::GetMessage,
        CredSspFutureState::SendFinalMessage | CredSspFutureState::SendAndFail | CredSspFutureState::Finished => {
            CredSspFutureState::Finished
        }
        CredSspFutureState::ParseMessage => {
            match cred_ssp_result
                .as_ref()
                .expect("CredSSP result must be present for matching ParseMessage state")
            {
                rdp_proto::CredSspResult::ReplyNeeded(_) => CredSspFutureState::SendMessage,
                rdp_proto::CredSspResult::FinalMessage(_) => CredSspFutureState::SendFinalMessage,
                rdp_proto::CredSspResult::WithError(_) => CredSspFutureState::SendAndFail,
                rdp_proto::CredSspResult::ClientCredentials(_) | rdp_proto::CredSspResult::Finished => {
                    CredSspFutureState::Finished
                }
            }
        }
    }
}
