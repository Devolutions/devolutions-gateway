use std::io;

use futures::{try_ready, Async, Future, Poll, Stream};
use tokio::{codec::Framed, prelude::*};
use tokio_tcp::TcpStream;
use tokio_tls::TlsStream;

use crate::transport::tsrequest::TsRequestTransport;
use rdp_proto::{CredSsp, CredSspResult, SspiError, SspiErrorType, TsRequest};

pub enum CredSspManagerResult {
    Done(TlsStream<TcpStream>),
    NotDone,
}

pub struct CredSspStream<T: CredSsp> {
    cred_ssp_context: T,
    ts_request: Option<TsRequest>,
    stream: Option<Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>>,
    send_future: Option<futures::sink::Send<Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>>>,
    state: CredSspManagerState,
}

#[derive(Copy, Clone, PartialEq)]
enum CredSspManagerState {
    GetMessage,
    ParseMessage,
    SendMessage,
    SendFinalMessage,
    SendAndFail,
    TakeData,
    Finished,
}

impl<T: CredSsp> CredSspStream<T> {
    pub fn new_for_client(
        stream: Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>,
        cred_ssp_context: T,
    ) -> Self {
        Self {
            cred_ssp_context,
            ts_request: Some(TsRequest::default()),
            stream: Some(stream),
            send_future: None,
            state: CredSspManagerState::ParseMessage,
        }
    }

    pub fn new_for_server(
        stream: Framed<tokio_tls::TlsStream<TcpStream>, TsRequestTransport>,
        cred_ssp_context: T,
    ) -> Self {
        Self {
            cred_ssp_context,
            ts_request: None,
            stream: Some(stream),
            send_future: None,
            state: CredSspManagerState::GetMessage,
        }
    }
}

impl<T: CredSsp> Stream for CredSspStream<T> {
    type Item = CredSspManagerResult;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                CredSspManagerState::GetMessage => {
                    let (read_ts_request, _) = try_ready!(self
                        .stream
                        .as_mut()
                        .expect("the stream must exist in the GetMessage state")
                        .into_future()
                        .map_err(|(e, _)| e)
                        .poll());
                    self.ts_request = read_ts_request;
                    self.state = CredSspManagerState::ParseMessage;
                }
                CredSspManagerState::ParseMessage => {
                    let response = self.cred_ssp_context.process(
                        self.ts_request
                            .take()
                            .expect("the ts_request must be set in the previous state"),
                    )?;
                    self.state = match response {
                        CredSspResult::ReplyNeeded(_) => CredSspManagerState::SendMessage,
                        CredSspResult::FinalMessage(_) => CredSspManagerState::SendFinalMessage,
                        CredSspResult::WithError(_) => CredSspManagerState::SendAndFail,
                        CredSspResult::Finished => CredSspManagerState::TakeData,
                    };
                    match response {
                        CredSspResult::ReplyNeeded(ts_request)
                        | CredSspResult::FinalMessage(ts_request)
                        | CredSspResult::WithError(ts_request) => {
                            self.send_future = Some(
                                self.stream
                                    .take()
                                    .expect("the stream must exist in the ParseMessage state")
                                    .send(ts_request),
                            );
                        }
                        CredSspResult::Finished => (),
                    };
                }
                CredSspManagerState::SendMessage
                | CredSspManagerState::SendFinalMessage
                | CredSspManagerState::SendAndFail => {
                    self.stream = Some(try_ready!(self
                        .send_future
                        .as_mut()
                        .expect("the 'Send' future must exist in SendMessage state")
                        .poll()));
                    self.send_future = None;

                    match self.state {
                        CredSspManagerState::SendMessage => {
                            self.state = CredSspManagerState::GetMessage;
                            return Ok(Async::Ready(Some(CredSspManagerResult::NotDone)));
                        }
                        CredSspManagerState::SendFinalMessage => {
                            self.state = CredSspManagerState::TakeData;
                        }
                        CredSspManagerState::SendAndFail => {
                            return Err(SspiError::new(
                                SspiErrorType::InternalError,
                                String::from("CredSSP finished with error"),
                            )
                            .into());
                        }
                        _ => unreachable!(),
                    };
                }
                CredSspManagerState::TakeData => {
                    self.state = CredSspManagerState::Finished;

                    return Ok(Async::Ready(Some(CredSspManagerResult::Done(
                        self.stream
                            .take()
                            .expect("TakeData state cannot be fired without the stream")
                            .into_inner(),
                    ))));
                }
                CredSspManagerState::Finished => return Ok(Async::Ready(None)),
            };
        }
    }
}
