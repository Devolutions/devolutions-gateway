use std::{
    collections::HashMap,
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use futures::ready;
use jet_proto::{
    accept::{JetAcceptReq, JetAcceptRsp},
    connect::{JetConnectReq, JetConnectRsp},
    test::{JetTestReq, JetTestRsp},
    JetMessage, StatusCode, JET_VERSION_V1, JET_VERSION_V2,
};
use slog_scope::{debug, error};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};
use uuid::Uuid;

use crate::{
    config::Config,
    http::controllers::jet::remove_association,
    jet::{
        association::Association,
        candidate::{Candidate, CandidateState},
        TransportType,
    },
    transport::JetTransport,
    utils::association::{RemoveAssociation, ACCEPT_REQUEST_TIMEOUT},
    Proxy,
};

pub type JetAssociationsMap = Arc<Mutex<HashMap<Uuid, Association>>>;

pub struct JetClient {
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
}

impl JetClient {
    pub fn new(config: Arc<Config>, jet_associations: JetAssociationsMap) -> Self {
        JetClient {
            config,
            jet_associations,
        }
    }

    pub async fn serve(self, transport: JetTransport) -> Result<(), io::Error> {
        let msg_reader = JetMsgReader::new(transport);
        let jet_associations = self.jet_associations.clone();
        let config = self.config;

        let (transport, msg) = msg_reader.await?;

        match msg {
            JetMessage::JetTestReq(jet_test_req) => HandleTestJetMsg::new(transport, jet_test_req).await,
            JetMessage::JetAcceptReq(jet_accept_req) => {
                HandleAcceptJetMsg::new(config, transport, jet_accept_req, jet_associations.clone()).await
            }
            JetMessage::JetConnectReq(jet_connect_req) => {
                let response = HandleConnectJetMsg::new(transport, jet_connect_req, jet_associations.clone()).await?;

                let remove_association = RemoveAssociation::new(
                    jet_associations.clone(),
                    response.association_id,
                    Some(response.candidate_id),
                );

                let proxy_result = Proxy::new(config)
                    .build(response.server_transport, response.client_transport)
                    .await;

                remove_association.await;

                proxy_result
            }
            JetMessage::JetAcceptRsp(_) => Err(error_other("Jet-Accept response can't be handled by the server.")),
            JetMessage::JetConnectRsp(_) => Err(error_other("Jet-Accept response can't be handled by the server.")),
            JetMessage::JetTestRsp(_) => Err(error_other("Jet-Test response can't be handled by the server.")),
        }
    }
}

fn error_other<E: Into<Box<dyn std::error::Error + Send + Sync>>>(desc: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

struct JetMsgReader {
    transport: Option<JetTransport>,
    data_received: Vec<u8>,
}

impl JetMsgReader {
    fn new(transport: JetTransport) -> Self {
        JetMsgReader {
            transport: Some(transport),
            data_received: Vec::new(),
        }
    }
}

impl Future for JetMsgReader {
    type Output = Result<(JetTransport, JetMessage), io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut buff = [0u8; 1024];
        let mut poll_buff = ReadBuf::new(&mut buff);
        let transport = self
            .transport
            .as_mut()
            .expect("Must be taken only for the future result");

        ready!(Pin::new(transport).poll_read(cx, &mut poll_buff))?;

        if poll_buff.filled().is_empty() {
            // The transport is closed
            return Poll::Ready(Err(error_other("Socket closed, no JetPacket received.")));
        }

        let mut buf = poll_buff.filled().to_vec();
        self.data_received.append(&mut buf);

        if self.data_received.len() >= jet_proto::JET_MSG_HEADER_SIZE as usize {
            let mut slice = self.data_received.as_slice();
            let signature = slice.read_u32::<LittleEndian>()?; // signature
            if signature != jet_proto::JET_MSG_SIGNATURE {
                return Poll::Ready(Err(error_other(format!(
                    "Invalid JetPacket - Signature = {}.",
                    signature
                ))));
            }

            let msg_len = slice.read_u16::<BigEndian>()?;

            if self.data_received.len() >= msg_len as usize {
                let mut slice = self.data_received.as_slice();
                let jet_message = jet_proto::JetMessage::read_request(&mut slice)?;
                debug!("jet_message received: {:?}", jet_message);

                Poll::Ready(Ok((self.transport.take().unwrap(), jet_message)))
            } else {
                debug!(
                    "Waiting more data: received:{} - needed:{}",
                    self.data_received.len(),
                    msg_len
                );

                cx.waker().clone().wake();
                Poll::Pending
            }
        } else {
            debug!(
                "Waiting more data: received:{} - needed: at least header length ({})",
                self.data_received.len(),
                jet_proto::JET_MSG_HEADER_SIZE
            );

            cx.waker().clone().wake();
            Poll::Pending
        }
    }
}

enum HandleAcceptJetMsgState {
    CreateResponse,
    WriteResponse(Vec<u8>),
    SetTransport,
}

struct HandleAcceptJetMsg {
    config: Arc<Config>,
    transport: Option<JetTransport>,
    request_msg: JetAcceptReq,
    jet_associations: JetAssociationsMap,
    state: Option<HandleAcceptJetMsgState>,
    association_uuid: Option<Uuid>,
    remove_association_future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl HandleAcceptJetMsg {
    fn new(
        config: Arc<Config>,
        transport: JetTransport,
        msg: JetAcceptReq,
        jet_associations: JetAssociationsMap,
    ) -> Self {
        HandleAcceptJetMsg {
            config,
            transport: Some(transport),
            request_msg: msg,
            jet_associations,
            state: Some(HandleAcceptJetMsgState::CreateResponse),
            association_uuid: None,
            remove_association_future: None,
        }
    }

    fn handle_create_response(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<Vec<u8>, io::Error>> {
        let Self {
            jet_associations,
            request_msg,
            remove_association_future,
            association_uuid,
            config,
            ..
        } = self.deref_mut();
        let (status_code, association) = if let Ok(mut jet_associations) = jet_associations.try_lock() {
            match request_msg.version {
                1 => {
                    // Candidate creation
                    let mut candidate = Candidate::new_v1();
                    candidate.set_state(CandidateState::Accepted);

                    // Association creation
                    let uuid = Uuid::new_v4();
                    let mut association = Association::new(uuid, JET_VERSION_V1);
                    association.add_candidate(candidate);

                    association_uuid.replace(uuid);
                    jet_associations.insert(uuid, association);

                    (StatusCode::OK, uuid)
                }
                2 => {
                    let mut status_code = StatusCode::BAD_REQUEST;

                    if let Some(association) = jet_associations.get_mut(&request_msg.association) {
                        if association.version() == JET_VERSION_V2 {
                            if let Some(candidate) = association.get_candidate_mut(request_msg.candidate) {
                                if candidate.transport_type() == TransportType::Tcp {
                                    candidate.set_state(CandidateState::Accepted);

                                    status_code = StatusCode::OK;
                                }
                            } else {
                                status_code = StatusCode::NOT_FOUND;
                            }
                        }
                    }

                    (status_code, Uuid::nil())
                }
                _ => {
                    // No jet message exist with version different than 1 or 2
                    unreachable!()
                }
            }
        } else {
            cx.waker().clone().wake();
            return Poll::Pending;
        };

        if request_msg.version == 1 && status_code == StatusCode::OK {
            remove_association_future.replace(Box::pin(remove_association(jet_associations.clone(), association)));
        }

        // Build response
        let response_msg = JetMessage::JetAcceptRsp(JetAcceptRsp {
            status_code,
            version: request_msg.version,
            association,
            instance: config.hostname.clone(),
            timeout: ACCEPT_REQUEST_TIMEOUT.as_secs() as u32,
        });
        let mut response_msg_buffer = Vec::with_capacity(512);
        response_msg.write_to(&mut response_msg_buffer)?;

        Poll::Ready(Ok(response_msg_buffer))
    }

    fn handle_set_transport(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let Self {
            jet_associations,
            transport,
            request_msg,
            remove_association_future,
            association_uuid,
            ..
        } = self.deref_mut();

        if let Ok(mut jet_associations) = jet_associations.try_lock() {
            match request_msg.version {
                1 => {
                    let association = jet_associations
                        .get_mut(
                            association_uuid
                                .as_ref()
                                .expect("Must be set during parsing of the request"),
                        )
                        .expect("Was checked during parsing the request");
                    let candidate = association
                        .get_candidate_by_index(0)
                        .expect("Only one candidate exists in version 1 and there is no candidate id");
                    candidate.set_transport(transport.take().expect("Must be set in the constructor"));
                }
                2 => {
                    if let Some(association) = jet_associations.get_mut(&request_msg.association) {
                        if association.version() == JET_VERSION_V2 {
                            if let Some(candidate) = association.get_candidate_mut(request_msg.candidate) {
                                candidate.set_transport(transport.take().expect("Must be set in the constructor"));
                            }
                        }
                    }
                }
                _ => {
                    // No jet message exist with version different than 1 or 2
                    unreachable!()
                }
            };

            if let Some(remove_association_future) = remove_association_future.take() {
                tokio::spawn(remove_association_future);
            }

            Poll::Ready(Ok(()))
        } else {
            cx.waker().clone().wake();
            Poll::Pending
        }
    }
}

impl Future for HandleAcceptJetMsg {
    type Output = Result<(), io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            if self.state.is_none() {
                // Already polled last state
                return Poll::Ready(Ok(()));
            }
            let state = self.state.take().unwrap();
            let next_state = match state {
                HandleAcceptJetMsgState::CreateResponse => {
                    let response_msg_buffer = ready!(self.as_mut().handle_create_response(cx))?;
                    HandleAcceptJetMsgState::WriteResponse(response_msg_buffer)
                }
                HandleAcceptJetMsgState::WriteResponse(response_msg) => {
                    // We have a response for sure ==> Send response
                    let response_msg = response_msg.clone();

                    let transport = self
                        .transport
                        .as_mut()
                        .expect("Must not be taken upon successful poll_write");
                    ready!(Pin::new(transport).poll_write(cx, &response_msg))?;

                    HandleAcceptJetMsgState::SetTransport
                }
                HandleAcceptJetMsgState::SetTransport => {
                    ready!(self.as_mut().handle_set_transport(cx))?;

                    return Poll::Ready(Ok(()));
                }
            };

            self.state.replace(next_state);
        }
    }
}

struct HandleConnectJetMsg {
    client_transport: Option<JetTransport>,
    server_transport: Option<JetTransport>,
    request_msg: JetConnectReq,
    response_msg: Vec<u8>,
    jet_associations: JetAssociationsMap,
    association_id: Option<Uuid>,
    candidate_id: Option<Uuid>,
}

impl HandleConnectJetMsg {
    fn new(transport: JetTransport, msg: JetConnectReq, jet_associations: JetAssociationsMap) -> Self {
        HandleConnectJetMsg {
            client_transport: Some(transport),
            server_transport: None,
            request_msg: msg,
            response_msg: Vec::with_capacity(512),
            jet_associations,
            association_id: None,
            candidate_id: None,
        }
    }
}

impl Future for HandleConnectJetMsg {
    type Output = Result<HandleConnectJetMsgResponse, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let (
            jet_associations,
            request_msg,
            server_transport,
            association_id,
            candidate_id,
            client_transport,
            mut response_msg,
        ) = match self.deref_mut() {
            Self {
                jet_associations,
                request_msg,
                server_transport,
                association_id,
                candidate_id,
                client_transport,
                response_msg,
                ..
            } => (
                jet_associations,
                request_msg,
                server_transport,
                association_id,
                candidate_id,
                client_transport,
                response_msg,
            ),
        };

        // Find the server transport
        if server_transport.is_none() {
            if let Ok(mut jet_associations) = jet_associations.try_lock() {
                let mut status_code = StatusCode::BAD_REQUEST;

                if let Some(association) = jet_associations.get_mut(&request_msg.association) {
                    let candidate = match (association.version(), request_msg.version) {
                        (1, 1) => {
                            // Only one candidate exists in version 1 and there is no candidate id.
                            if let Some(candidate) = association.get_candidate_by_index(0) {
                                if candidate.state() == CandidateState::Accepted {
                                    Some(candidate)
                                } else {
                                    None
                                }
                            } else {
                                unreachable!("No candidate found for an association version 1. Should never happen.");
                            }
                        }
                        (2, 2) => {
                            if let Some(candidate) = association.get_candidate_mut(request_msg.candidate) {
                                if candidate.transport_type() == TransportType::Tcp
                                    && candidate.state() == CandidateState::Accepted
                                {
                                    Some(candidate)
                                } else {
                                    None
                                }
                            } else {
                                status_code = StatusCode::NOT_FOUND;

                                None
                            }
                        }
                        (association_version, request_version) => {
                            error!(
                                "Invalid version: Association version={}, Request version={}",
                                association_version, request_version
                            );

                            None
                        }
                    };

                    if let Some(candidate) = candidate {
                        // The accept request has been received before and a transport is available to open the proxy
                        if let Some(candidate_server_transport) = candidate.take_transport() {
                            candidate.set_state(CandidateState::Connected);

                            server_transport.replace(candidate_server_transport);
                            association_id.replace(candidate.association_id());
                            candidate_id.replace(candidate.id());

                            let client_transport = client_transport
                                .as_ref()
                                .expect("Client's transport must be taken on the future result");
                            candidate.set_client_nb_bytes_read(client_transport.clone_nb_bytes_read());
                            candidate.set_client_nb_bytes_written(client_transport.clone_nb_bytes_written());

                            status_code = StatusCode::OK;
                        }
                    }
                } else {
                    status_code = StatusCode::NOT_FOUND;
                }

                let connect_response_msg = JetMessage::JetConnectRsp(JetConnectRsp {
                    status_code,
                    version: request_msg.version,
                });
                connect_response_msg.write_to(&mut response_msg)?;
            } else {
                cx.waker().clone().wake();
                return Poll::Pending;
            }
        }

        {
            let client_transport = client_transport
                .as_mut()
                .expect("Client's transport must be taken on the future result");

            ready!(Pin::new(client_transport).poll_write(cx, response_msg.as_ref()))?;
        }

        // If server stream found, start the proxy
        match (server_transport.take(), association_id.take(), candidate_id.take()) {
            (Some(server_transport), Some(association_id), Some(candidate_id)) => {
                let client_transport = client_transport.take().expect("Must be taken only once");
                Poll::Ready(Ok(HandleConnectJetMsgResponse {
                    client_transport,
                    server_transport,
                    association_id,
                    candidate_id,
                }))
            }
            _ => Poll::Ready(Err(error_other(format!(
                "Invalid association ID received: {}",
                request_msg.association
            )))),
        }
    }
}

pub struct HandleConnectJetMsgResponse {
    pub client_transport: JetTransport,
    pub server_transport: JetTransport,
    pub association_id: Uuid,
    pub candidate_id: Uuid,
}

struct HandleTestJetMsg {
    transport: JetTransport,
    request: JetTestReq,
    response: Option<Vec<u8>>,
}

impl HandleTestJetMsg {
    fn new(transport: JetTransport, request: JetTestReq) -> Self {
        Self {
            transport,
            request,
            response: None,
        }
    }
}

impl Future for HandleTestJetMsg {
    type Output = Result<(), io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if self.response.is_none() {
            let response_msg = JetMessage::JetTestRsp(JetTestRsp {
                status_code: StatusCode::OK,
                version: self.request.version,
            });
            let mut response_msg_buffer = Vec::with_capacity(512);
            response_msg.write_to(&mut response_msg_buffer)?;
            self.response = Some(response_msg_buffer);
        }

        let Self {
            response, transport, ..
        } = self.deref_mut();
        let response = response.as_ref().unwrap();
        ready!(Pin::new(transport).poll_write(cx, &response))?;
        Poll::Ready(Ok(()))
    }
}
