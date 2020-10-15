use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use futures::{future::err, try_ready, Async, Future, Poll};
use jet_proto::test::JetTestReq;
use jet_proto::{
    accept::{JetAcceptReq, JetAcceptRsp},
    connect::{JetConnectReq, JetConnectRsp},
    test::JetTestRsp,
    JetMessage, StatusCode, JET_VERSION_V1, JET_VERSION_V2,
};
use slog_scope::{debug, error};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::TaskExecutor,
};
use uuid::Uuid;

use crate::{
    config::Config,
    http::controllers::jet::create_remove_association_future,
    jet::{
        association::Association,
        candidate::{Candidate, CandidateState},
        TransportType,
    },
    transport::JetTransport,
    utils::association::{RemoveAssociation, ACCEPT_REQUEST_TIMEOUT_SEC},
    Proxy,
};

pub type JetAssociationsMap = Arc<Mutex<HashMap<Uuid, Association>>>;

pub struct JetClient {
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    _executor_handle: TaskExecutor,
}

impl JetClient {
    pub fn new(config: Arc<Config>, jet_associations: JetAssociationsMap, executor_handle: TaskExecutor) -> Self {
        JetClient {
            config,
            jet_associations,
            _executor_handle: executor_handle,
        }
    }

    pub fn serve(self, transport: JetTransport) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let msg_reader = JetMsgReader::new(transport);
        let jet_associations = self.jet_associations.clone();
        let executor_handle = self._executor_handle.clone();
        let config = self.config;

        Box::new(msg_reader.and_then(move |(transport, msg)| match msg {
            JetMessage::JetTestReq(jet_test_req) => {
                let handle_msg = HandleTestJetMsg::new(transport, jet_test_req);
                Box::new(handle_msg) as Box<dyn Future<Item = (), Error = io::Error> + Send>
            }
            JetMessage::JetAcceptReq(jet_accept_req) => {
                let handle_msg = HandleAcceptJetMsg::new(
                    config,
                    transport,
                    jet_accept_req,
                    jet_associations.clone(),
                    executor_handle,
                );

                Box::new(handle_msg) as Box<dyn Future<Item = (), Error = io::Error> + Send>
            }
            JetMessage::JetConnectReq(jet_connect_req) => {
                let handle_msg = HandleConnectJetMsg::new(transport, jet_connect_req, jet_associations.clone());
                Box::new(handle_msg.and_then(move |response| {
                    let remove_association = RemoveAssociation::new(
                        jet_associations.clone(),
                        response.association_id,
                        Some(response.candidate_id),
                    );

                    Proxy::new(config)
                        .build(response.server_transport, response.client_transport)
                        .then(|proxy_result| remove_association.then(|_| futures::future::result(proxy_result)))
                }))
            }
            JetMessage::JetAcceptRsp(_) => {
                Box::new(err(error_other("Jet-Accept response can't be handled by the server.")))
            }
            JetMessage::JetConnectRsp(_) => {
                Box::new(err(error_other("Jet-Accept response can't be handled by the server.")))
            }
            JetMessage::JetTestRsp(_) => {
                Box::new(err(error_other("Jet-Test response can't be handled by the server.")))
            }
        }))
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
    type Item = (JetTransport, JetMessage);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut buff = [0u8; 1024];
        let len = try_ready!(self
            .transport
            .as_mut()
            .expect("Must be taken only for the future result")
            .poll_read(&mut buff));

        if len == 0 {
            // The transport is closed
            return Err(error_other("Socket closed, no JetPacket received."));
        }

        let mut buf = buff.to_vec();
        buf.truncate(len);
        self.data_received.append(&mut buf);

        if self.data_received.len() >= jet_proto::JET_MSG_HEADER_SIZE as usize {
            let mut slice = self.data_received.as_slice();
            let signature = slice.read_u32::<LittleEndian>()?; // signature
            if signature != jet_proto::JET_MSG_SIGNATURE {
                return Err(error_other(format!("Invalid JetPacket - Signature = {}.", signature)));
            }

            let msg_len = slice.read_u16::<BigEndian>()?;

            if self.data_received.len() >= msg_len as usize {
                let mut slice = self.data_received.as_slice();
                let jet_message = jet_proto::JetMessage::read_request(&mut slice)?;
                debug!("jet_message received: {:?}", jet_message);

                Ok(Async::Ready((self.transport.take().unwrap(), jet_message)))
            } else {
                debug!(
                    "Waiting more data: received:{} - needed:{}",
                    self.data_received.len(),
                    msg_len
                );

                Ok(Async::NotReady)
            }
        } else {
            debug!(
                "Waiting more data: received:{} - needed: at least header length ({})",
                self.data_received.len(),
                jet_proto::JET_MSG_HEADER_SIZE
            );

            Ok(Async::NotReady)
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
    executor_handle: TaskExecutor,
    state: HandleAcceptJetMsgState,
    association_uuid: Option<Uuid>,
    remove_association_future: Option<Box<dyn Future<Item = (), Error = ()> + Send>>,
}

impl HandleAcceptJetMsg {
    fn new(
        config: Arc<Config>,
        transport: JetTransport,
        msg: JetAcceptReq,
        jet_associations: JetAssociationsMap,
        executor_handle: TaskExecutor,
    ) -> Self {
        HandleAcceptJetMsg {
            config,
            transport: Some(transport),
            request_msg: msg,
            jet_associations,
            executor_handle,
            state: HandleAcceptJetMsgState::CreateResponse,
            association_uuid: None,
            remove_association_future: None,
        }
    }

    fn handle_create_response(&mut self) -> Poll<Vec<u8>, io::Error> {
        if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
            let request = &self.request_msg;

            let (status_code, association) = match self.request_msg.version {
                1 => {
                    // Candidate creation
                    let mut candidate = Candidate::new_v1();
                    candidate.set_state(CandidateState::Accepted);

                    // Association creation
                    let uuid = Uuid::new_v4();
                    let mut association = Association::new(uuid, JET_VERSION_V1);
                    association.add_candidate(candidate);
                    self.association_uuid = Some(uuid);

                    jet_associations.insert(uuid, association);

                    (StatusCode::OK, uuid)
                }
                2 => {
                    let mut status_code = StatusCode::BAD_REQUEST;

                    if let Some(association) = jet_associations.get_mut(&request.association) {
                        if association.version() == JET_VERSION_V2 {
                            if let Some(candidate) = association.get_candidate_mut(request.candidate) {
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
            };

            if request.version == 1 && status_code == StatusCode::OK {
                self.remove_association_future = Some(Box::new(create_remove_association_future(
                    self.jet_associations.clone(),
                    association,
                )));
            }

            // Build response
            let response_msg = JetMessage::JetAcceptRsp(JetAcceptRsp {
                status_code,
                version: request.version,
                association,
                instance: self.config.jet_instance.clone(),
                timeout: ACCEPT_REQUEST_TIMEOUT_SEC,
            });
            let mut response_msg_buffer = Vec::with_capacity(512);
            response_msg.write_to(&mut response_msg_buffer)?;

            Ok(Async::Ready(response_msg_buffer))
        } else {
            Ok(Async::NotReady)
        }
    }

    fn handle_set_transport(&mut self) -> Poll<(), io::Error> {
        if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
            match self.request_msg.version {
                1 => {
                    let association = jet_associations
                        .get_mut(
                            self.association_uuid
                                .as_ref()
                                .expect("Must be set during parsing of the request"),
                        )
                        .expect("Was checked during parsing the request");
                    let candidate = association
                        .get_candidate_by_index(0)
                        .expect("Only one candidate exists in version 1 and there is no candidate id");
                    candidate.set_transport(self.transport.take().expect("Must be set in the constructor"));
                }
                2 => {
                    let request = &self.request_msg;
                    if let Some(association) = jet_associations.get_mut(&request.association) {
                        if association.version() == JET_VERSION_V2 {
                            if let Some(candidate) = association.get_candidate_mut(request.candidate) {
                                candidate.set_transport(self.transport.take().expect("Must be set in the constructor"));
                            }
                        }
                    }
                }
                _ => {
                    // No jet message exist with version different than 1 or 2
                    unreachable!()
                }
            };

            if let Some(remove_association_future) = self.remove_association_future.take() {
                self.executor_handle.spawn(remove_association_future);
            }

            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }
}

impl Future for HandleAcceptJetMsg {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match &self.state {
                HandleAcceptJetMsgState::CreateResponse => {
                    let response_msg_buffer = try_ready!(self.handle_create_response());
                    self.state = HandleAcceptJetMsgState::WriteResponse(response_msg_buffer);
                }
                HandleAcceptJetMsgState::WriteResponse(response_msg) => {
                    // We have a response for sure ==> Send response
                    try_ready!(self
                        .transport
                        .as_mut()
                        .expect("Must not be taken upon successful poll_write")
                        .poll_write(response_msg));

                    self.state = HandleAcceptJetMsgState::SetTransport;
                }
                HandleAcceptJetMsgState::SetTransport => {
                    try_ready!(self.handle_set_transport());

                    return Ok(Async::Ready(()));
                }
            }
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
    type Item = HandleConnectJetMsgResponse;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Find the server transport
        if self.server_transport.is_none() {
            if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
                let mut status_code = StatusCode::BAD_REQUEST;

                if let Some(association) = jet_associations.get_mut(&self.request_msg.association) {
                    let candidate = match (association.version(), self.request_msg.version) {
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
                            if let Some(candidate) = association.get_candidate_mut(self.request_msg.candidate) {
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
                        if let Some(server_transport) = candidate.take_transport() {
                            candidate.set_state(CandidateState::Connected);

                            self.server_transport = Some(server_transport);
                            self.association_id = Some(candidate.association_id());
                            self.candidate_id = Some(candidate.id());

                            let client_transport = self
                                .client_transport
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

                let response_msg = JetMessage::JetConnectRsp(JetConnectRsp {
                    status_code,
                    version: self.request_msg.version,
                });
                response_msg.write_to(&mut self.response_msg)?;
            } else {
                return Ok(Async::NotReady);
            }
        }

        // Send response
        try_ready!(self
            .client_transport
            .as_mut()
            .expect("Client's transport must be taken on the future result")
            .poll_write(self.response_msg.as_ref()));

        // If server stream found, start the proxy
        match (
            self.server_transport.take(),
            self.association_id.take(),
            self.candidate_id.take(),
        ) {
            (Some(server_transport), Some(association_id), Some(candidate_id)) => {
                let client_transport = self.client_transport.take().expect("Must be taken only once");
                Ok(Async::Ready(HandleConnectJetMsgResponse {
                    client_transport,
                    server_transport,
                    association_id,
                    candidate_id,
                }))
            }
            _ => Err(error_other(format!(
                "Invalid association ID received: {}",
                self.request_msg.association
            ))),
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
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.response.is_none() {
            let response_msg = JetMessage::JetTestRsp(JetTestRsp {
                status_code: StatusCode::OK,
                version: self.request.version,
            });
            let mut response_msg_buffer = Vec::with_capacity(512);
            response_msg.write_to(&mut response_msg_buffer)?;
            self.response = Some(response_msg_buffer);
        }

        let response = self.response.as_ref().unwrap(); // set above
        try_ready!(self.transport.poll_write(&response));
        Ok(Async::Ready(()))
    }
}
