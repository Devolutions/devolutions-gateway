use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{io, str};

use futures::future::{err, ok};
use futures::{try_ready, Async, Future};
use tokio::runtime::TaskExecutor;
use tokio::timer::Delay;
use tokio_io::{AsyncRead, AsyncWrite};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use uuid::Uuid;
use jet_proto::{StatusCode, JET_VERSION_V2};

use jet_proto::{JET_VERSION_V1, JetMessage};
use log::{debug, error, info};

use crate::config::Config;
use crate::transport::JetTransport;
use crate::Proxy;
use crate::jet::association::Association;
use crate::jet::candidate::Candidate;
use jet_proto::connect::{JetConnectReq, JetConnectRsp};
use jet_proto::accept::{JetAcceptReq, JetAcceptRsp};
use crate::jet::TransportType;
use crate::utils::association::{RemoveAssociation, ACCEPT_REQUEST_TIMEOUT_SEC};

pub type JetAssociationsMap = Arc<Mutex<HashMap<Uuid, Association>>>;



pub struct JetClient {
    config: Config,
    jet_associations: JetAssociationsMap,
    _executor_handle: TaskExecutor,
}

impl JetClient {
    pub fn new(config: Config, jet_associations: JetAssociationsMap, executor_handle: TaskExecutor) -> Self {
        JetClient {
            config,
            jet_associations,
            _executor_handle: executor_handle,
        }
    }

    pub fn serve(self, transport: JetTransport) -> Box<dyn Future<Item = (), Error = io::Error> + Send> {
        let msg_reader = JetMsgReader::new(transport.clone());
        let jet_associations = self.jet_associations.clone();
        let executor_handle = self._executor_handle.clone();
        let config = self.config.clone();

        Box::new(msg_reader.and_then(move |msg| {
            match msg {
                JetMessage::JetAcceptReq(jet_accept_req) => {
                    let handle_msg = HandleAcceptJetMsg::new(&config, transport.clone(), jet_accept_req, jet_associations, executor_handle);
                    Box::new(handle_msg) as Box<dyn Future<Item = (), Error = io::Error> + Send>
                }
                JetMessage::JetConnectReq(jet_connect_req) => {
                    let handle_msg = HandleConnectJetMsg::new(transport.clone(), jet_connect_req, jet_associations);
                    Box::new(handle_msg.and_then(|(t1, t2)| Proxy::new(config).build(t1, t2)))
                        as Box<dyn Future<Item = (), Error = io::Error> + Send>
                }
                JetMessage::JetAcceptRsp(_) => {
                    Box::new(err(error_other("Jet-Accept response can't be handled by the server."))) as Box<dyn Future<Item = (), Error = io::Error> + Send>
                }
                JetMessage::JetConnectRsp(_) => {
                    Box::new(err(error_other("Jet-Accept response can't be handled by the server."))) as Box<dyn Future<Item = (), Error = io::Error> + Send>
                }
            }
        }))
    }
}

fn error_other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

struct JetMsgReader {
    transport: JetTransport,
    data_received: Vec<u8>,
}

impl JetMsgReader {
    fn new(transport: JetTransport) -> Self {
        JetMsgReader {
            transport,
            data_received: Vec::new(),
        }
    }
}

impl Future for JetMsgReader {
    type Item = JetMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        let mut buff = [0u8; 1024];
        let len = try_ready!(self.transport.poll_read(&mut buff));
        let mut buf = buff.to_vec();
        buf.truncate(len);
        self.data_received.append(&mut buf);

        if self.data_received.len() >= jet_proto::JET_MSG_HEADER_SIZE as usize {
            let mut slice = self.data_received.as_slice();
            let signature = slice.read_u32::<LittleEndian>()?; // signature
            if signature != jet_proto::JET_MSG_SIGNATURE {
                return Err(error_other(&format!("Invalid JetPacket - Signature = {}.", signature)));
            }

            let msg_len = slice.read_u16::<BigEndian>()?;

            if self.data_received.len() >= msg_len as usize {
                let mut slice = self.data_received.as_slice();
                let jet_message = jet_proto::JetMessage::read_request(&mut slice)?;
                debug!("jet_message received: {:?}", jet_message);
                Ok(Async::Ready(jet_message))
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

struct HandleAcceptJetMsg {
    config: Config,
    transport: JetTransport,
    request_msg: JetAcceptReq,
    response_msg: Option<JetMessage>,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
}

impl HandleAcceptJetMsg {
    fn new(
        config: &Config,
        transport: JetTransport,
        msg: JetAcceptReq,
        jet_associations: JetAssociationsMap,
        executor_handle: TaskExecutor,
    ) -> Self {
        HandleAcceptJetMsg {
            config: config.clone(),
            transport,
            request_msg: msg,
            response_msg: None,
            jet_associations,
            executor_handle,
        }
    }
}

impl Future for HandleAcceptJetMsg {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        let mut new_association = false;

        if self.response_msg.is_none() {
            if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
                let request = &self.request_msg;
                match self.request_msg.version {
                    1 => {
                        // Association creation
                        let uuid = Uuid::new_v4();
                        let mut association = Association::new(uuid, JET_VERSION_V1);
                        let mut candidate = Candidate::new_v1();
                        candidate.set_server_transport(self.transport.clone());
                        association.add_candidate(candidate);

                        jet_associations.insert(uuid, association);
                        new_association = true;

                        // Build response
                        self.response_msg = Some(JetMessage::JetAcceptRsp(JetAcceptRsp {
                            status_code: StatusCode::OK,
                            version: request.version,
                            association: uuid,
                            instance: self.config.jet_instance(),
                            timeout: ACCEPT_REQUEST_TIMEOUT_SEC,
                        }));
                    }
                    2 => {
                        let mut status_code = StatusCode::BAD_REQUEST;

                        if let Some(association) = jet_associations.get_mut(&request.association) {
                            if association.version() == JET_VERSION_V2 {
                                if let Some(candidate) = association.get_candidate_mut(request.candidate) {
                                    if candidate.transport_type() == TransportType::Tcp {
                                        candidate.set_server_transport(self.transport.clone());
                                        status_code = StatusCode::OK;
                                    }
                                } else {
                                    status_code = StatusCode::NOT_FOUND;
                                }
                            }
                        }

                        self.response_msg = Some(JetMessage::JetAcceptRsp(JetAcceptRsp {
                            status_code,
                            version: request.version,
                            association: Uuid::nil(),
                            instance: self.config.jet_instance(),
                            timeout: ACCEPT_REQUEST_TIMEOUT_SEC,
                        }));
                    }
                    _ => {
                        // No jet message exist with version different than 1 or 2
                        unreachable!()
                    }
                }
            } else {
                return Ok(Async::NotReady);
            }
        }

        // We have a response ==> Send response + timeout to remove the server if not used
        let response_msg = self.response_msg.as_ref().unwrap();
        let mut v = Vec::new();
        response_msg.write_to(&mut v)?;
        try_ready!(self.transport.poll_write(&v));

        // Start timeout to remove the association if no connect is received
        if new_association {
            if let JetMessage::JetAcceptRsp(accept_rsp) = response_msg {
                if accept_rsp.status_code == 200 {
                    let association = accept_rsp.association;
                    let jet_associations = self.jet_associations.clone();
                    let timeout = Delay::new(Instant::now() + Duration::from_secs(ACCEPT_REQUEST_TIMEOUT_SEC as u64));
                    self.executor_handle.spawn(timeout.then(move |_| {
                        RemoveAssociation::new(jet_associations, association).then(move |res| {
                            if let Ok(true) = res {
                                info!(
                                    "No connect request received with association {}. Association removed!",
                                    association
                                );
                            }
                            ok(())
                        })
                    }));
                }
            }
        }

        Ok(Async::Ready(()))
    }
}

struct HandleConnectJetMsg {
    transport: JetTransport,
    server_transport: Option<JetTransport>,
    request_msg: JetConnectReq,
    response_msg: Option<JetMessage>,
    jet_associations: JetAssociationsMap,
}

impl HandleConnectJetMsg {
    fn new(transport: JetTransport, msg: JetConnectReq, jet_associations: JetAssociationsMap) -> Self {
        HandleConnectJetMsg {
            transport,
            server_transport: None,
            request_msg: msg,
            response_msg: None,
            jet_associations,
        }
    }
}

impl Future for HandleConnectJetMsg {
    type Item = (JetTransport, JetTransport);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        // Find the server transport
        if self.server_transport.is_none() {
            if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
                let association_opt = jet_associations.remove(&self.request_msg.association);
                let mut status_code = StatusCode::BAD_REQUEST;

                if let Some(mut association) = association_opt {
                    match (association.version(), self.request_msg.version) {
                        (1, 1) => {
                            // Only one candidate exists in version 1 and there is no candidate id.
                            if let Some(candidate) = association.get_candidate_by_index(0) {
                                if let Some(transport) = candidate.server_transport() {
                                    // The accept request has been received before and a transport is available to open the proxy
                                    self.server_transport = Some(transport);
                                    status_code = StatusCode::OK;
                                }
                            } else {
                                error!("No candidate found for an association version 1. Should never happen.");
                                status_code = StatusCode::INTERNAL_SERVER_ERROR;
                            }
                        }
                        (2, 2) => {
                            if let Some(candidate) = association.get_candidate_mut(self.request_msg.candidate) {
                                if candidate.transport_type() == TransportType::Tcp {
                                    if let Some(transport) = candidate.server_transport() {
                                        // The accept request has been received before and a transport is available to open the proxy
                                        self.server_transport = Some(transport);
                                        status_code = StatusCode::OK;
                                    }
                                }
                            } else {
                                status_code = StatusCode::NOT_FOUND;
                            }
                        }
                        (association_version, request_version) => {
                            error!("Invalid version: Association version={}, Request version={}", association_version, request_version);
                        }
                    }

                } else {
                    status_code = StatusCode::NOT_FOUND;
                }

                self.response_msg = Some(JetMessage::JetConnectRsp(JetConnectRsp {
                    status_code,
                    version: self.request_msg.version,
                }));

            } else {
                return Ok(Async::NotReady);
            }
        }

        // Send response
        let msg = self.response_msg.clone().unwrap();

        let mut v = Vec::new();
        msg.write_to(&mut v)?;
        let _ = try_ready!(self.transport.poll_write(&v));

        // If server stream found, start the proxy
        if self.server_transport.is_some() {
            Ok(Async::Ready((
                self.server_transport.take().unwrap().clone(),
                self.transport.clone(),
            )))
        } else {
            Err(error_other(&format!(
                "Invalid association ID received: {}", self.request_msg.association)))
        }
    }
}