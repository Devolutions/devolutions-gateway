use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, io, str};

use futures::future::{err, ok};
use futures::{try_ready, Async, Future};
use tokio::runtime::TaskExecutor;
use tokio::timer::Delay;
use tokio_io::{AsyncRead, AsyncWrite};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use lazy_static::lazy_static;
use uuid::Uuid;

use jet_proto::{JetPacket, ResponseStatusCode, JET_VERSION_V1};
use log::{debug, error, info};

use crate::config::Config;
use crate::transport::JetTransport;
use crate::Proxy;
use url::Url;
use crate::jet::Role;
use crate::jet::association::Association;
use crate::jet::candidate::Candidate;

pub type JetAssociationsMap = Arc<Mutex<HashMap<Uuid, Association>>>;

lazy_static! {
    static ref JET_INSTANCE: Option<String> = { env::var("JET_INSTANCE").ok() };
}

const ACCEPT_REQUEST_TIMEOUT_SEC: u64 = 5 * 60;

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
            if msg.is_accept() {
                let handle_msg = HandleAcceptJetMsg::new(transport.clone(), msg, jet_associations, executor_handle);
                Box::new(handle_msg) as Box<dyn Future<Item = (), Error = io::Error> + Send>
            } else if msg.is_connect() {
                let handle_msg = HandleConnectJetMsg::new(transport.clone(), msg, jet_associations);
                Box::new(handle_msg.and_then(|(t1, t2)| Proxy::new(config).build(t1, t2)))
                    as Box<dyn Future<Item = (), Error = io::Error> + Send>
            } else {
                Box::new(err(error_other("Invalid method"))) as Box<dyn Future<Item = (), Error = io::Error> + Send>
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
    type Item = JetPacket;
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
                let jet_packet = jet_proto::JetPacket::read_from(&mut slice)?;
                debug!("jet_packet received: {:?}", jet_packet);
                Ok(Async::Ready(jet_packet))
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
    transport: JetTransport,
    request_msg: JetPacket,
    response_msg: Option<JetPacket>,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
}

impl HandleAcceptJetMsg {
    fn new(
        transport: JetTransport,
        msg: JetPacket,
        jet_associations: JetAssociationsMap,
        executor_handle: TaskExecutor,
    ) -> Self {
        assert!(msg.is_accept());
        HandleAcceptJetMsg {
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
        if self.response_msg.is_none() {
            if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
                let uuid = Uuid::new_v4();
                let mut response_msg = JetPacket::new_response(
                    self.request_msg.flags(),
                    self.request_msg.mask(),
                    ResponseStatusCode::StatusCode200,
                );
                response_msg.set_timeout(Some(ACCEPT_REQUEST_TIMEOUT_SEC as u32));
                response_msg.set_association(Some(uuid));
                response_msg.set_jet_instance(JET_INSTANCE.clone());
                self.response_msg = Some(response_msg);

                let mut association = Association::new(uuid, JET_VERSION_V1);
                let mut candidate = Candidate::new_v1(); //TODO Remove unwrap
                candidate.set_server_transport(self.transport.clone());
                association.add_candidate(candidate);

                jet_associations.insert(uuid, association);
            } else {
                return Ok(Async::NotReady);
            }
        }

        // We have a response ==> Send response + timeout to remove the server if not used
        let response_msg = self.response_msg.as_ref().unwrap();
        let mut v = Vec::new();
        response_msg.write_to(&mut v)?;
        try_ready!(self.transport.poll_write(&v));

        // Start timeout to remove the server if no connect request is received with that UUID
        let association = response_msg.association().unwrap();
        let jet_associations = self.jet_associations.clone();
        let timeout = Delay::new(Instant::now() + Duration::from_secs(ACCEPT_REQUEST_TIMEOUT_SEC));
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

        Ok(Async::Ready(()))
    }
}

struct HandleConnectJetMsg {
    transport: JetTransport,
    server_transport: Option<JetTransport>,
    request_msg: JetPacket,
    response_msg: Option<JetPacket>,
    jet_associations: JetAssociationsMap,
}

impl HandleConnectJetMsg {
    fn new(transport: JetTransport, msg: JetPacket, jet_associations: JetAssociationsMap) -> Self {
        assert!(msg.is_connect());

        HandleConnectJetMsg {
            transport,
            server_transport: None,
            request_msg: msg,
            response_msg: None,
            jet_associations,
        }
    }

    fn send_response(&mut self, response: &JetPacket) -> Result<Async<usize>, io::Error> {
        let mut v = Vec::new();
        response.write_to(&mut v)?;
        let len = try_ready!(self.transport.poll_write(&v));
        Ok(Async::Ready(len))
    }
}

impl Future for HandleConnectJetMsg {
    type Item = (JetTransport, JetTransport);
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        //Validate the request
        if self.request_msg.association().is_none() {
            let response = JetPacket::new_response(
                self.request_msg.flags(),
                self.request_msg.mask(),
                ResponseStatusCode::StatusCode400,
            );
            self.send_response(&response)?;
            return Err(error_other("Invalid connect request: No association provided."));
        }

        // Find the server transport
        if self.server_transport.is_none() {
            if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
                let association_opt = jet_associations.remove(&self.request_msg.association().unwrap());

                if let Some(mut association) = association_opt {
                    if let Some(candidate) = association.get_candidate_by_index(0) {
                        self.server_transport = candidate.server_transport();
                        self.response_msg = Some(JetPacket::new_response(
                                self.request_msg.flags(),
                                self.request_msg.mask(),
                                ResponseStatusCode::StatusCode200,
                            ));
                    }

                } else {
                    self.response_msg = Some(JetPacket::new_response(
                        self.request_msg.flags(),
                        self.request_msg.mask(),
                        ResponseStatusCode::StatusCode400,
                    ));
                    error!(
                        "Invalid association ID received: {}",
                        self.request_msg.association().unwrap()
                    );
                }
            } else {
                return Ok(Async::NotReady);
            }
        }

        // Send response
        let msg = self.response_msg.clone().unwrap();
        try_ready!(self.send_response(&msg));

        // If server stream found, start the proxy
        if self.server_transport.is_some() {
            Ok(Async::Ready((
                self.server_transport.take().unwrap().clone(),
                self.transport.clone(),
            )))
        } else {
            Err(error_other(&format!(
                "Invalid association ID received: {}",
                self.request_msg.association().unwrap()
            )))
        }
    }
}

struct RemoveAssociation {
    jet_associations: JetAssociationsMap,
    association: Uuid,
}

impl RemoveAssociation {
    fn new(jet_associations: JetAssociationsMap, association: Uuid) -> Self {
        RemoveAssociation {
            jet_associations,
            association,
        }
    }
}

impl Future for RemoveAssociation {
    type Item = bool;
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
            let removed = jet_associations.remove(&self.association).is_some();
            Ok(Async::Ready(removed))
        } else {
            Ok(Async::NotReady)
        }
    }
}
