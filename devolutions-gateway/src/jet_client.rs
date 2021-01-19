use std::{collections::HashMap, future::Future, io, pin::Pin, sync::Arc};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use jet_proto::{
    accept::{JetAcceptReq, JetAcceptRsp},
    connect::{JetConnectReq, JetConnectRsp},
    test::{JetTestReq, JetTestRsp},
    JetMessage, StatusCode, JET_VERSION_V1, JET_VERSION_V2,
};
use slog_scope::{debug, error};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
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
    utils::{
        association::{remove_jet_association, ACCEPT_REQUEST_TIMEOUT},
        into_other_io_error as error_other,
    },
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
        let jet_associations = self.jet_associations.clone();
        let config = self.config;

        let (transport, msg) = read_jet_message(transport).await?;

        match msg {
            JetMessage::JetTestReq(jet_test_req) => handle_test_jet_msg(transport, jet_test_req).await,
            JetMessage::JetAcceptReq(jet_accept_req) => {
                HandleAcceptJetMsg::new(config, transport, jet_accept_req, jet_associations.clone())
                    .accept()
                    .await
            }
            JetMessage::JetConnectReq(jet_connect_req) => {
                let response = handle_connect_jet_msg(transport, jet_connect_req, jet_associations.clone()).await?;

                let association_id = response.association_id;
                let candidate_id = response.candidate_id;

                let proxy_result = Proxy::new(config)
                    .build(response.server_transport, response.client_transport)
                    .await;

                remove_jet_association(jet_associations.clone(), association_id, Some(candidate_id)).await;

                proxy_result
            }
            JetMessage::JetAcceptRsp(_) => Err(error_other("Jet-Accept response can't be handled by the server.")),
            JetMessage::JetConnectRsp(_) => Err(error_other("Jet-Accept response can't be handled by the server.")),
            JetMessage::JetTestRsp(_) => Err(error_other("Jet-Test response can't be handled by the server.")),
        }
    }
}

async fn read_jet_message(mut transport: JetTransport) -> Result<(JetTransport, JetMessage), io::Error> {
    let mut data_received = Vec::new();

    let mut buff = [0u8; 1024];

    while data_received.len() < jet_proto::JET_MSG_HEADER_SIZE as usize {
        let bytes_read = transport.read(&mut buff).await?;

        if bytes_read == 0 {
            return Err(error_other(
                "Socket closed during Jet header receive, no JetPacket received.",
            ));
        }

        data_received.extend_from_slice(&buff[..bytes_read]);

        debug!(
            "Received {} of {} bytes of jet message header",
            data_received.len(),
            jet_proto::JET_MSG_HEADER_SIZE
        );
    }

    let mut slice = data_received.as_slice();
    let signature = ReadBytesExt::read_u32::<LittleEndian>(&mut slice)?; // signature
    if signature != jet_proto::JET_MSG_SIGNATURE {
        return Err(error_other(format!("Invalid JetPacket - Signature = {}.", signature)));
    }

    let msg_len = ReadBytesExt::read_u16::<BigEndian>(&mut slice)?;

    while data_received.len() < msg_len as usize {
        let bytes_read = transport.read(&mut buff).await?;

        if bytes_read == 0 {
            return Err(error_other(
                "Socket closed during Jet message receive, no JetPacket received.",
            ));
        }

        data_received.extend_from_slice(&buff[..bytes_read]);

        debug!("Received {} of {} bytes of jet message", data_received.len(), msg_len);
    }

    let mut slice = data_received.as_slice();
    let jet_message = jet_proto::JetMessage::read_request(&mut slice)?;
    debug!("jet_message received: {:?}", jet_message);

    Ok((transport, jet_message))
}

struct HandleAcceptJetMsg {
    config: Arc<Config>,
    transport: Option<JetTransport>,
    request_msg: JetAcceptReq,
    jet_associations: JetAssociationsMap,
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
            association_uuid: None,
            remove_association_future: None,
        }
    }

    async fn handle_create_response(&mut self) -> Result<Vec<u8>, io::Error> {
        let (status_code, association) = {
            let mut jet_associations = self.jet_associations.lock().await;

            match self.request_msg.version {
                1 => {
                    // Candidate creation
                    let mut candidate = Candidate::new_v1();
                    candidate.set_state(CandidateState::Accepted);

                    // Association creation
                    let uuid = Uuid::new_v4();
                    let mut association = Association::new(uuid, JET_VERSION_V1);
                    association.add_candidate(candidate);

                    self.association_uuid.replace(uuid);
                    jet_associations.insert(uuid, association);

                    (StatusCode::OK, uuid)
                }
                2 => {
                    let mut status_code = StatusCode::BAD_REQUEST;

                    if let Some(association) = jet_associations.get_mut(&self.request_msg.association) {
                        if association.version() == JET_VERSION_V2 {
                            if let Some(candidate) = association.get_candidate_mut(self.request_msg.candidate) {
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
        };

        if self.request_msg.version == 1 && status_code == StatusCode::OK {
            self.remove_association_future
                .replace(Box::pin(remove_association(self.jet_associations.clone(), association)));
        }

        // Build response
        let response_msg = JetMessage::JetAcceptRsp(JetAcceptRsp {
            status_code,
            version: self.request_msg.version,
            association,
            instance: self.config.hostname.clone(),
            timeout: ACCEPT_REQUEST_TIMEOUT.as_secs() as u32,
        });
        let mut response_msg_buffer = Vec::with_capacity(512);
        response_msg.write_to(&mut response_msg_buffer)?;

        Ok(response_msg_buffer)
    }

    async fn handle_set_transport(&mut self) -> Result<(), io::Error> {
        let mut jet_associations = self.jet_associations.lock().await;

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
                if let Some(association) = jet_associations.get_mut(&self.request_msg.association) {
                    if association.version() == JET_VERSION_V2 {
                        if let Some(candidate) = association.get_candidate_mut(self.request_msg.candidate) {
                            candidate.set_transport(self.transport.take().expect("Must be set in the constructor"));
                        }
                    }
                }
            }
            _ => {
                // No jet message exist with version different than 1 or 2
                unreachable!()
            }
        }

        if let Some(remove_association_future) = self.remove_association_future.take() {
            tokio::spawn(remove_association_future);
        }

        Ok(())
    }

    async fn accept(mut self) -> Result<(), io::Error> {
        let response_msg = self.handle_create_response().await?;
        let transport = self
            .transport
            .as_mut()
            .expect("Must not be taken upon successful call to handle_set_transport");
        transport.write(&response_msg).await?;
        self.handle_set_transport().await
    }
}

async fn handle_connect_jet_msg(
    mut client_transport: JetTransport,
    request_msg: JetConnectReq,
    jet_associations: JetAssociationsMap,
) -> Result<HandleConnectJetMsgResponse, io::Error> {
    let mut response_msg = Vec::with_capacity(512);
    let mut server_transport = None;
    let mut association_id = None;
    let mut candidate_id = None;
    // Find the server transport
    let mut status_code = StatusCode::BAD_REQUEST;

    let mut jet_associations = jet_associations.lock().await;

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
                    if candidate.transport_type() == TransportType::Tcp && candidate.state() == CandidateState::Accepted
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

    client_transport.write(&response_msg).await?;

    // If server stream found, start the proxy
    match (server_transport.take(), association_id.take(), candidate_id.take()) {
        (Some(server_transport), Some(association_id), Some(candidate_id)) => Ok(HandleConnectJetMsgResponse {
            client_transport,
            server_transport,
            association_id,
            candidate_id,
        }),
        _ => Err(error_other(format!(
            "Invalid association ID received: {}",
            request_msg.association
        ))),
    }
}

pub struct HandleConnectJetMsgResponse {
    pub client_transport: JetTransport,
    pub server_transport: JetTransport,
    pub association_id: Uuid,
    pub candidate_id: Uuid,
}

async fn handle_test_jet_msg(mut transport: JetTransport, request: JetTestReq) -> Result<(), io::Error> {
    let response_msg = JetMessage::JetTestRsp(JetTestRsp {
        status_code: StatusCode::OK,
        version: request.version,
    });
    let mut response_msg_buffer = Vec::with_capacity(512);
    response_msg.write_to(&mut response_msg_buffer)?;

    transport.write(&response_msg_buffer).await?;
    Ok(())
}
