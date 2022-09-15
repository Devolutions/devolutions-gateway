use crate::config::Conf;
use crate::interceptor::plugin_recording::PluginRecordingInspector;
use crate::interceptor::Interceptor;
use crate::jet::association::Association;
use crate::jet::candidate::CandidateState;
use crate::jet::TransportType;
use crate::proxy::Proxy;
use crate::registry::Registry;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::AssociationTokenClaims;
use crate::utils::association::{remove_jet_association, ACCEPT_REQUEST_TIMEOUT};
use crate::utils::create_tls_connector;
use anyhow::Context as _;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use jet_proto::accept::{JetAcceptReq, JetAcceptRsp};
use jet_proto::connect::{JetConnectReq, JetConnectRsp};
use jet_proto::test::{JetTestReq, JetTestRsp};
use jet_proto::{JetMessage, StatusCode, JET_VERSION_V2};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use transport::Transport;
use typed_builder::TypedBuilder;
use uuid::Uuid;

pub type JetAssociationsMap = Mutex<HashMap<Uuid, Association>>;

// FIXME? why "client"? Wouldn't `JetServer` or `JetProxy` be more appropriate naming?

#[derive(TypedBuilder)]
pub struct JetClient {
    conf: Arc<Conf>,
    associations: Arc<JetAssociationsMap>,
    addr: SocketAddr,
    transport: TcpStream,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
}

impl JetClient {
    pub async fn serve(self) -> anyhow::Result<()> {
        let Self {
            conf,
            associations,
            addr,
            mut transport,
            sessions,
            subscriber_tx,
        } = self;

        let msg = read_jet_message(&mut transport).await?;

        match msg {
            JetMessage::JetTestReq(jet_test_req) => handle_test_jet_msg(transport, jet_test_req).await,
            JetMessage::JetAcceptReq(jet_accept_req) => {
                HandleAcceptJetMsg::new(conf, addr, transport, jet_accept_req, associations.clone())
                    .accept()
                    .await
            }
            JetMessage::JetConnectReq(jet_connect_req) => {
                let response = handle_connect_jet_msg(transport, jet_connect_req, associations.clone()).await?;

                let association_id = response.association_id;
                let candidate_id = response.candidate_id;

                let proxy_result = handle_build_proxy(&associations, conf, sessions, subscriber_tx, response).await;

                remove_jet_association(&associations, association_id, Some(candidate_id));

                proxy_result
            }
            JetMessage::JetAcceptRsp(_) => anyhow::bail!("Jet-Accept response can't be handled by the server."),
            JetMessage::JetConnectRsp(_) => anyhow::bail!("Jet-Accept response can't be handled by the server."),
            JetMessage::JetTestRsp(_) => anyhow::bail!("Jet-Test response can't be handled by the server."),
        }
    }
}

async fn handle_build_tls_proxy(
    conf: Arc<Conf>,
    response: HandleConnectJetMsgResponse,
    client_inspector: PluginRecordingInspector,
    server_inspector: PluginRecordingInspector,
    tls_acceptor: &TlsAcceptor,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<()> {
    let client_stream = tls_acceptor.accept(response.client_transport).await?;
    let mut client_transport = Interceptor::new(client_stream);
    client_transport.inspectors.push(Box::new(client_inspector));

    let server_stream = create_tls_connector(response.server_transport).await?;
    let mut server_transport = Interceptor::new(server_stream);
    server_transport.inspectors.push(Box::new(server_inspector));

    let info = SessionInfo::new(
        response.association_id,
        response.association_claims.jet_ap,
        ConnectionModeDetails::Rdv,
    )
    .with_recording_policy(response.association_claims.jet_rec)
    .with_filtering_policy(response.association_claims.jet_flt);

    Proxy::builder()
        .conf(conf)
        .session_info(info)
        .address_a(response.client_addr)
        .transport_a(client_transport)
        .address_b(response.server_addr)
        .transport_b(server_transport)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .build()
        .forward()
        .await
}

async fn handle_build_proxy(
    associations: &JetAssociationsMap,
    conf: Arc<Conf>,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
    response: HandleConnectJetMsgResponse,
) -> anyhow::Result<()> {
    let mut recording_inspector: Option<(PluginRecordingInspector, PluginRecordingInspector)> = None;
    let association_id = response.association_id;
    let mut recording_dir = None;
    let mut file_pattern = None;

    if let Some(association) = associations.lock().get(&association_id) {
        match (association.record_session(), conf.plugins.is_some()) {
            (true, true) => {
                let init_result = PluginRecordingInspector::init(
                    association_id,
                    response.candidate_id,
                    conf.recording_path.as_ref().map(|path| path.as_str()),
                )?;
                recording_dir = init_result.recording_dir;
                file_pattern = Some(init_result.filename_pattern);
                recording_inspector = Some((init_result.client_inspector, init_result.server_inspector));
            }
            (true, false) => anyhow::bail!("can't meet recording policy"),
            (false, _) => {}
        }
    }

    if let Some((client_inspector, server_inspector)) = recording_inspector {
        let tls_acceptor = conf
            .tls
            .as_ref()
            .map(|conf| &conf.acceptor)
            .context("TLS configuration is missing")?;

        let proxy_result = handle_build_tls_proxy(
            conf.clone(),
            response,
            client_inspector,
            server_inspector,
            tls_acceptor,
            sessions,
            subscriber_tx,
        )
        .await;

        if let (Some(dir), Some(pattern)) = (recording_dir, file_pattern) {
            let registry = Registry::new(conf);
            registry.manage_files(association_id.to_string(), pattern, &dir).await;
        };

        proxy_result
    } else {
        let info = SessionInfo::new(
            response.association_id,
            response.association_claims.jet_ap,
            ConnectionModeDetails::Rdv,
        )
        .with_recording_policy(response.association_claims.jet_rec)
        .with_filtering_policy(response.association_claims.jet_flt);

        Proxy::builder()
            .conf(conf)
            .session_info(info)
            .transport_a(response.client_transport)
            .address_a(response.client_addr)
            .transport_b(response.server_transport)
            .address_b(response.server_addr)
            .sessions(sessions)
            .subscriber_tx(subscriber_tx)
            .build()
            .forward()
            .await
    }
}

async fn read_jet_message(transport: &mut TcpStream) -> anyhow::Result<JetMessage> {
    let mut data_received = Vec::new();

    let mut buff = [0u8; 1024];

    while data_received.len() < jet_proto::JET_MSG_HEADER_SIZE as usize {
        let bytes_read = transport.read(&mut buff).await?;

        if bytes_read == 0 {
            anyhow::bail!("Socket closed during Jet header receive, no JetPacket received.",);
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
        anyhow::bail!("Invalid JetPacket - Signature = {}.", signature)
    }

    let msg_len = ReadBytesExt::read_u16::<BigEndian>(&mut slice)?;

    while data_received.len() < msg_len as usize {
        let bytes_read = transport.read(&mut buff).await?;

        if bytes_read == 0 {
            anyhow::bail!("Socket closed during Jet message receive, no JetPacket received.");
        }

        data_received.extend_from_slice(&buff[..bytes_read]);

        debug!("Received {} of {} bytes of jet message", data_received.len(), msg_len);
    }

    let mut slice = data_received.as_slice();
    let jet_message = jet_proto::JetMessage::read_request(&mut slice)?;
    debug!("jet_message received: {:?}", jet_message);

    Ok(jet_message)
}

struct HandleAcceptJetMsg {
    conf: Arc<Conf>,
    transport: Option<(SocketAddr, TcpStream)>,
    request_msg: JetAcceptReq,
    associations: Arc<JetAssociationsMap>,
    remove_association_future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl HandleAcceptJetMsg {
    fn new(
        conf: Arc<Conf>,
        addr: SocketAddr,
        transport: TcpStream,
        msg: JetAcceptReq,
        associations: Arc<JetAssociationsMap>,
    ) -> Self {
        HandleAcceptJetMsg {
            conf,
            transport: Some((addr, transport)),
            request_msg: msg,
            associations,
            remove_association_future: None,
        }
    }

    async fn handle_create_response(&mut self) -> anyhow::Result<Vec<u8>> {
        let (status_code, association_id) = {
            match self.request_msg.version {
                2 => {
                    let mut jet_associations = self.associations.lock();
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
                _ => (StatusCode::BAD_REQUEST, Uuid::nil()),
            }
        };

        // Build response
        let response_msg = JetMessage::JetAcceptRsp(JetAcceptRsp {
            status_code,
            version: self.request_msg.version,
            association: association_id,
            instance: self.conf.hostname.clone(),
            timeout: ACCEPT_REQUEST_TIMEOUT.as_secs() as u32,
        });
        let mut response_msg_buffer = Vec::with_capacity(512);
        response_msg.write_to(&mut response_msg_buffer)?;

        Ok(response_msg_buffer)
    }

    async fn handle_set_transport(&mut self) -> anyhow::Result<()> {
        let mut jet_associations = self.associations.lock();

        if let Some(association) = jet_associations.get_mut(&self.request_msg.association) {
            if association.version() == JET_VERSION_V2 {
                if let Some(candidate) = association.get_candidate_mut(self.request_msg.candidate) {
                    let (addr, stream) = self.transport.take().expect("Must be set in the constructor");
                    candidate.set_transport(Transport::new(stream, addr), None);
                }
            }
        }

        if let Some(remove_association_future) = self.remove_association_future.take() {
            tokio::spawn(remove_association_future);
        }

        Ok(())
    }

    async fn accept(mut self) -> anyhow::Result<()> {
        let response_msg = self.handle_create_response().await?;
        let (_, transport) = self
            .transport
            .as_mut()
            .expect("Must not be taken upon successful call to handle_set_transport");
        transport.write_all(&response_msg).await?;
        self.handle_set_transport().await
    }
}

async fn handle_connect_jet_msg(
    mut client_transport: TcpStream,
    request_msg: JetConnectReq,
    associations: Arc<JetAssociationsMap>,
) -> anyhow::Result<HandleConnectJetMsgResponse> {
    let mut response_msg = Vec::with_capacity(512);
    let mut server_transport = None;
    let mut association_id = None;
    let mut candidate_id = None;
    let mut association_token = None;

    // Find the server transport
    let mut status_code = StatusCode::BAD_REQUEST;

    if let Some(association) = associations.lock().get_mut(&request_msg.association) {
        association_token = Some(association.get_token_claims().clone());

        let candidate = match (association.version(), request_msg.version) {
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

    client_transport.write_all(&response_msg).await?;

    // If server stream found, start the proxy
    match (
        server_transport.take(),
        association_id.take(),
        candidate_id.take(),
        association_token.take(),
    ) {
        (Some((server_transport, None)), Some(association_id), Some(candidate_id), Some(token)) => {
            Ok(HandleConnectJetMsgResponse {
                client_addr: client_transport
                    .peer_addr()
                    .context("client transport should have a peer address")?,
                client_transport,
                server_addr: server_transport.addr,
                server_transport: server_transport
                    .stream
                    .into_tcp()
                    .ok()
                    .context("Server Transport should be a TCP stream in TCP jet rendez-vous mode")?,
                association_id,
                candidate_id,
                association_claims: token,
            })
        }
        _ => anyhow::bail!("Invalid association ID received: {}", request_msg.association),
    }
}

pub struct HandleConnectJetMsgResponse {
    pub client_addr: SocketAddr,
    pub client_transport: TcpStream,
    pub server_addr: SocketAddr,
    pub server_transport: TcpStream,
    pub association_id: Uuid,
    pub candidate_id: Uuid,
    pub association_claims: AssociationTokenClaims,
}

async fn handle_test_jet_msg(transport: impl AsyncWrite, request: JetTestReq) -> anyhow::Result<()> {
    let response_msg = JetMessage::JetTestRsp(JetTestRsp {
        status_code: StatusCode::OK,
        version: request.version,
    });
    let mut response_msg_buffer = Vec::with_capacity(512);
    response_msg.write_to(&mut response_msg_buffer)?;

    tokio::pin!(transport);
    transport.write_all(&response_msg_buffer).await?;

    Ok(())
}
