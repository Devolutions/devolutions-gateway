//! QUIC listener for agent tunnel connections (Quinn-based).
//!
//! Manages a QUIC endpoint using Quinn, accepts connections from agents with mTLS,
//! processes control messages (route advertisements, heartbeats), and
//! creates proxy streams on demand.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{ConnectRequest, ConnectResponse, ControlMessage, ControlStream, SessionStream};
use anyhow::Context as _;
use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use super::authorization::{AcceptedAgent, DynAgentAuthorizationStore, EnrollmentAttempt, EnrollmentOutcome};
use super::cert::CaManager;
use super::registry::{AgentPeer, AgentRegistry};
use super::stream::TunnelStream;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Handle for external code to interact with the running agent tunnel.
///
/// Cloneable and safe to share across tasks.
#[derive(Clone)]
pub struct AgentTunnelHandle {
    registry: Arc<AgentRegistry>,
    agent_connections: Arc<RwLock<HashMap<Uuid, RegisteredAgentConnection>>>,
    ca_manager: Arc<CaManager>,
    authorization_store: DynAgentAuthorizationStore,
    lifecycle: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct RegisteredAgentConnection {
    instance_id: Uuid,
    connection: quinn::Connection,
}

impl AgentTunnelHandle {
    pub fn registry(&self) -> &AgentRegistry {
        &self.registry
    }

    pub fn ca_manager(&self) -> &CaManager {
        &self.ca_manager
    }

    pub async fn enroll(&self, attempt: EnrollmentAttempt) -> anyhow::Result<EnrollmentOutcome> {
        let _lifecycle_guard = self.lifecycle.lock().await;
        self.authorization_store.enroll(attempt).await
    }

    pub async fn accepted_agents(&self) -> anyhow::Result<Vec<AcceptedAgent>> {
        self.authorization_store.list().await
    }

    pub async fn accepted_agent(&self, agent_id: Uuid) -> anyhow::Result<Option<AcceptedAgent>> {
        self.authorization_store.get(agent_id).await
    }

    pub async fn delete_agent(&self, agent_id: Uuid) -> anyhow::Result<Option<AcceptedAgent>> {
        let _lifecycle_guard = self.lifecycle.lock().await;
        let Some(deleted) = self.authorization_store.delete(agent_id).await? else {
            return Ok(None);
        };

        let connection = self
            .agent_connections
            .write()
            .await
            .remove(&agent_id)
            .map(|registered| registered.connection);
        self.registry.unregister(&agent_id).await;
        if let Some(connection) = connection {
            connection.close(0u32.into(), b"agent-deleted");
        }

        Ok(Some(deleted))
    }

    /// Open a proxy stream through a connected agent.
    // TODO: Emit TrafficEvent for connections routed through the agent tunnel.
    pub async fn connect_via_agent(
        &self,
        agent_id: Uuid,
        session_id: Uuid,
        target: &str,
    ) -> anyhow::Result<TunnelStream> {
        let conn = self
            .agent_connections
            .read()
            .await
            .get(&agent_id)
            .map(|registered| registered.connection.clone())
            .ok_or_else(|| anyhow::anyhow!("agent {} not connected", agent_id))?;

        let mut session: SessionStream<_, _> = conn
            .open_bi()
            .await
            .context("open bidirectional stream to agent")?
            .into();

        // Send ConnectRequest.
        let connect_msg = ConnectRequest::tcp(session_id, target.to_owned());
        session
            .send_request(&connect_msg)
            .await
            .context("send ConnectRequest")?;

        // Read ConnectResponse (with timeout to prevent stalled peers).
        let response = tokio::time::timeout(Duration::from_secs(30), session.recv_response())
            .await
            .map_err(|_| anyhow::anyhow!("session handshake timeout (30s)"))?
            .context("recv ConnectResponse")?;

        agent_tunnel_proto::validate_protocol_version(response.protocol_version())
            .map_err(|e| anyhow::anyhow!("ConnectResponse: {e}"))?;

        if let ConnectResponse::Error { reason, .. } = &response {
            anyhow::bail!("agent refused connection: {reason}");
        }

        info!(
            %agent_id,
            %session_id,
            %target,
            "Proxy stream established via agent tunnel"
        );

        let (send, recv) = session.into_inner();
        Ok(TunnelStream { send, recv })
    }
}

// ---------------------------------------------------------------------------
// Listener task
// ---------------------------------------------------------------------------

pub struct AgentTunnelListener {
    endpoint: quinn::Endpoint,
    registry: Arc<AgentRegistry>,
    agent_connections: Arc<RwLock<HashMap<Uuid, RegisteredAgentConnection>>>,
    ca_manager: Arc<CaManager>,
    authorization_store: DynAgentAuthorizationStore,
    lifecycle: Arc<Mutex<()>>,
}

impl AgentTunnelListener {
    pub async fn bind(
        listen_addr: SocketAddr,
        ca_manager: Arc<CaManager>,
        hostname: &str,
        authorization_store: DynAgentAuthorizationStore,
    ) -> anyhow::Result<(Self, AgentTunnelHandle)> {
        let tls_config = ca_manager
            .build_server_tls_config(hostname)
            .context("build server TLS config")?;

        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_config))
            .context("create QUIC server config from TLS config")?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        // Configure transport parameters.
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(
                Duration::from_secs(120)
                    .try_into()
                    .expect("120s should be a valid idle timeout"),
            ))
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .max_concurrent_bidi_streams(100u32.into());

        server_config.transport_config(Arc::new(transport));

        let endpoint = bind_dual_stack_endpoint(server_config, listen_addr)
            .with_context(|| format!("bind QUIC endpoint on {listen_addr}"))?;

        let bound_addr = endpoint.local_addr().unwrap_or(listen_addr);
        info!(
            configured_addr = %listen_addr,
            bound_addr = %bound_addr,
            "Agent tunnel QUIC endpoint bound"
        );

        let registry = Arc::new(AgentRegistry::new());
        let agent_connections = Arc::new(RwLock::new(HashMap::new()));
        let lifecycle = Arc::new(Mutex::new(()));

        let handle = AgentTunnelHandle {
            registry: Arc::clone(&registry),
            agent_connections: Arc::clone(&agent_connections),
            ca_manager: Arc::clone(&ca_manager),
            authorization_store: Arc::clone(&authorization_store),
            lifecycle: Arc::clone(&lifecycle),
        };

        let listener = Self {
            endpoint,
            registry,
            agent_connections,
            ca_manager,
            authorization_store,
            lifecycle,
        };

        Ok((listener, handle))
    }

    /// Returns the local address the QUIC endpoint is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr().expect("endpoint has local addr")
    }
}

#[async_trait]
impl devolutions_gateway_task::Task for AgentTunnelListener {
    type Output = anyhow::Result<()>;
    const NAME: &'static str = "agent-tunnel-listener";

    async fn run(self, mut shutdown_signal: devolutions_gateway_task::ShutdownSignal) -> anyhow::Result<()> {
        let local_addr = self.endpoint.local_addr()?;
        info!(%local_addr, "Agent tunnel listener started");

        let mut conn_handles = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                biased;

                _ = shutdown_signal.wait() => {
                    info!("Agent tunnel listener shutting down");
                    self.endpoint.close(0u32.into(), b"shutdown");
                    break;
                }

                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        info!("QUIC endpoint closed");
                        break;
                    };

                    let registry = Arc::clone(&self.registry);
                    let agent_connections = Arc::clone(&self.agent_connections);
                    let ca_manager = Arc::clone(&self.ca_manager);
                    let authorization_store = Arc::clone(&self.authorization_store);
                    let lifecycle = Arc::clone(&self.lifecycle);

                    conn_handles.spawn(run_agent_connection(
                        registry,
                        agent_connections,
                        ca_manager,
                        authorization_store,
                        lifecycle,
                        incoming,
                    ));
                }

                // Reap completed connection tasks to prevent unbounded growth.
                Some(_) = conn_handles.join_next() => {}
            }
        }

        conn_handles.shutdown().await;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async fn run_agent_connection(
    registry: Arc<AgentRegistry>,
    agent_connections: Arc<RwLock<HashMap<Uuid, RegisteredAgentConnection>>>,
    ca_manager: Arc<CaManager>,
    authorization_store: DynAgentAuthorizationStore,
    lifecycle: Arc<Mutex<()>>,
    incoming: quinn::Incoming,
) {
    let peer_addr = incoming.remote_address();

    let result: anyhow::Result<()> = async {
        info!(%peer_addr, "Accepting new QUIC connection");

        let conn = incoming.await.context("QUIC handshake failed")?;

        // Extract peer certificate to identify the agent.
        let peer_identity = conn.peer_identity().context("no peer identity after handshake")?;

        let peer_certs = peer_identity
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .map_err(|_| anyhow::anyhow!("unexpected peer identity type"))?;

        let peer_cert_der = peer_certs.first().context("no peer certificate in chain")?;

        let agent_id =
            super::cert::extract_agent_id_from_der(peer_cert_der).context("extract agent_id from peer certificate")?;
        let client_spki_sha256 = super::cert::spki_sha256_digest_from_der(peer_cert_der)
            .context("extract SPKI SHA-256 from peer certificate")?;
        let fingerprint = super::cert::cert_fingerprint_from_der(peer_cert_der);
        let instance_id = Uuid::new_v4();
        let lifecycle_guard = lifecycle.lock().await;
        let accepted = match authorization_store.authorize(agent_id, client_spki_sha256).await {
            Ok(Some(accepted)) => accepted,
            Ok(None) => {
                warn!(%agent_id, %peer_addr, "Rejecting Agent connection: credential is not accepted");
                conn.close(0u32.into(), b"agent-not-accepted");
                return Ok(());
            }
            Err(error) => {
                error!(%agent_id, %peer_addr, %error, "Failed to query Agent authorization");
                conn.close(0u32.into(), b"authorization-unavailable");
                return Ok(());
            }
        };
        let agent_name = accepted.name;

        info!(%agent_id, %agent_name, %peer_addr, "Agent authenticated via mTLS");

        let peer = Arc::new(AgentPeer::new(agent_id, agent_name.clone(), fingerprint));
        registry.register(Arc::clone(&peer)).await;
        let previous = agent_connections.write().await.insert(
            agent_id,
            RegisteredAgentConnection {
                instance_id,
                connection: conn.clone(),
            },
        );
        if let Some(previous) = previous {
            previous.connection.close(0u32.into(), b"connection-superseded");
        }
        drop(lifecycle_guard);

        // Accept the first bidirectional stream as the control stream.
        let control_result = run_control_loop(&conn, &peer, client_spki_sha256, &ca_manager).await;

        // Agent disconnected — clean up.
        info!(%agent_id, "Agent QUIC connection closed");
        let _lifecycle_guard = lifecycle.lock().await;
        let should_unregister = {
            let mut connections = agent_connections.write().await;
            if connections
                .get(&agent_id)
                .is_some_and(|registered| registered.instance_id == instance_id)
            {
                connections.remove(&agent_id);
                true
            } else {
                false
            }
        };
        if should_unregister {
            registry.unregister(&agent_id).await;
        }

        control_result
    }
    .await;

    if let Err(e) = result {
        warn!(%peer_addr, error = format!("{e:#}"), "Agent connection failed");
    }
}

async fn run_control_loop(
    conn: &quinn::Connection,
    peer: &AgentPeer,
    client_spki_sha256: [u8; 32],
    ca_manager: &CaManager,
) -> anyhow::Result<()> {
    let mut ctrl: ControlStream<_, _> = conn.accept_bi().await.context("accept control stream")?.into();
    let agent_id = peer.agent_id;

    info!(%agent_id, "Control stream accepted");

    loop {
        tokio::select! {
            // Read control messages from the agent.
            msg_result = ctrl.recv() => {
                let msg = match msg_result {
                    Ok(msg) => msg,
                    Err(agent_tunnel_proto::ProtoError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        debug!(%agent_id, "Control stream EOF");
                        break;
                    }
                    Err(e) => {
                        warn!(%agent_id, error = %e, "Control stream decode error");
                        break;
                    }
                };

                handle_control_message(
                    peer,
                    ca_manager,
                    client_spki_sha256,
                    &mut ctrl,
                    msg,
                )
                .await;
            }

            // Detect connection close.
            reason = conn.closed() => {
                debug!(%agent_id, ?reason, "QUIC connection closed");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_control_message<S: tokio::io::AsyncWrite + Unpin, R: tokio::io::AsyncRead + Unpin>(
    peer: &AgentPeer,
    ca_manager: &CaManager,
    client_spki_sha256: [u8; 32],
    ctrl: &mut ControlStream<S, R>,
    msg: ControlMessage,
) {
    let agent_id = peer.agent_id;
    let agent_name = &peer.name;
    let protocol_version = msg.protocol_version();
    if agent_tunnel_proto::validate_protocol_version(protocol_version)
        .inspect_err(|e| warn!(%agent_id, %protocol_version, %e, "Ignoring control message: unsupported version"))
        .is_err()
    {
        return;
    }

    match msg {
        ControlMessage::RouteAdvertise {
            epoch,
            subnets,
            domains,
            ..
        } => {
            info!(
                %agent_id,
                epoch,
                subnet_count = subnets.len(),
                domain_count = domains.len(),
                "Received route advertisement"
            );

            peer.update_routes(epoch, subnets, domains);
            peer.touch();
        }
        ControlMessage::Heartbeat {
            timestamp_ms,
            active_stream_count,
            ..
        } => {
            debug!(%agent_id, timestamp_ms, active_stream_count, "Received heartbeat");

            peer.touch();

            let ack = ControlMessage::heartbeat_ack(timestamp_ms);

            let _ = ctrl.send(&ack).await.inspect_err(|e| {
                warn!(%agent_id, error = %e, "Failed to send heartbeat ack");
            });
        }
        ControlMessage::HeartbeatAck { .. } => {
            debug!(%agent_id, "Unexpected HeartbeatAck from agent");
        }
        ControlMessage::CertRenewalRequest { csr_pem, .. } => {
            info!(%agent_id, "Agent requested certificate renewal");

            // Reuse the agent_id and agent_name authenticated by mTLS — never
            // trust the CSR's subject. The CA only re-signs the public key the
            // agent put in its CSR; identity stays whatever the existing cert
            // already proved during the handshake.
            let renewal = ca_manager
                .sign_agent_csr(agent_id, agent_name, &csr_pem, None)
                .and_then(|signed| {
                    let renewed_spki_sha256 = super::cert::spki_sha256_digest_from_pem(&signed.client_cert_pem)?;
                    anyhow::ensure!(
                        renewed_spki_sha256 == client_spki_sha256,
                        "certificate renewal key rotation is not allowed"
                    );
                    Ok(signed)
                });
            let result = match renewal {
                Ok(signed) => {
                    info!(%agent_id, %agent_name, "Renewed agent certificate");
                    agent_tunnel_proto::CertRenewalResult::Success {
                        client_cert_pem: signed.client_cert_pem,
                        gateway_ca_cert_pem: signed.ca_cert_pem,
                    }
                }
                Err(error) => {
                    warn!(%agent_id, error = %format!("{error:#}"), "Certificate renewal failed");
                    agent_tunnel_proto::CertRenewalResult::Error {
                        reason: format!("{error:#}"),
                    }
                }
            };

            let response = ControlMessage::cert_renewal_response(result);
            let _ = ctrl.send(&response).await.inspect_err(|e| {
                warn!(%agent_id, error = %e, "Failed to send CertRenewalResponse");
            });
        }
        ControlMessage::CertRenewalResponse { .. } => {
            debug!(%agent_id, "Unexpected CertRenewalResponse from agent");
        }
    }
}

/// Bind a QUIC endpoint, preferring a dual-stack IPv6 socket so the listener
/// accepts agents whose DNS resolution returns either IPv4 or IPv6.
///
/// `quinn::Endpoint::server` would otherwise honor the OS default for
/// `IPV6_V6ONLY`, which is `0` (dual-stack) on Windows but `1` (v6-only) on
/// Linux per RFC 3493. We explicitly clear the flag with `socket2`, then hand
/// the socket to `quinn::Endpoint::new`. If the v6 bind fails entirely
/// (e.g. IPv6 disabled on the host), we fall back to plain IPv4.
fn bind_dual_stack_endpoint(
    server_config: quinn::ServerConfig,
    listen_addr: SocketAddr,
) -> anyhow::Result<quinn::Endpoint> {
    if !listen_addr.is_ipv6() {
        return quinn::Endpoint::server(server_config, listen_addr).map_err(Into::into);
    }

    let socket = match build_dual_stack_v6_socket(listen_addr) {
        Ok(socket) => socket,
        Err(error) if listen_addr.ip().is_unspecified() => {
            let v4_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, listen_addr.port()));
            warn!(%error, fallback = %v4_addr, "IPv6 dual-stack bind failed; falling back to IPv4");
            return quinn::Endpoint::server(server_config, v4_addr).map_err(Into::into);
        }
        Err(error) => return Err(error),
    };

    let runtime = quinn::default_runtime().context("no quinn-compatible async runtime found")?;
    quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_config), socket, runtime).map_err(Into::into)
}

fn build_dual_stack_v6_socket(listen_addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("create IPv6 UDP socket")?;

    if let Err(error) = socket.set_only_v6(false) {
        warn!(%error, "set_only_v6(false) failed; listener may be IPv6-only");
    }

    socket.set_nonblocking(true).context("set socket non-blocking")?;
    socket.bind(&listen_addr.into()).context("bind v6 UDP socket")?;

    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use ipnetwork::Ipv4Network;

    use super::*;

    #[tokio::test]
    async fn control_message_updates_only_its_connection_peer() {
        let agent_id = Uuid::new_v4();
        let old_peer = AgentPeer::new(agent_id, String::from("old"), String::from("old-cert"));
        let replacement_peer = AgentPeer::new(agent_id, String::from("replacement"), String::from("replacement-cert"));
        let temp_dir = std::env::temp_dir().join(format!("dgw-peer-isolation-test-{}", Uuid::new_v4()));
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("temporary path is UTF-8");
        let ca_manager = CaManager::load_or_generate(&data_dir).expect("generate test CA");
        let mut control = ControlStream::new(tokio::io::sink(), tokio::io::empty());
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("parse test subnet");

        handle_control_message(
            &old_peer,
            &ca_manager,
            [0; 32],
            &mut control,
            ControlMessage::route_advertise(9, vec![subnet], Vec::new()),
        )
        .await;

        assert_eq!(old_peer.route_state().epoch, 9);
        assert_eq!(replacement_peer.route_state().epoch, 0);
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
