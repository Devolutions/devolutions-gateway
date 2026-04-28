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
use tokio::sync::RwLock;
use uuid::Uuid;

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
    /// Map of agent_id → live Quinn connection, used for opening new streams.
    agent_connections: Arc<RwLock<HashMap<Uuid, quinn::Connection>>>,
    ca_manager: Arc<CaManager>,
}

impl AgentTunnelHandle {
    pub fn registry(&self) -> &AgentRegistry {
        &self.registry
    }

    pub fn ca_manager(&self) -> &CaManager {
        &self.ca_manager
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
            .cloned()
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
    agent_connections: Arc<RwLock<HashMap<Uuid, quinn::Connection>>>,
    ca_manager: Arc<CaManager>,
}

impl AgentTunnelListener {
    pub async fn bind(
        listen_addr: SocketAddr,
        ca_manager: Arc<CaManager>,
        hostname: &str,
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
        info!(listen_addr = %bound_addr, "Agent tunnel QUIC endpoint bound");

        let registry = Arc::new(AgentRegistry::new());
        let agent_connections: Arc<RwLock<HashMap<Uuid, quinn::Connection>>> = Arc::new(RwLock::new(HashMap::new()));

        let handle = AgentTunnelHandle {
            registry: Arc::clone(&registry),
            agent_connections: Arc::clone(&agent_connections),
            ca_manager: Arc::clone(&ca_manager),
        };

        let listener = Self {
            endpoint,
            registry,
            agent_connections,
            ca_manager,
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

                    conn_handles.spawn(
                        run_agent_connection(registry, agent_connections, ca_manager, incoming),
                    );
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
    agent_connections: Arc<RwLock<HashMap<Uuid, quinn::Connection>>>,
    ca_manager: Arc<CaManager>,
    incoming: quinn::Incoming,
) {
    let peer_addr = incoming.remote_address();

    let result: anyhow::Result<()> = async {
        info!(%peer_addr, "Accepting new QUIC connection");

        let conn = incoming.await.context("QUIC handshake failed")?;

        // Extract peer certificate to identify the agent.
        let peer_identity = conn.peer_identity().context("no peer identity after handshake")?;

        let peer_certs = peer_identity
            .downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
            .map_err(|_| anyhow::anyhow!("unexpected peer identity type"))?;

        let peer_cert_der = peer_certs.first().context("no peer certificate in chain")?;

        let agent_id =
            super::cert::extract_agent_id_from_der(peer_cert_der).context("extract agent_id from peer certificate")?;

        let agent_name =
            super::cert::extract_agent_name_from_der(peer_cert_der).unwrap_or_else(|_| format!("agent-{agent_id}"));

        let fingerprint = super::cert::cert_fingerprint_from_der(peer_cert_der);

        info!(%agent_id, %agent_name, %peer_addr, "Agent authenticated via mTLS");

        let peer = Arc::new(AgentPeer::new(agent_id, agent_name.clone(), fingerprint));
        registry.register(Arc::clone(&peer)).await;
        agent_connections.write().await.insert(agent_id, conn.clone());

        // Accept the first bidirectional stream as the control stream.
        let control_result = run_control_loop(&conn, agent_id, &agent_name, &registry, &ca_manager).await;

        // Agent disconnected — clean up.
        info!(%agent_id, "Agent QUIC connection closed");
        registry.unregister(&agent_id).await;
        agent_connections.write().await.remove(&agent_id);

        control_result
    }
    .await;

    if let Err(e) = result {
        warn!(%peer_addr, error = format!("{e:#}"), "Agent connection failed");
    }
}

async fn run_control_loop(
    conn: &quinn::Connection,
    agent_id: Uuid,
    agent_name: &str,
    registry: &AgentRegistry,
    ca_manager: &CaManager,
) -> anyhow::Result<()> {
    let mut ctrl: ControlStream<_, _> = conn.accept_bi().await.context("accept control stream")?.into();

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

                handle_control_message(registry, ca_manager, agent_id, agent_name, &mut ctrl, msg).await;
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
    registry: &AgentRegistry,
    ca_manager: &CaManager,
    agent_id: Uuid,
    agent_name: &str,
    ctrl: &mut ControlStream<S, R>,
    msg: ControlMessage,
) {
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

            if let Some(peer) = registry.get(&agent_id).await {
                peer.update_routes(epoch, subnets, domains);
                peer.touch();
            }
        }
        ControlMessage::Heartbeat {
            timestamp_ms,
            active_stream_count,
            ..
        } => {
            debug!(%agent_id, timestamp_ms, active_stream_count, "Received heartbeat");

            if let Some(peer) = registry.get(&agent_id).await {
                peer.touch();
            }

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

            let result = match ca_manager.sign_agent_csr(agent_id, agent_name, &csr_pem, None) {
                Ok(signed) => {
                    info!(%agent_id, "Certificate renewed successfully");
                    agent_tunnel_proto::CertRenewalResult::Success {
                        client_cert_pem: signed.client_cert_pem,
                        gateway_ca_cert_pem: signed.ca_cert_pem,
                    }
                }
                Err(e) => {
                    warn!(%agent_id, error = %e, "Certificate renewal failed");
                    agent_tunnel_proto::CertRenewalResult::Error { reason: e.to_string() }
                }
            };

            let response = ControlMessage::cert_renewal_response(result);
            if let Err(e) = ctrl.send(&response).await {
                warn!(%agent_id, error = %e, "Failed to send renewal response");
            }
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
