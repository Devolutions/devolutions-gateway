//! QUIC listener for agent tunnel connections (Quinn-based).
//!
//! Manages a QUIC endpoint using Quinn, accepts connections from agents with mTLS,
//! processes control messages (route advertisements, heartbeats), and
//! creates proxy streams on demand.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{ConnectMessage, ConnectResponse, ControlMessage};
use anyhow::Context as _;
use async_trait::async_trait;
use dashmap::DashMap;
use uuid::Uuid;

use super::cert::CaManager;
use super::enrollment_store::EnrollmentTokenStore;
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
    agent_connections: Arc<DashMap<Uuid, quinn::Connection>>,
    ca_manager: Arc<CaManager>,
    enrollment_token_store: Arc<EnrollmentTokenStore>,
}

impl AgentTunnelHandle {
    pub fn registry(&self) -> &AgentRegistry {
        &self.registry
    }

    pub fn ca_manager(&self) -> &CaManager {
        &self.ca_manager
    }

    pub fn enrollment_token_store(&self) -> &EnrollmentTokenStore {
        &self.enrollment_token_store
    }

    /// Open a proxy stream through a connected agent.
    pub async fn connect_via_agent(
        &self,
        agent_id: Uuid,
        session_id: Uuid,
        target: &str,
    ) -> anyhow::Result<TunnelStream> {
        let conn = self
            .agent_connections
            .get(&agent_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow::anyhow!("agent {} not connected", agent_id))?;

        let (mut send, mut recv) = conn.open_bi().await.context("open bidirectional stream to agent")?;

        // Send ConnectMessage.
        let connect_msg = ConnectMessage::new(session_id, target.to_owned());
        connect_msg
            .encode(&mut send)
            .await
            .map_err(|e| anyhow::anyhow!("encode ConnectMessage: {e}"))?;

        // Read ConnectResponse.
        let response = ConnectResponse::decode(&mut recv)
            .await
            .map_err(|e| anyhow::anyhow!("decode ConnectResponse: {e}"))?;

        if !response.is_success() {
            let reason = match &response {
                ConnectResponse::Error { reason, .. } => reason.clone(),
                _ => "unknown".to_owned(),
            };
            anyhow::bail!("agent refused connection: {reason}");
        }

        info!(
            %agent_id,
            %session_id,
            %target,
            "Proxy stream established via agent tunnel"
        );

        Ok(TunnelStream { send, recv })
    }
}

// ---------------------------------------------------------------------------
// Listener task
// ---------------------------------------------------------------------------

pub struct AgentTunnelListener {
    endpoint: quinn::Endpoint,
    registry: Arc<AgentRegistry>,
    agent_connections: Arc<DashMap<Uuid, quinn::Connection>>,
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
        transport.max_idle_timeout(Some(
            Duration::from_secs(120)
                .try_into()
                .expect("120s should be a valid idle timeout"),
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        transport.max_concurrent_bidi_streams(100u32.into());
        server_config.transport_config(Arc::new(transport));

        let endpoint = quinn::Endpoint::server(server_config, listen_addr)
            .with_context(|| format!("bind QUIC endpoint on {listen_addr}"))?;

        info!(%listen_addr, "Agent tunnel QUIC endpoint bound");

        let registry = Arc::new(AgentRegistry::new());
        let agent_connections: Arc<DashMap<Uuid, quinn::Connection>> = Arc::new(DashMap::new());
        let enrollment_token_store = Arc::new(EnrollmentTokenStore::new());

        let handle = AgentTunnelHandle {
            registry: Arc::clone(&registry),
            agent_connections: Arc::clone(&agent_connections),
            ca_manager,
            enrollment_token_store,
        };

        let listener = Self {
            endpoint,
            registry,
            agent_connections,
        };

        Ok((listener, handle))
    }
}

#[async_trait]
impl devolutions_gateway_task::Task for AgentTunnelListener {
    type Output = anyhow::Result<()>;
    const NAME: &'static str = "agent-tunnel-listener";

    async fn run(self, mut shutdown_signal: devolutions_gateway_task::ShutdownSignal) -> anyhow::Result<()> {
        let local_addr = self.endpoint.local_addr()?;
        info!(%local_addr, "Agent tunnel listener started");

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

                    tokio::spawn(async move {
                        if let Err(e) = handle_agent_connection(registry, agent_connections, incoming).await {
                            warn!(error = format!("{e:#}"), "Agent connection handler failed");
                        }
                    });
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async fn handle_agent_connection(
    registry: Arc<AgentRegistry>,
    agent_connections: Arc<DashMap<Uuid, quinn::Connection>>,
    incoming: quinn::Incoming,
) -> anyhow::Result<()> {
    let peer_addr = incoming.remote_address();
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

    let peer = Arc::new(AgentPeer::new(agent_id, agent_name, fingerprint));
    registry.register(Arc::clone(&peer));
    agent_connections.insert(agent_id, conn.clone());

    // Accept the first bidirectional stream as the control stream.
    let control_result = handle_control_stream(&conn, agent_id, &registry).await;

    // Agent disconnected — clean up.
    info!(%agent_id, "Agent QUIC connection closed");
    registry.unregister(&agent_id);
    agent_connections.remove(&agent_id);

    control_result
}

async fn handle_control_stream(
    conn: &quinn::Connection,
    agent_id: Uuid,
    registry: &AgentRegistry,
) -> anyhow::Result<()> {
    let (mut control_send, mut control_recv) = conn.accept_bi().await.context("accept control stream")?;

    info!(%agent_id, "Control stream accepted");

    loop {
        tokio::select! {
            // Read control messages from the agent.
            msg_result = ControlMessage::decode(&mut control_recv) => {
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

                handle_control_message(registry, agent_id, &mut control_send, msg).await;
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

async fn handle_control_message(
    registry: &AgentRegistry,
    agent_id: Uuid,
    control_send: &mut quinn::SendStream,
    msg: ControlMessage,
) {
    match msg {
        ControlMessage::RouteAdvertise {
            protocol_version,
            epoch,
            subnets,
            domains,
            ..
        } => {
            if let Err(e) = agent_tunnel_proto::validate_protocol_version(protocol_version) {
                warn!(%agent_id, %protocol_version, %e, "Rejecting route advertisement: unsupported protocol version");
                return;
            }
            info!(
                %agent_id,
                epoch,
                subnet_count = subnets.len(),
                domain_count = domains.len(),
                "Received route advertisement"
            );
            if let Some(peer) = registry.get(&agent_id) {
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
            if let Some(peer) = registry.get(&agent_id) {
                peer.touch();
            }

            let ack = ControlMessage::heartbeat_ack(timestamp_ms);
            if let Err(e) = ack.encode(control_send).await {
                warn!(%agent_id, error = %e, "Failed to send heartbeat ack");
            }
        }
        ControlMessage::HeartbeatAck { .. } => {
            debug!(%agent_id, "Unexpected HeartbeatAck from agent");
        }
    }
}
