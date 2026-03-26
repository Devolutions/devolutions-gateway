//! QUIC listener for agent tunnel connections.
//!
//! Manages a UDP socket, accepts QUIC connections from agents with mTLS,
//! processes control messages (route advertisements, heartbeats), and
//! creates proxy streams on demand.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agent_tunnel_proto::{ConnectMessage, ConnectResponse, ControlMessage};
use anyhow::{Context as _, Result};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::cert::CaManager;
use super::enrollment_store::EnrollmentTokenStore;
use super::registry::{AgentPeer, AgentRegistry};
use super::stream::{QuicStream, StreamWrite};

/// Maximum UDP payload size for QUIC datagrams.
const MAX_DATAGRAM_SIZE: usize = 1350;

/// Channel buffer for per-stream reads from the event loop.
const STREAM_READ_BUFFER: usize = 64;

/// ALPN protocol identifier for the agent tunnel.
const ALPN_PROTOCOL: &[u8] = b"devolutions-agent-tunnel";

// --- Public API ---

/// Handle for external code to interact with the running agent tunnel.
///
/// Cloneable and safe to share across tasks.
#[derive(Clone)]
pub struct AgentTunnelHandle {
    registry: Arc<AgentRegistry>,
    request_tx: mpsc::Sender<ProxyRequest>,
    ca_manager: Arc<CaManager>,
    enrollment_token_store: Arc<EnrollmentTokenStore>,
}

impl AgentTunnelHandle {
    /// Returns a reference to the agent registry.
    pub fn registry(&self) -> &AgentRegistry {
        &self.registry
    }

    /// Returns a reference to the CA manager (for enrollment).
    pub fn ca_manager(&self) -> &CaManager {
        &self.ca_manager
    }

    /// Returns a reference to the enrollment token store.
    pub fn enrollment_token_store(&self) -> &EnrollmentTokenStore {
        &self.enrollment_token_store
    }

    /// Open a proxy stream through a connected agent.
    ///
    /// Sends a `ConnectMessage` to the agent and waits for a `ConnectResponse`.
    /// On success, returns a `QuicStream` that can be used for bidirectional I/O.
    pub async fn connect_via_agent(&self, agent_id: Uuid, session_id: Uuid, target: &str) -> Result<QuicStream> {
        let (response_tx, response_rx) = oneshot::channel();

        self.request_tx
            .send(ProxyRequest {
                agent_id,
                session_id,
                target: target.to_owned(),
                response_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("agent tunnel listener shut down"))?;

        response_rx
            .await
            .map_err(|_| anyhow::anyhow!("agent tunnel listener dropped request"))?
    }
}

/// The main agent tunnel listener task.
///
/// Runs a QUIC server on a UDP socket, accepting mTLS-authenticated agent connections.
pub struct AgentTunnelListener {
    socket: UdpSocket,
    quiche_config: quiche::Config,
    registry: Arc<AgentRegistry>,
    request_rx: mpsc::Receiver<ProxyRequest>,
    write_rx: mpsc::UnboundedReceiver<StreamWrite>,
    write_tx: mpsc::UnboundedSender<StreamWrite>,
    next_internal_id: AtomicU64,
}

impl AgentTunnelListener {
    /// Bind the UDP socket and prepare the QUIC configuration.
    ///
    /// Returns the listener (to be registered as a task) and a handle for external interaction.
    pub async fn bind(
        listen_addr: SocketAddr,
        ca_manager: Arc<CaManager>,
        hostname: &str,
    ) -> Result<(Self, AgentTunnelHandle)> {
        let socket = UdpSocket::bind(listen_addr)
            .await
            .with_context(|| format!("bind UDP socket on {listen_addr}"))?;

        info!(%listen_addr, "Agent tunnel UDP socket bound");

        // Server cert signed by our CA (so agents can verify us).
        let (server_cert_path, server_key_path) = ca_manager
            .ensure_server_cert(hostname)
            .context("ensure server certificate")?;

        // Configure QUIC with mTLS.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).context("create quiche config")?;

        config
            .load_cert_chain_from_pem_file(server_cert_path.as_str())
            .context("load server cert chain")?;
        config
            .load_priv_key_from_pem_file(server_key_path.as_str())
            .context("load server private key")?;
        config
            .load_verify_locations_from_file(ca_manager.ca_cert_path().as_str())
            .context("load CA cert for client verification")?;
        config.verify_peer(true);

        config.set_application_protos(&[ALPN_PROTOCOL]).context("set ALPN")?;

        // QUIC transport settings.
        config.set_max_idle_timeout(120_000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_disable_active_migration(true);

        let registry = Arc::new(AgentRegistry::new());
        let (request_tx, request_rx) = mpsc::channel(32);
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let enrollment_token_store = Arc::new(EnrollmentTokenStore::new());

        let handle = AgentTunnelHandle {
            registry: Arc::clone(&registry),
            request_tx,
            ca_manager,
            enrollment_token_store,
        };

        let listener = Self {
            socket,
            quiche_config: config,
            registry,
            request_rx,
            write_rx,
            write_tx,
            next_internal_id: AtomicU64::new(1),
        };

        Ok((listener, handle))
    }
}

#[async_trait]
impl devolutions_gateway_task::Task for AgentTunnelListener {
    type Output = Result<()>;

    const NAME: &'static str = "agent-tunnel-listener";

    async fn run(mut self, mut shutdown_signal: devolutions_gateway_task::ShutdownSignal) -> Result<()> {
        let mut connections: HashMap<u64, ManagedConnection> = HashMap::new();
        // Maps quiche connection IDs (dcid bytes) → internal id.
        let mut cid_map: HashMap<Vec<u8>, u64> = HashMap::new();

        let mut recv_buf = vec![0u8; 65535];
        let mut send_buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let local_addr = self.socket.local_addr()?;

        info!(%local_addr, "Agent tunnel listener started");

        loop {
            let timeout = connections
                .values()
                .filter_map(|mc| mc.quiche_conn.timeout())
                .min()
                .unwrap_or(Duration::from_secs(1));

            tokio::select! {
                biased;

                _ = shutdown_signal.wait() => {
                    info!("Agent tunnel listener shutting down");
                    break;
                }

                result = self.socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            handle_udp_recv(
                                &mut self.quiche_config,
                                &self.next_internal_id,
                                &mut connections,
                                &mut cid_map,
                                &self.registry,
                                &mut recv_buf[..len],
                                peer_addr,
                                local_addr,
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "UDP recv error");
                        }
                    }
                }

                Some(request) = self.request_rx.recv() => {
                    handle_proxy_request(
                        &mut connections,
                        &self.write_tx,
                        request,
                    );
                }

                Some(write) = self.write_rx.recv() => {
                    apply_stream_write(&mut connections, write);
                    // Drain additional pending writes.
                    while let Ok(w) = self.write_rx.try_recv() {
                        apply_stream_write(&mut connections, w);
                    }
                }

                _ = tokio::time::sleep(timeout) => {
                    for mc in connections.values_mut() {
                        mc.quiche_conn.on_timeout();
                    }
                }
            }

            // After every event: flush outgoing data and clean up closed connections.
            flush_all(&mut connections, &self.socket, &mut send_buf).await;
            reap_closed(&mut connections, &mut cid_map, &self.registry);
        }

        Ok(())
    }
}

// --- Internal types ---

struct ProxyRequest {
    agent_id: Uuid,
    session_id: Uuid,
    target: String,
    response_tx: oneshot::Sender<Result<QuicStream>>,
}

struct ManagedConnection {
    quiche_conn: quiche::Connection,
    internal_id: u64,
    agent_id: Option<Uuid>,
    peer_addr: SocketAddr,
    /// Active streams whose data is forwarded to a `QuicStream`.
    stream_readers: HashMap<u64, mpsc::UnboundedSender<io::Result<Vec<u8>>>>,
    /// Streams in the proxy handshake phase (waiting for `ConnectResponse`).
    pending_proxies: HashMap<u64, PendingProxy>,
    /// Buffered stream writes waiting for additional QUIC send capacity.
    pending_stream_writes: HashMap<u64, PendingStreamWrite>,
    /// Buffer for partial control-stream reads.
    control_buf: Vec<u8>,
    /// Counter for server-initiated bidirectional stream IDs (1, 5, 9, …).
    next_server_bidi: u64,
}

struct PendingProxy {
    response_tx: oneshot::Sender<Result<QuicStream>>,
    buffer: Vec<u8>,
    write_tx: mpsc::UnboundedSender<StreamWrite>,
    conn_internal_id: u64,
}

#[derive(Default)]
struct PendingStreamWrite {
    chunks: VecDeque<Vec<u8>>,
    finish_after_write: bool,
}

// --- Event loop helpers ---

#[expect(
    clippy::too_many_arguments,
    reason = "QUIC receive path needs shared mutable state and packet metadata in one place"
)]
fn handle_udp_recv(
    config: &mut quiche::Config,
    id_gen: &AtomicU64,
    connections: &mut HashMap<u64, ManagedConnection>,
    cid_map: &mut HashMap<Vec<u8>, u64>,
    registry: &AgentRegistry,
    buf: &mut [u8],
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
) {
    let hdr = match quiche::Header::from_slice(buf, quiche::MAX_CONN_ID_LEN) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "Failed to parse QUIC header");
            return;
        }
    };

    let dcid_vec = hdr.dcid.as_ref().to_vec();

    // Look up existing connection.
    let internal_id = cid_map.get(&dcid_vec).copied();
    let internal_id = if let Some(id) = internal_id {
        id
    } else {
        // Only accept Initial packets for new connections.
        if hdr.ty != quiche::Type::Initial {
            debug!("Ignoring non-Initial packet for unknown connection");
            return;
        }

        let new_id = id_gen.fetch_add(1, Ordering::Relaxed);

        // Derive a server source connection ID.
        let mut scid_bytes = vec![0u8; quiche::MAX_CONN_ID_LEN];
        scid_bytes[..8].copy_from_slice(&new_id.to_be_bytes());
        let scid = quiche::ConnectionId::from_vec(scid_bytes.clone());

        let conn = match quiche::accept(&scid, None, local_addr, peer_addr, config) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, %peer_addr, "Failed to accept QUIC connection");
                return;
            }
        };

        info!(%peer_addr, internal_id = new_id, "Accepted new QUIC connection");

        let mc = ManagedConnection {
            quiche_conn: conn,
            internal_id: new_id,
            agent_id: None,
            peer_addr,
            stream_readers: HashMap::new(),
            pending_proxies: HashMap::new(),
            pending_stream_writes: HashMap::new(),
            control_buf: Vec::new(),
            next_server_bidi: 1, // First server-initiated bidi stream ID.
        };

        connections.insert(new_id, mc);
        cid_map.insert(dcid_vec, new_id);
        cid_map.insert(scid_bytes, new_id);

        new_id
    };

    let mc = match connections.get_mut(&internal_id) {
        Some(mc) => mc,
        None => return,
    };

    let recv_info = quiche::RecvInfo {
        from: peer_addr,
        to: local_addr,
    };

    if let Err(e) = mc.quiche_conn.recv(buf, recv_info) {
        debug!(error = %e, "QUIC recv error");
        return;
    }

    // Detect handshake completion.
    if mc.quiche_conn.is_established() && mc.agent_id.is_none() {
        handle_handshake_complete(mc, registry);
    }

    // Process readable streams.
    if mc.quiche_conn.is_established() {
        let readable: Vec<u64> = mc.quiche_conn.readable().collect();
        for stream_id in readable {
            process_readable_stream(mc, stream_id, registry);
        }

        flush_pending_stream_writes(mc);
    }
}

fn handle_handshake_complete(mc: &mut ManagedConnection, registry: &AgentRegistry) {
    let peer_cert_der = match mc.quiche_conn.peer_cert() {
        Some(cert) => cert.to_vec(),
        None => {
            warn!(peer_addr = %mc.peer_addr, "No peer certificate after handshake");
            mc.quiche_conn.close(false, 0x1, b"no client cert").ok();
            return;
        }
    };

    match super::cert::extract_agent_id_from_der(&peer_cert_der) {
        Ok(agent_id) => {
            info!(%agent_id, peer_addr = %mc.peer_addr, "Agent authenticated via mTLS");
            mc.agent_id = Some(agent_id);

            let fingerprint = super::cert::cert_fingerprint_from_der(&peer_cert_der);
            let peer = Arc::new(AgentPeer::new(agent_id, format!("agent-{agent_id}"), fingerprint));
            registry.register(peer);
        }
        Err(e) => {
            warn!(error = %e, peer_addr = %mc.peer_addr, "Failed to extract agent_id from certificate");
            mc.quiche_conn.close(false, 0x1, b"invalid cert").ok();
        }
    }
}

fn process_readable_stream(mc: &mut ManagedConnection, stream_id: u64, registry: &AgentRegistry) {
    let mut buf = vec![0u8; 65535];

    let (read, fin) = match mc.quiche_conn.stream_recv(stream_id, &mut buf) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, stream_id, "stream_recv error");
            return;
        }
    };

    let data = &buf[..read];

    // --- Control stream (client-initiated bidi stream 0) ---
    if stream_id == 0 {
        process_control_data(mc, data, registry);
        return;
    }

    // --- Pending proxy handshake ---
    if let Some(pending) = mc.pending_proxies.get_mut(&stream_id) {
        pending.buffer.extend_from_slice(data);

        if pending.buffer.len() >= 4 {
            let msg_len = u32::from_be_bytes([
                pending.buffer[0],
                pending.buffer[1],
                pending.buffer[2],
                pending.buffer[3],
            ]) as usize;

            if pending.buffer.len() >= 4 + msg_len {
                let decode_result = bincode::deserialize::<ConnectResponse>(&pending.buffer[4..4 + msg_len]);

                let pending = mc.pending_proxies.remove(&stream_id).expect("just checked");

                match decode_result {
                    Ok(response) if response.is_success() => {
                        let (stream, read_handle) = QuicStream::new(
                            pending.conn_internal_id,
                            stream_id,
                            pending.write_tx,
                            STREAM_READ_BUFFER,
                        );

                        // Forward leftover bytes (after the ConnectResponse) to the new stream.
                        let leftover = &pending.buffer[4 + msg_len..];
                        if !leftover.is_empty() {
                            let _ = read_handle.tx.send(Ok(leftover.to_vec()));
                        }

                        mc.stream_readers.insert(stream_id, read_handle.tx);
                        let _ = pending.response_tx.send(Ok(stream));
                    }
                    Ok(response) => {
                        let reason = match &response {
                            ConnectResponse::Error { reason, .. } => reason.clone(),
                            _ => "unknown".to_owned(),
                        };
                        let _ = pending
                            .response_tx
                            .send(Err(anyhow::anyhow!("agent refused connection: {reason}")));
                    }
                    Err(e) => {
                        warn!(error = %e, stream_id, "Failed to decode ConnectResponse");
                        let _ = pending
                            .response_tx
                            .send(Err(anyhow::anyhow!("invalid ConnectResponse from agent")));
                    }
                }
            }
        }
        return;
    }

    // --- Active data stream ---
    if let Some(reader_tx) = mc.stream_readers.get(&stream_id) {
        if !data.is_empty() {
            let _ = reader_tx.send(Ok(data.to_vec()));
        }
        if fin {
            // Signal EOF then remove.
            let _ = reader_tx.send(Ok(Vec::new()));
            mc.stream_readers.remove(&stream_id);
        }
    }
}

fn process_control_data(mc: &mut ManagedConnection, data: &[u8], registry: &AgentRegistry) {
    mc.control_buf.extend_from_slice(data);

    // Try to decode complete messages from the buffer.
    loop {
        if mc.control_buf.len() < 4 {
            break;
        }

        let msg_len = u32::from_be_bytes([
            mc.control_buf[0],
            mc.control_buf[1],
            mc.control_buf[2],
            mc.control_buf[3],
        ]) as usize;

        if mc.control_buf.len() < 4 + msg_len {
            break; // Incomplete message; wait for more data.
        }

        let payload = mc.control_buf[4..4 + msg_len].to_vec();
        mc.control_buf.drain(..4 + msg_len);

        let msg = match bincode::deserialize::<ControlMessage>(&payload) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to decode control message");
                continue;
            }
        };

        let agent_id = match mc.agent_id {
            Some(id) => id,
            None => continue,
        };

        match msg {
            ControlMessage::RouteAdvertise { epoch, subnets, .. } => {
                info!(%agent_id, epoch, subnet_count = subnets.len(), "Received route advertisement");
                if let Some(peer) = registry.get(&agent_id) {
                    peer.update_routes(epoch, subnets);
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

                // Reply with HeartbeatAck.
                let ack = ControlMessage::heartbeat_ack(timestamp_ms);
                if let Ok(payload) = bincode::serialize(&ack) {
                    let len = u32::try_from(payload.len())
                        .expect("heartbeat ack payload length should fit in u32")
                        .to_be_bytes();
                    let mut response = Vec::with_capacity(4 + payload.len());
                    response.extend_from_slice(&len);
                    response.extend_from_slice(&payload);
                    queue_stream_write(mc, 0, response, false);
                }
            }
            ControlMessage::HeartbeatAck { .. } => {
                debug!(%agent_id, "Unexpected HeartbeatAck from agent");
            }
        }
    }
}

fn handle_proxy_request(
    connections: &mut HashMap<u64, ManagedConnection>,
    write_tx: &mpsc::UnboundedSender<StreamWrite>,
    request: ProxyRequest,
) {
    let mc = match connections
        .values_mut()
        .find(|mc| mc.agent_id == Some(request.agent_id))
    {
        Some(mc) => mc,
        None => {
            let _ = request
                .response_tx
                .send(Err(anyhow::anyhow!("agent {} not connected", request.agent_id)));
            return;
        }
    };

    // Allocate a server-initiated bidirectional stream (IDs: 1, 5, 9, …).
    let stream_id = mc.next_server_bidi;
    mc.next_server_bidi += 4;

    // Encode ConnectMessage.
    let connect_msg = ConnectMessage::new(request.session_id, request.target.clone());
    let payload = match bincode::serialize(&connect_msg) {
        Ok(p) => p,
        Err(e) => {
            let _ = request.response_tx.send(Err(e.into()));
            return;
        }
    };
    let len = u32::try_from(payload.len())
        .expect("ConnectMessage payload length should fit in u32")
        .to_be_bytes();
    let mut data = Vec::with_capacity(4 + payload.len());
    data.extend_from_slice(&len);
    data.extend_from_slice(&payload);

    queue_stream_write(mc, stream_id, data, false);

    info!(
        agent_id = %request.agent_id,
        stream_id,
        target = %request.target,
        session_id = %request.session_id,
        "Opened proxy stream to agent"
    );

    mc.pending_proxies.insert(
        stream_id,
        PendingProxy {
            response_tx: request.response_tx,
            buffer: Vec::new(),
            write_tx: write_tx.clone(),
            conn_internal_id: mc.internal_id,
        },
    );
}

fn apply_stream_write(connections: &mut HashMap<u64, ManagedConnection>, write: StreamWrite) {
    let mc = match connections.get_mut(&write.conn_id) {
        Some(mc) => mc,
        None => return,
    };

    if write.data.is_empty() {
        queue_stream_finish(mc, write.stream_id);
    } else {
        queue_stream_write(mc, write.stream_id, write.data, false);
    }
}

fn queue_stream_write(mc: &mut ManagedConnection, stream_id: u64, data: Vec<u8>, finish_after_write: bool) {
    let pending = mc.pending_stream_writes.entry(stream_id).or_default();

    if !data.is_empty() {
        pending.chunks.push_back(data);
    }

    pending.finish_after_write |= finish_after_write;
    flush_pending_stream_writes(mc);
}

fn queue_stream_finish(mc: &mut ManagedConnection, stream_id: u64) {
    let pending = mc.pending_stream_writes.entry(stream_id).or_default();
    pending.finish_after_write = true;
    flush_pending_stream_writes(mc);
}

fn flush_pending_stream_writes(mc: &mut ManagedConnection) {
    let stream_ids: Vec<u64> = mc.pending_stream_writes.keys().copied().collect();

    for stream_id in stream_ids {
        let mut should_remove = false;

        if let Some(pending) = mc.pending_stream_writes.get_mut(&stream_id) {
            loop {
                let Some(chunk) = pending.chunks.front_mut() else {
                    break;
                };

                match mc.quiche_conn.stream_send(stream_id, chunk, false) {
                    Ok(written) => {
                        if written >= chunk.len() {
                            pending.chunks.pop_front();
                        } else {
                            let remainder = chunk[written..].to_vec();
                            *chunk = remainder;
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => {
                        debug!(%error, stream_id, "stream_send error");
                        pending.finish_after_write = false;
                        pending.chunks.clear();
                        should_remove = true;
                        break;
                    }
                }
            }

            if !should_remove && pending.chunks.is_empty() && pending.finish_after_write {
                match mc.quiche_conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0) {
                    Ok(()) => should_remove = true,
                    Err(quiche::Error::Done) => {}
                    Err(error) => {
                        debug!(%error, stream_id, "stream_shutdown error");
                        should_remove = true;
                    }
                }
            } else if !should_remove && pending.chunks.is_empty() && !pending.finish_after_write {
                should_remove = true;
            }
        }

        if should_remove {
            mc.pending_stream_writes.remove(&stream_id);
        }
    }
}

async fn flush_all(connections: &mut HashMap<u64, ManagedConnection>, socket: &UdpSocket, send_buf: &mut [u8]) {
    for mc in connections.values_mut() {
        loop {
            let (write_len, send_info) = match mc.quiche_conn.send(send_buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    warn!(error = %e, "QUIC send error");
                    mc.quiche_conn.close(false, 0x1, b"internal error").ok();
                    break;
                }
            };

            if let Err(e) = socket.send_to(&send_buf[..write_len], send_info.to).await {
                if e.kind() != io::ErrorKind::WouldBlock {
                    warn!(error = %e, "UDP send error");
                }
                break;
            }
        }
    }
}

fn reap_closed(
    connections: &mut HashMap<u64, ManagedConnection>,
    cid_map: &mut HashMap<Vec<u8>, u64>,
    registry: &AgentRegistry,
) {
    let closed_ids: Vec<u64> = connections
        .iter()
        .filter(|(_, mc)| mc.quiche_conn.is_closed())
        .map(|(&id, _)| id)
        .collect();

    for id in closed_ids {
        if let Some(mc) = connections.remove(&id)
            && let Some(agent_id) = mc.agent_id
        {
            info!(%agent_id, "Agent QUIC connection closed");
            registry.unregister(&agent_id);
        }
        cid_map.retain(|_, v| *v != id);
    }
}
