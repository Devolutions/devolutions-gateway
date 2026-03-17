use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use dashmap::DashMap;
use devolutions_gateway_task::ShutdownSignal;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace, warn};
use tunnel_proto::{RelayMessage, RelayMsgType, RouteAdvertisement};
use uuid::Uuid;
use wireguard_tunnel::TunnResult;

use super::peer::{AgentPeer, StreamHandle};
use super::stream::VirtualTcpStream;
use crate::config::{WireGuardConf, WireGuardPeerConfig};
use crate::target_addr::TargetAddr;

const AGENT_OFFLINE_TIMEOUT: Duration = Duration::from_secs(30);
const WG_HANDSHAKE_INIT: u32 = 1;
const WG_HANDSHAKE_RESP: u32 = 2;
const WG_COOKIE_REPLY: u32 = 3;
const WG_DATA: u32 = 4;
const WG_HANDSHAKE_INIT_LEN: usize = 148;
const WG_HANDSHAKE_RESP_LEN: usize = 92;
const WG_COOKIE_REPLY_LEN: usize = 64;
const WG_DATA_MIN_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireGuardPacketKind {
    HandshakeInit,
    Indexed { receiver_idx: u32 },
}

fn parse_wireguard_packet_kind(packet: &[u8]) -> Result<WireGuardPacketKind> {
    anyhow::ensure!(packet.len() >= 4, "wireguard packet is too short");

    let msg_type = u32::from_le_bytes(packet[0..4].try_into().expect("header length checked above"));

    match (msg_type, packet.len()) {
        (WG_HANDSHAKE_INIT, WG_HANDSHAKE_INIT_LEN) => Ok(WireGuardPacketKind::HandshakeInit),
        (WG_HANDSHAKE_RESP, WG_HANDSHAKE_RESP_LEN) | (WG_COOKIE_REPLY, WG_COOKIE_REPLY_LEN) => {
            let receiver_idx =
                u32::from_le_bytes(packet[8..12].try_into().expect("receiver index length checked above"));
            Ok(WireGuardPacketKind::Indexed { receiver_idx })
        }
        (WG_DATA, WG_DATA_MIN_LEN..) => {
            let receiver_idx =
                u32::from_le_bytes(packet[4..8].try_into().expect("receiver index length checked above"));
            Ok(WireGuardPacketKind::Indexed { receiver_idx })
        }
        _ => anyhow::bail!("unsupported wireguard packet shape"),
    }
}

fn receiver_tunnel_index(receiver_idx: u32) -> u32 {
    receiver_idx >> 8
}

/// Serialize SystemTime as Unix timestamp (seconds since epoch)
fn serialize_systemtime_as_unix<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match time {
        Some(t) => {
            let duration = t
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(serde::ser::Error::custom)?;
            serializer.serialize_some(&duration.as_secs())
        }
        None => serializer.serialize_none(),
    }
}

struct StreamIdGuard {
    peer: Arc<AgentPeer>,
    stream_id: Option<u32>,
}

impl StreamIdGuard {
    fn new(peer: Arc<AgentPeer>, stream_id: u32) -> Self {
        Self {
            peer,
            stream_id: Some(stream_id),
        }
    }

    fn stream_id(&self) -> u32 {
        self.stream_id.expect("stream ID guard should still own the stream ID")
    }

    fn defuse(mut self) -> u32 {
        self.stream_id
            .take()
            .expect("stream ID guard should still own the stream ID")
    }
}

impl Drop for StreamIdGuard {
    fn drop(&mut self) {
        if let Some(stream_id) = self.stream_id.take() {
            self.peer.free_stream_id(stream_id);
        }
    }
}

#[derive(Clone)]
struct WireGuardPeerRegistry {
    peers: Arc<DashMap<Uuid, Arc<AgentPeer>>>,
    pubkey_to_agent: Arc<DashMap<[u8; 32], Uuid>>,
    tunnel_ip_to_agent: Arc<DashMap<Ipv4Addr, Uuid>>,
    tunnel_index_to_agent: Arc<DashMap<u32, Uuid>>,
    next_local_tunnel_index: Arc<AtomicU32>,
}

impl WireGuardPeerRegistry {
    fn new() -> Self {
        Self {
            peers: Arc::new(DashMap::new()),
            pubkey_to_agent: Arc::new(DashMap::new()),
            tunnel_ip_to_agent: Arc::new(DashMap::new()),
            tunnel_index_to_agent: Arc::new(DashMap::new()),
            next_local_tunnel_index: Arc::new(AtomicU32::new(1)),
        }
    }

    fn allocate_local_tunnel_index(&self) -> Result<u32> {
        let local_tunnel_index = self.next_local_tunnel_index.fetch_add(1, Ordering::Relaxed);
        anyhow::ensure!(local_tunnel_index != u32::MAX, "local tunnel index space is exhausted");
        Ok(local_tunnel_index)
    }

    fn register_peer(&self, peer: Arc<AgentPeer>) {
        self.next_local_tunnel_index
            .fetch_max(peer.local_tunnel_index.saturating_add(1), Ordering::Relaxed);
        self.pubkey_to_agent
            .insert(wireguard_public_key_bytes(&peer.public_key), peer.agent_id);
        self.tunnel_ip_to_agent.insert(peer.assigned_ip, peer.agent_id);
        self.tunnel_index_to_agent
            .insert(peer.local_tunnel_index, peer.agent_id);
        self.peers.insert(peer.agent_id, peer);
    }

    fn remove_peer(&self, agent_id: &Uuid) -> Option<Arc<AgentPeer>> {
        let (_, peer) = self.peers.remove(agent_id)?;
        self.pubkey_to_agent
            .remove(&wireguard_public_key_bytes(&peer.public_key));
        self.tunnel_ip_to_agent.remove(&peer.assigned_ip);
        self.tunnel_index_to_agent.remove(&peer.local_tunnel_index);
        Some(peer)
    }
}

fn wireguard_public_key_bytes(public_key: &wireguard_tunnel::PublicKey) -> [u8; 32] {
    *public_key.as_bytes()
}

/// Handle for interacting with WireGuard listener
#[derive(Clone)]
pub struct WireGuardHandle {
    /// Configured agent peers (agent_id -> peer)
    registry: WireGuardPeerRegistry,
    /// UDP socket for WireGuard traffic
    udp_socket: Arc<UdpSocket>,
    /// Gateway's tunnel IP
    gateway_tunnel_ip: Ipv4Addr,
    /// Gateway's WireGuard private key
    gateway_private_key: wireguard_tunnel::StaticSecret,
}

impl WireGuardHandle {
    /// Connect to a target via an agent
    pub async fn connect_via_agent(
        &self,
        agent_id: Uuid,
        targets: &[TargetAddr],
    ) -> Result<(VirtualTcpStream, SocketAddr, TargetAddr)> {
        let peer = self
            .registry
            .peers
            .get(&agent_id)
            .with_context(|| format!("Agent {} not found", agent_id))?
            .clone();

        let target = targets.first().context("No target addresses provided")?;

        anyhow::ensure!(peer.is_online(AGENT_OFFLINE_TIMEOUT), "Agent {} is offline", agent_id);

        // Verify agent can reach target (if it's an IP address)
        if let Some(target_ip) = target.host_ip() {
            anyhow::ensure!(
                peer.can_reach(target_ip),
                "Agent {} cannot reach target {} (IP: {})",
                agent_id,
                target.as_str(),
                target_ip
            );
        }

        // Allocate stream ID
        let stream_id = peer.allocate_stream_id().context("Failed to allocate stream ID")?;
        let stream_id_guard = StreamIdGuard::new(Arc::clone(&peer), stream_id);

        // Create channel for receiving data
        let (tx, rx) = mpsc::channel(64);
        let (connected_tx, connected_rx) = oneshot::channel();

        // Register stream handle
        peer.active_streams.insert(
            stream_id_guard.stream_id(),
            StreamHandle {
                target: target.as_str().to_owned(),
                tx,
                connected_tx: Some(connected_tx),
                last_activity: std::time::Instant::now(),
            },
        );

        // Send CONNECT message
        let connect_msg = RelayMessage::connect(stream_id_guard.stream_id(), target.as_str())
            .context("Failed to create CONNECT message")?;

        peer.send_relay_message(self.gateway_tunnel_ip, &connect_msg, &self.udp_socket)
            .await
            .context("Failed to send CONNECT message")?;

        info!(
            stream_id = stream_id_guard.stream_id(),
            agent_id = %agent_id,
            target = %target.as_str(),
            "Sent CONNECT request to agent"
        );

        // Wait for CONNECTED (with timeout)
        tokio::time::timeout(Duration::from_secs(10), connected_rx)
            .await
            .context("Timeout waiting for agent to connect")?
            .context("Agent dropped CONNECT response channel")?
            .map_err(anyhow::Error::msg)?;

        let stream_id = stream_id_guard.defuse();

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<RelayMessage>(64);
        let peer_for_outbound = Arc::clone(&peer);
        let udp_socket = Arc::clone(&self.udp_socket);
        let gateway_tunnel_ip = self.gateway_tunnel_ip;

        tokio::spawn(async move {
            while let Some(msg) = outbound_rx.recv().await {
                let msg_type = msg.msg_type;

                if let Err(error) = peer_for_outbound
                    .send_relay_message(gateway_tunnel_ip, &msg, &udp_socket)
                    .await
                {
                    warn!(
                        stream_id,
                        agent_id = %peer_for_outbound.agent_id,
                        error = %error,
                        "Failed to send relay message to agent"
                    );
                    // Stream ID cleanup is owned by VirtualTcpStream::Drop to avoid double-freeing
                    // IDs when the outbound task fails before the stream object is dropped.
                    break;
                }

                if msg_type == RelayMsgType::Close {
                    break;
                }
            }
        });

        // Create virtual stream
        let peer_addr = SocketAddr::new(IpAddr::V4(peer.assigned_ip), 0);
        let local_addr = SocketAddr::new(IpAddr::V4(self.gateway_tunnel_ip), 0);

        let stream = VirtualTcpStream::new(Arc::clone(&peer), stream_id, rx, outbound_tx, peer_addr, local_addr);

        Ok((stream, peer_addr, target.clone()))
    }

    /// List all registered agents with their status
    pub fn list_agents(&self) -> Vec<AgentInfo> {
        self.registry
            .peers
            .iter()
            .map(|entry| {
                let peer = entry.value();
                AgentInfo::from_peer(entry.key(), peer)
            })
            .collect()
    }

    /// Get information for a specific agent
    pub fn get_agent(&self, agent_id: &Uuid) -> Option<AgentInfo> {
        self.registry
            .peers
            .get(agent_id)
            .map(|peer| AgentInfo::from_peer(agent_id, &peer))
    }

    /// Find agents that can reach a given IP address
    pub fn find_agents_for_target(&self, target_ip: IpAddr) -> Vec<AgentInfo> {
        let mut agents = self
            .registry
            .peers
            .iter()
            .filter(|entry| entry.value().is_online(AGENT_OFFLINE_TIMEOUT))
            .filter(|entry| entry.value().can_reach(target_ip))
            .map(|entry| AgentInfo::from_peer(entry.key(), entry.value()))
            .collect::<Vec<_>>();

        agents.sort_by(|left, right| right.last_advertised_at.cmp(&left.last_advertised_at));
        agents
    }

    pub fn select_agent_for_target(&self, target_ip: IpAddr) -> Option<Arc<AgentPeer>> {
        // Route selection must yield a single winner.
        // For overlapping subnets, Gateway only uses the latest online winner and must never
        // retry the same connection attempt against another agent. Agent-to-agent fallback only
        // happens after route ownership changes, such as when the current winner goes offline.
        self.registry
            .peers
            .iter()
            .filter(|entry| entry.value().is_online(AGENT_OFFLINE_TIMEOUT))
            .filter_map(|entry| {
                let peer = entry.value();
                let route_state = peer.route_state()?;
                let matches = match target_ip {
                    IpAddr::V4(ipv4) => route_state.subnets.iter().any(|subnet| subnet.contains(ipv4)),
                    IpAddr::V6(_) => false,
                };

                if matches {
                    Some((route_state.received_at, Arc::clone(peer)))
                } else {
                    None
                }
            })
            .max_by_key(|(received_at, _)| *received_at)
            .map(|(_, peer)| peer)
    }

    pub fn add_peer(&self, peer_config: WireGuardPeerConfig) -> Result<Arc<AgentPeer>> {
        anyhow::ensure!(
            !self.registry.peers.contains_key(&peer_config.agent_id),
            "WireGuard peer {} already exists",
            peer_config.agent_id
        );
        anyhow::ensure!(
            !self.registry.tunnel_ip_to_agent.contains_key(&peer_config.assigned_ip),
            "WireGuard tunnel IP {} is already in use",
            peer_config.assigned_ip
        );

        let local_tunnel_index = self.registry.allocate_local_tunnel_index()?;
        let peer = Arc::new(AgentPeer::new(
            peer_config,
            self.gateway_private_key.clone(),
            self.gateway_tunnel_ip,
            local_tunnel_index,
        )?);

        self.registry.register_peer(Arc::clone(&peer));

        info!(
            agent_id = %peer.agent_id,
            name = %peer.name,
            assigned_ip = %peer.assigned_ip,
            local_tunnel_index,
            "Registered WireGuard peer at runtime"
        );

        Ok(peer)
    }

    pub fn remove_peer(&self, agent_id: &Uuid) -> Option<Arc<AgentPeer>> {
        let peer = self.registry.remove_peer(agent_id)?;

        info!(
            agent_id = %peer.agent_id,
            name = %peer.name,
            assigned_ip = %peer.assigned_ip,
            local_tunnel_index = peer.local_tunnel_index,
            "Removed WireGuard peer at runtime"
        );

        Some(peer)
    }
}

/// Agent information for API responses
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentInfo {
    pub agent_id: Uuid,
    pub name: String,
    pub status: AgentStatus,
    pub assigned_ip: Ipv4Addr,
    pub advertised_subnets: Vec<String>,
    pub route_epoch: Option<u64>,
    pub active_streams: usize,
    #[serde(serialize_with = "serialize_systemtime_as_unix")]
    pub last_advertised_at: Option<SystemTime>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Online,
    Offline,
    Unknown,
}

impl AgentInfo {
    fn from_peer(agent_id: &Uuid, peer: &AgentPeer) -> Self {
        let route_state = peer.route_state();
        Self {
            agent_id: *agent_id,
            name: peer.name.clone(),
            status: if peer.is_online(AGENT_OFFLINE_TIMEOUT) {
                AgentStatus::Online
            } else {
                AgentStatus::Offline
            },
            assigned_ip: peer.assigned_ip,
            advertised_subnets: route_state
                .as_ref()
                .map(|route_state| route_state.subnets.iter().map(|subnet| subnet.to_string()).collect())
                .unwrap_or_default(),
            route_epoch: route_state.as_ref().map(|route_state| route_state.epoch),
            active_streams: peer.active_streams.len(),
            last_advertised_at: route_state.map(|route_state| route_state.updated_at),
        }
    }
}

/// WireGuard listener for agent tunneling
pub struct WireGuardListener {
    /// UDP socket for WireGuard traffic
    udp_socket: Arc<UdpSocket>,
    /// Configured agent peers (agent_id -> peer)
    registry: WireGuardPeerRegistry,
    /// Gateway's WireGuard private key
    #[allow(dead_code)]
    gateway_private_key: wireguard_tunnel::StaticSecret,
    /// Gateway's tunnel IP
    #[allow(dead_code)]
    gateway_tunnel_ip: Ipv4Addr,
}

impl WireGuardListener {
    /// Initialize and bind the WireGuard listener
    pub fn init_and_bind(
        bind_addr: SocketAddr,
        config: &WireGuardConf,
        initial_peers: Vec<WireGuardPeerConfig>,
    ) -> Result<(Self, WireGuardHandle)> {
        // Bind UDP socket
        let udp_socket = std::net::UdpSocket::bind(bind_addr)
            .with_context(|| format!("Failed to bind WireGuard UDP socket on {}", bind_addr))?;
        udp_socket.set_nonblocking(true)?;
        let udp_socket = Arc::new(UdpSocket::from_std(udp_socket)?);

        info!(?bind_addr, "WireGuard listener bound");

        let registry = WireGuardPeerRegistry::new();

        // Initialize peers
        for peer_config in initial_peers {
            let local_tunnel_index = registry.allocate_local_tunnel_index()?;
            let peer = AgentPeer::new(
                peer_config.clone(),
                config.private_key.clone(),
                config.gateway_ip,
                local_tunnel_index,
            )?;

            info!(
                agent_id = %peer.agent_id,
                name = %peer.name,
                assigned_ip = %peer.assigned_ip,
                local_tunnel_index,
                "Registered WireGuard peer"
            );

            // For now, we identify peers by endpoint or tunnel IP
            // TODO: Implement proper WireGuard packet header parsing for peer identification

            registry.register_peer(Arc::new(peer));
        }

        let handle = WireGuardHandle {
            registry: registry.clone(),
            udp_socket: Arc::clone(&udp_socket),
            gateway_tunnel_ip: config.gateway_ip,
            gateway_private_key: config.private_key.clone(),
        };

        let listener = Self {
            udp_socket,
            registry,
            gateway_private_key: config.private_key.clone(),
            gateway_tunnel_ip: config.gateway_ip,
        };

        Ok((listener, handle))
    }

    /// Main event loop
    async fn run_event_loop(&self) -> Result<()> {
        info!("WireGuard event loop started, waiting for packets");
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        let mut udp_buf = vec![0u8; 65536];
        let mut dst_buf = vec![0u8; 65536];

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    self.handle_timer(&mut dst_buf).await?;
                }

                result = self.udp_socket.recv_from(&mut udp_buf) => {
                    let (n, peer_addr) = result?;
                    trace!(?peer_addr, len = n, "Received UDP packet");
                    if let Err(e) = self.handle_udp_packet(&udp_buf[..n], peer_addr, &mut dst_buf).await {
                        warn!(error = ?e, %peer_addr, "Failed to handle UDP packet");
                    }
                }
            }
        }
    }

    /// Handle incoming UDP packet
    async fn handle_udp_packet(&self, packet: &[u8], peer_addr: SocketAddr, dst: &mut [u8]) -> Result<()> {
        if matches!(parse_wireguard_packet_kind(packet)?, WireGuardPacketKind::HandshakeInit)
            && self.find_peer_by_endpoint(peer_addr).is_none()
            && self.registry.peers.len() > 1
        {
            return self.handle_handshake_init_packet(packet, peer_addr, dst).await;
        }

        let peer = self.find_peer_for_packet(packet, peer_addr)?;
        self.process_packet_for_peer(peer, packet, peer_addr, dst).await
    }

    async fn process_packet_for_peer(
        &self,
        peer: Arc<AgentPeer>,
        packet: &[u8],
        peer_addr: SocketAddr,
        dst: &mut [u8],
    ) -> Result<()> {
        peer.mark_packet_received();

        // Decrypt with WireGuard and extract relay message (if any)
        let (relay_msg_opt, handshake_response) = {
            let mut tunn = peer.tunn.lock();
            let result = tunn.decapsulate(Some(peer_addr.ip()), packet, dst);
            match result {
                TunnResult::WriteToTunnelV4(ip_packet, _) => {
                    // Extract relay protocol payload
                    let payload = wireguard_tunnel::ip_packet::extract_payload(ip_packet)
                        .context("Failed to extract relay payload from IP packet")?;

                    if payload.is_empty() {
                        return Ok(());
                    }

                    // Decode relay message
                    let relay_msg = RelayMessage::decode(&payload[..]).context("Failed to decode relay message")?;

                    debug!(
                        stream_id = relay_msg.stream_id,
                        msg_type = ?relay_msg.msg_type,
                        agent_id = %peer.agent_id,
                        "Received relay message"
                    );

                    (Some(relay_msg), None)
                }
                TunnResult::WriteToNetwork(response) => {
                    // Copy response to send after releasing lock
                    (None, Some(Bytes::copy_from_slice(response)))
                }
                TunnResult::Done => (None, None),
                TunnResult::Err(e) => {
                    anyhow::bail!("WireGuard decapsulate error: {:?}", e);
                }
                _ => (None, None),
            }
        }; // tunn lock released here

        // Send handshake response if any
        if let Some(response) = handshake_response {
            self.udp_socket.send_to(&response, peer_addr).await?;
        }

        // Handle relay message if we got one
        if let Some(relay_msg) = relay_msg_opt {
            self.handle_relay_message(Arc::clone(&peer), relay_msg).await?;
        }

        // CRITICAL: Flush loop (boringtun requirement)
        let flush_packets = {
            let mut tunn = peer.tunn.lock();
            let mut packets = Vec::new();
            loop {
                let result = tunn.decapsulate(None, &[], dst);
                match result {
                    TunnResult::WriteToNetwork(resp) => {
                        packets.push(Bytes::copy_from_slice(resp));
                    }
                    TunnResult::Done => break,
                    TunnResult::Err(e) => {
                        anyhow::bail!("WireGuard flush error: {:?}", e);
                    }
                    _ => {}
                }
            }
            packets
        }; // tunn lock released

        // Send flush packets
        for packet in flush_packets {
            self.udp_socket.send_to(&packet, peer_addr).await?;
        }

        // Update endpoint (NAT traversal support)
        *peer.endpoint.write() = peer_addr;

        Ok(())
    }

    async fn handle_handshake_init_packet(&self, packet: &[u8], peer_addr: SocketAddr, dst: &mut [u8]) -> Result<()> {
        for peer_entry in self.registry.peers.iter() {
            let peer = Arc::clone(peer_entry.value());
            let handshake_response = {
                let mut tunn = peer.tunn.lock();
                match tunn.decapsulate(Some(peer_addr.ip()), packet, dst) {
                    TunnResult::WriteToNetwork(response) => Some(Bytes::copy_from_slice(response)),
                    TunnResult::Err(_) => None,
                    _ => None,
                }
            };

            let Some(handshake_response) = handshake_response else {
                continue;
            };

            peer.mark_packet_received();
            self.udp_socket.send_to(&handshake_response, peer_addr).await?;

            let flush_packets = {
                let mut tunn = peer.tunn.lock();
                let mut packets = Vec::new();
                loop {
                    match tunn.decapsulate(None, &[], dst) {
                        TunnResult::WriteToNetwork(resp) => {
                            packets.push(Bytes::copy_from_slice(resp));
                        }
                        TunnResult::Done => break,
                        TunnResult::Err(e) => {
                            anyhow::bail!("WireGuard flush error: {:?}", e);
                        }
                        _ => {}
                    }
                }
                packets
            };

            for packet in flush_packets {
                self.udp_socket.send_to(&packet, peer_addr).await?;
            }

            *peer.endpoint.write() = peer_addr;

            info!(
                agent_id = %peer.agent_id,
                local_tunnel_index = peer.local_tunnel_index,
                ?peer_addr,
                "Identified peer from handshake initiation"
            );

            return Ok(());
        }

        anyhow::bail!("Unable to identify peer for handshake initiation from {}", peer_addr)
    }

    /// Handle timer tick (WireGuard keepalives, rekeys, etc.)
    async fn handle_timer(&self, dst: &mut [u8]) -> Result<()> {
        trace!("Timer tick, processing {} peers", self.registry.peers.len());
        for peer_entry in self.registry.peers.iter() {
            let peer = peer_entry.value();
            peer.clear_routes_if_offline(AGENT_OFFLINE_TIMEOUT);

            let packets = {
                let mut tunn = peer.tunn.lock();
                wireguard_tunnel::tunn_manager::handle_timer_tick(&mut tunn, dst)
                    .context("timer tick failed")?
            };

            let endpoint = *peer.endpoint.read();
            if endpoint.port() != 0 {
                for packet in packets {
                    self.udp_socket.send_to(&packet, endpoint).await?;
                }
            }
        }

        Ok(())
    }

    fn find_peer_by_endpoint(&self, peer_addr: SocketAddr) -> Option<Arc<AgentPeer>> {
        for peer_entry in self.registry.peers.iter() {
            let peer = peer_entry.value();
            let endpoint = *peer.endpoint.read();
            if endpoint == peer_addr {
                return Some(Arc::clone(peer));
            }
        }

        None
    }

    fn find_peer_by_tunnel_index(&self, local_tunnel_index: u32) -> Option<Arc<AgentPeer>> {
        self.registry
            .tunnel_index_to_agent
            .get(&local_tunnel_index)
            .and_then(|agent_id| {
                self.registry
                    .peers
                    .get(agent_id.value())
                    .map(|peer| Arc::clone(peer.value()))
            })
    }

    /// Find peer for incoming packet using endpoint or receiver index.
    fn find_peer_for_packet(&self, packet: &[u8], peer_addr: SocketAddr) -> Result<Arc<AgentPeer>> {
        if let Some(peer) = self.find_peer_by_endpoint(peer_addr) {
            return Ok(peer);
        }

        if let WireGuardPacketKind::Indexed { receiver_idx } = parse_wireguard_packet_kind(packet)?
            && let Some(peer) = self.find_peer_by_tunnel_index(receiver_tunnel_index(receiver_idx))
        {
            return Ok(peer);
        }

        if self.registry.peers.len() == 1 {
            return self
                .registry
                .peers
                .iter()
                .next()
                .map(|e| Arc::clone(e.value()))
                .context("No peers configured");
        }

        anyhow::bail!("Unable to identify peer for packet from {}", peer_addr)
    }

    /// Handle relay protocol message
    async fn handle_relay_message(&self, peer: Arc<AgentPeer>, msg: RelayMessage) -> Result<()> {
        match msg.msg_type {
            RelayMsgType::Connected => {
                // Agent successfully connected to target
                if let Some(mut handle) = peer.active_streams.get_mut(&msg.stream_id) {
                    debug!(stream_id = msg.stream_id, agent_id = %peer.agent_id, "Stream connected");
                    if let Some(connected_tx) = handle.connected_tx.take() {
                        let _ = connected_tx.send(Ok(()));
                    }
                    handle.last_activity = std::time::Instant::now();
                }
            }

            RelayMsgType::Data => {
                // Forward data to stream consumer
                let tx = peer.active_streams.get(&msg.stream_id).map(|handle| handle.tx.clone());

                if let Some(tx) = tx {
                    match tx.try_send(msg.payload) {
                        Ok(()) => {
                            if let Some(mut handle) = peer.active_streams.get_mut(&msg.stream_id) {
                                handle.last_activity = std::time::Instant::now();
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            warn!(stream_id = msg.stream_id, "Stream consumer dropped");
                            peer.free_stream_id(msg.stream_id);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!(stream_id = msg.stream_id, "Virtual stream receive buffer is full");
                            peer.free_stream_id(msg.stream_id);
                        }
                    }
                }
            }

            RelayMsgType::Close => {
                // Agent closed stream
                if let Some(mut handle) = peer.active_streams.get_mut(&msg.stream_id)
                    && let Some(connected_tx) = handle.connected_tx.take()
                {
                    let _ = connected_tx.send(Err("stream closed before CONNECTED".to_owned()));
                }
                debug!(stream_id = msg.stream_id, agent_id = %peer.agent_id, "Stream closed by agent");
                peer.active_streams.remove(&msg.stream_id);
                peer.free_stream_id(msg.stream_id);
            }

            RelayMsgType::Error => {
                // Agent reported error
                let error_msg = String::from_utf8_lossy(&msg.payload);
                if let Some(mut handle) = peer.active_streams.get_mut(&msg.stream_id)
                    && let Some(connected_tx) = handle.connected_tx.take()
                {
                    let _ = connected_tx.send(Err(error_msg.to_string()));
                }
                warn!(
                    stream_id = msg.stream_id,
                    agent_id = %peer.agent_id,
                    error = %error_msg,
                    "Agent reported stream error"
                );
                peer.active_streams.remove(&msg.stream_id);
                peer.free_stream_id(msg.stream_id);
            }

            RelayMsgType::RouteAdvertise => {
                anyhow::ensure!(
                    msg.stream_id == 0,
                    "RouteAdvertise must use control stream ID 0, got {}",
                    msg.stream_id
                );
                let advertisement =
                    RouteAdvertisement::decode(&msg.payload[..]).context("Failed to decode route advertisement")?;
                let subnet_count = advertisement.subnets.len();
                let epoch = advertisement.epoch;
                peer.update_routes(epoch, advertisement.subnets);
                info!(
                    agent_id = %peer.agent_id,
                    epoch,
                    subnet_count,
                    "Updated peer route advertisement"
                );
            }

            RelayMsgType::Connect => {
                // This should not happen (CONNECT is gateway → agent)
                warn!(stream_id = msg.stream_id, "Received unexpected CONNECT from agent");
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl devolutions_gateway_task::Task for WireGuardListener {
    type Output = Result<()>;

    const NAME: &'static str = "wireguard listener";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> Self::Output {
        info!("WireGuard listener started");

        tokio::select! {
            result = self.run_event_loop() => {
                error!(?result, "WireGuard listener event loop exited");
                result
            }
            _ = shutdown_signal.wait() => {
                info!("WireGuard listener shutting down");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use wireguard_tunnel::TunnResult;

    use super::*;

    fn test_peer(agent_id: Uuid, name: &str, assigned_ip: Ipv4Addr) -> Arc<AgentPeer> {
        let gateway_private_key = wireguard_tunnel::StaticSecret::from([7u8; 32]);
        let agent_private_key = wireguard_tunnel::StaticSecret::from([9u8; 32]);

        Arc::new(
            AgentPeer::new(
                WireGuardPeerConfig {
                    agent_id,
                    name: name.to_owned(),
                    public_key: wireguard_tunnel::PublicKey::from(&agent_private_key),
                    assigned_ip,
                },
                gateway_private_key,
                Ipv4Addr::new(10, 10, 0, 1),
                assigned_ip.octets()[3].into(),
            )
            .expect("test peer should build"),
        )
    }

    async fn test_handle(peers: Vec<Arc<AgentPeer>>) -> WireGuardHandle {
        let udp_socket = Arc::new(
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .expect("test UDP socket should bind"),
        );
        let registry = WireGuardPeerRegistry::new();

        for peer in peers {
            *peer.last_packet_at.write() = Some(std::time::Instant::now());
            registry.register_peer(peer);
        }

        WireGuardHandle {
            registry,
            udp_socket,
            gateway_tunnel_ip: Ipv4Addr::new(10, 10, 0, 1),
            gateway_private_key: wireguard_tunnel::StaticSecret::from([7u8; 32]),
        }
    }

    async fn test_listener(peers: Vec<Arc<AgentPeer>>) -> WireGuardListener {
        let udp_socket = Arc::new(
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .expect("test UDP socket should bind"),
        );
        let registry = WireGuardPeerRegistry::new();

        for peer in peers {
            registry.register_peer(peer);
        }

        WireGuardListener {
            udp_socket,
            registry,
            gateway_private_key: wireguard_tunnel::StaticSecret::from([7u8; 32]),
            gateway_tunnel_ip: Ipv4Addr::new(10, 10, 0, 1),
        }
    }

    fn handshake_init_packet(
        agent_private_key_bytes: [u8; 32],
        gateway_private_key_bytes: [u8; 32],
        agent_tunnel_ip: Ipv4Addr,
        gateway_tunnel_ip: Ipv4Addr,
    ) -> Bytes {
        let agent_private_key = wireguard_tunnel::StaticSecret::from(agent_private_key_bytes);
        let gateway_private_key = wireguard_tunnel::StaticSecret::from(gateway_private_key_bytes);
        let gateway_public_key = wireguard_tunnel::PublicKey::from(&gateway_private_key);
        let mut tunn = wireguard_tunnel::Tunn::new(agent_private_key, gateway_public_key, None, Some(25), 0, None);
        let mut dst_buf = vec![0u8; 65536];
        let dummy_packet = wireguard_tunnel::ip_packet::build_ip_packet(agent_tunnel_ip, gateway_tunnel_ip, &[])
            .expect("dummy IP packet");

        match tunn.encapsulate(&dummy_packet, &mut dst_buf) {
            TunnResult::WriteToNetwork(packet) => Bytes::copy_from_slice(packet),
            other => panic!("expected handshake initiation packet, got {other:?}"),
        }
    }

    #[test]
    fn stream_id_guard_releases_stream_id_when_not_defused() {
        let peer = test_peer(Uuid::new_v4(), "guard-agent", Ipv4Addr::new(10, 10, 0, 9));
        let stream_id = peer.allocate_stream_id().expect("stream ID should allocate");

        {
            let _guard = StreamIdGuard::new(Arc::clone(&peer), stream_id);
        }

        let recycled_stream_id = peer.allocate_stream_id().expect("freed stream ID should reallocate");
        assert_eq!(recycled_stream_id, stream_id);
    }

    #[test]
    fn stream_id_guard_preserves_stream_id_after_defuse() {
        let peer = test_peer(Uuid::new_v4(), "guard-agent", Ipv4Addr::new(10, 10, 0, 9));
        let stream_id = peer.allocate_stream_id().expect("stream ID should allocate");

        let defused_stream_id = {
            let guard = StreamIdGuard::new(Arc::clone(&peer), stream_id);
            guard.defuse()
        };

        let next_stream_id = peer
            .allocate_stream_id()
            .expect("defused stream ID must stay allocated");
        assert_ne!(next_stream_id, defused_stream_id);
        peer.free_stream_id(defused_stream_id);
    }

    #[tokio::test]
    async fn runtime_add_and_remove_peer_updates_registry() {
        let handle = test_handle(Vec::new()).await;
        let agent_id = Uuid::new_v4();
        let private_key = wireguard_tunnel::StaticSecret::from([11u8; 32]);
        let peer_config = WireGuardPeerConfig {
            agent_id,
            name: "runtime-agent".to_owned(),
            public_key: wireguard_tunnel::PublicKey::from(&private_key),
            assigned_ip: Ipv4Addr::new(10, 10, 0, 22),
        };

        let peer = handle.add_peer(peer_config).expect("peer should be added");

        assert_eq!(peer.agent_id, agent_id);
        assert!(handle.get_agent(&agent_id).is_some());

        let removed = handle.remove_peer(&agent_id).expect("peer should be removed");

        assert_eq!(removed.agent_id, agent_id);
        assert!(handle.get_agent(&agent_id).is_none());
    }

    #[tokio::test]
    async fn select_agent_for_target_preserves_winner_for_same_epoch_refreshes() {
        let primary_agent_id = Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
        let secondary_agent_id = Uuid::from_u128(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb);
        let primary_agent = test_peer(primary_agent_id, "agent-a", Ipv4Addr::new(10, 10, 0, 2));
        let secondary_agent = test_peer(secondary_agent_id, "agent-b", Ipv4Addr::new(10, 10, 0, 3));
        let handle = test_handle(vec![Arc::clone(&primary_agent), Arc::clone(&secondary_agent)]).await;
        let subnet = "10.200.1.0/24".parse().expect("valid CIDR");
        let target_ip = IpAddr::V4(Ipv4Addr::new(10, 200, 1, 10));

        primary_agent.update_routes(10, vec![subnet]);
        std::thread::sleep(Duration::from_millis(5));
        secondary_agent.update_routes(20, vec![subnet]);

        let winner = handle
            .select_agent_for_target(target_ip)
            .expect("a winner should exist after both advertisements");
        assert_eq!(winner.agent_id, secondary_agent_id, "newer agent should initially win");

        std::thread::sleep(Duration::from_millis(5));
        primary_agent.update_routes(10, vec![subnet]);

        let winner = handle
            .select_agent_for_target(target_ip)
            .expect("a winner should exist after a same-epoch refresh");
        assert_eq!(
            winner.agent_id, secondary_agent_id,
            "same-epoch refreshes should not steal priority back from a newer competing advertisement"
        );
    }

    #[tokio::test]
    async fn select_agent_for_target_skips_offline_latest_winner() {
        let primary_agent_id = Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
        let secondary_agent_id = Uuid::from_u128(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb);
        let primary_agent = test_peer(primary_agent_id, "agent-a", Ipv4Addr::new(10, 10, 0, 2));
        let secondary_agent = test_peer(secondary_agent_id, "agent-b", Ipv4Addr::new(10, 10, 0, 3));
        let handle = test_handle(vec![Arc::clone(&primary_agent), Arc::clone(&secondary_agent)]).await;
        let subnet = "10.200.1.0/24".parse().expect("valid CIDR");
        let target_ip = IpAddr::V4(Ipv4Addr::new(10, 200, 1, 10));

        primary_agent.update_routes(10, vec![subnet]);
        std::thread::sleep(Duration::from_millis(5));
        secondary_agent.update_routes(20, vec![subnet]);

        *secondary_agent.last_packet_at.write() = Some(std::time::Instant::now() - Duration::from_secs(31));

        let winner = handle
            .select_agent_for_target(target_ip)
            .expect("offline winner should be skipped in favor of the remaining online agent");
        assert_eq!(winner.agent_id, primary_agent_id);
    }

    #[tokio::test]
    async fn handle_handshake_init_works_with_multiple_registered_peers() {
        let gateway_private_key_bytes = [7u8; 32];
        let gateway_private_key = wireguard_tunnel::StaticSecret::from(gateway_private_key_bytes);
        let primary_agent_private_key = wireguard_tunnel::StaticSecret::from([9u8; 32]);
        let secondary_agent_private_key = wireguard_tunnel::StaticSecret::from([11u8; 32]);
        let primary_agent_id = Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
        let secondary_agent_id = Uuid::from_u128(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb);
        let primary_agent = Arc::new(
            AgentPeer::new(
                WireGuardPeerConfig {
                    agent_id: primary_agent_id,
                    name: "agent-a".to_owned(),
                    public_key: wireguard_tunnel::PublicKey::from(&primary_agent_private_key),
                    assigned_ip: Ipv4Addr::new(10, 10, 0, 2),
                },
                gateway_private_key.clone(),
                Ipv4Addr::new(10, 10, 0, 1),
                1,
            )
            .expect("agent A peer should build"),
        );
        let secondary_agent = Arc::new(
            AgentPeer::new(
                WireGuardPeerConfig {
                    agent_id: secondary_agent_id,
                    name: "agent-b".to_owned(),
                    public_key: wireguard_tunnel::PublicKey::from(&secondary_agent_private_key),
                    assigned_ip: Ipv4Addr::new(10, 10, 0, 3),
                },
                gateway_private_key,
                Ipv4Addr::new(10, 10, 0, 1),
                2,
            )
            .expect("agent B peer should build"),
        );
        let listener = test_listener(vec![Arc::clone(&primary_agent), Arc::clone(&secondary_agent)]).await;
        let packet = handshake_init_packet(
            [9u8; 32],
            gateway_private_key_bytes,
            Ipv4Addr::new(10, 10, 0, 2),
            Ipv4Addr::new(10, 10, 0, 1),
        );

        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51820);
        let mut dst_buf = vec![0u8; 65536];

        listener
            .handle_udp_packet(&packet, peer_addr, &mut dst_buf)
            .await
            .expect("handshake initiation should identify and bind the correct peer endpoint");

        assert_eq!(*primary_agent.endpoint.read(), peer_addr);
        assert_ne!(*secondary_agent.endpoint.read(), peer_addr);
    }

    #[tokio::test]
    async fn find_peer_for_indexed_packet_uses_receiver_index_mapping() {
        let primary_agent_id = Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
        let secondary_agent_id = Uuid::from_u128(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb);
        let primary_agent = test_peer(primary_agent_id, "agent-a", Ipv4Addr::new(10, 10, 0, 2));
        let secondary_agent = test_peer(secondary_agent_id, "agent-b", Ipv4Addr::new(10, 10, 0, 3));
        let listener = test_listener(vec![Arc::clone(&primary_agent), Arc::clone(&secondary_agent)]).await;
        let mut packet = vec![0u8; WG_DATA_MIN_LEN];

        packet[0..4].copy_from_slice(&WG_DATA.to_le_bytes());
        packet[4..8].copy_from_slice(&(secondary_agent.local_tunnel_index << 8).to_le_bytes());

        let peer = listener
            .find_peer_for_packet(&packet, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 60000))
            .expect("receiver index mapping should resolve the packet to agent B");

        assert_eq!(peer.agent_id, secondary_agent_id);
    }
}
