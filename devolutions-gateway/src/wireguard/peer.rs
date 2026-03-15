use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use ipnetwork::Ipv4Network;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, oneshot};
use tunnel_proto::{RelayMessage, StreamIdAllocator};
use uuid::Uuid;
use wireguard_tunnel::Tunn;

use crate::config::WireGuardPeerConfig;

/// Handle for an active relay stream
#[derive(Debug)]
pub struct StreamHandle {
    /// Target address this stream is connected to
    pub target: String,
    /// Channel to send data to the stream consumer
    pub tx: mpsc::Sender<Bytes>,
    /// Completion signal for the CONNECT / CONNECTED handshake
    pub connected_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
    /// Timestamp of last activity (for cleanup)
    pub last_activity: Instant,
}

#[derive(Debug, Clone)]
pub struct RouteAdvertisementState {
    pub epoch: u64,
    pub subnets: Vec<Ipv4Network>,
    pub received_at: Instant,
    pub updated_at: SystemTime,
}

/// Represents a WireGuard peer (agent)
pub struct AgentPeer {
    /// Agent UUID
    pub agent_id: Uuid,
    /// Friendly name
    pub name: String,
    /// WireGuard tunnel instance
    pub tunn: Arc<Mutex<Tunn>>,
    /// Agent's assigned tunnel IP
    pub assigned_ip: Ipv4Addr,
    /// Gateway-side local tunnel index used by boringtun to demultiplex receiver indexes.
    pub local_tunnel_index: u32,
    /// Current UDP endpoint (may change due to NAT)
    pub endpoint: Arc<RwLock<SocketAddr>>,
    /// Runtime route advertisement received from the agent
    pub route_state: Arc<RwLock<Option<RouteAdvertisementState>>>,
    /// Last time we received any packet from this peer
    pub last_packet_at: Arc<RwLock<Option<Instant>>>,
    /// Stream ID allocator
    pub stream_allocator: Arc<StreamIdAllocator>,
    /// Active streams (stream_id -> handle)
    pub active_streams: Arc<DashMap<u32, StreamHandle>>,
}

impl AgentPeer {
    /// Create a new agent peer
    pub fn new(
        config: WireGuardPeerConfig,
        gateway_private_key: wireguard_tunnel::StaticSecret,
        _gateway_ip: Ipv4Addr,
        local_tunnel_index: u32,
    ) -> Result<Self> {
        // Create WireGuard tunnel
        let tunn = Tunn::new(
            gateway_private_key,
            config.public_key,
            None, // No preshared key
            None, // No keepalive (we'll handle this manually)
            local_tunnel_index,
            None, // No rate limiter
        );

        Ok(Self {
            agent_id: config.agent_id,
            name: config.name,
            tunn: Arc::new(Mutex::new(tunn)),
            assigned_ip: config.assigned_ip,
            local_tunnel_index,
            endpoint: Arc::new(RwLock::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))),
            route_state: Arc::new(RwLock::new(None)),
            last_packet_at: Arc::new(RwLock::new(None)),
            stream_allocator: Arc::new(StreamIdAllocator::default()),
            active_streams: Arc::new(DashMap::new()),
        })
    }

    /// Check if this peer can route to a given IP address
    pub fn can_reach(&self, target_ip: IpAddr) -> bool {
        self.route_state()
            .map(|route_state| match target_ip {
                IpAddr::V4(ipv4) => route_state.subnets.iter().any(|subnet| subnet.contains(ipv4)),
                IpAddr::V6(_) => false,
            })
            .unwrap_or(false)
    }

    pub fn route_state(&self) -> Option<RouteAdvertisementState> {
        self.route_state.read().clone()
    }

    pub fn update_routes(&self, epoch: u64, subnets: Vec<Ipv4Network>) {
        let now_instant = Instant::now();
        let now_system = SystemTime::now();
        let received_at = self
            .route_state
            .read()
            .as_ref()
            .filter(|route_state| route_state.epoch == epoch)
            .map(|route_state| route_state.received_at)
            .unwrap_or(now_instant);

        *self.route_state.write() = Some(RouteAdvertisementState {
            epoch,
            subnets,
            received_at,
            updated_at: now_system,
        });
    }

    pub fn clear_routes(&self) {
        *self.route_state.write() = None;
    }

    pub fn mark_packet_received(&self) {
        *self.last_packet_at.write() = Some(Instant::now());
    }

    pub fn is_online(&self, offline_timeout: Duration) -> bool {
        self.last_packet_at
            .read()
            .is_some_and(|last_packet_at| last_packet_at.elapsed() <= offline_timeout)
    }

    pub fn clear_routes_if_offline(&self, offline_timeout: Duration) {
        if !self.is_online(offline_timeout) {
            self.clear_routes();
        }
    }

    /// Allocate a new stream ID
    pub fn allocate_stream_id(&self) -> Result<u32> {
        self.stream_allocator.allocate().map_err(Into::into)
    }

    /// Free a stream ID
    pub fn free_stream_id(&self, stream_id: u32) {
        self.stream_allocator.free(stream_id);
        self.active_streams.remove(&stream_id);
    }

    /// Send a relay message to the agent
    pub async fn send_relay_message(
        &self,
        gateway_ip: Ipv4Addr,
        msg: &RelayMessage,
        udp_socket: &tokio::net::UdpSocket,
    ) -> Result<()> {
        // Encode relay message
        let mut buf = BytesMut::new();
        msg.encode(&mut buf).context("Failed to encode relay message")?;

        // Encrypt with WireGuard
        let mut dst_buf = vec![0u8; 65536];
        let encrypted = {
            let mut tunn = self.tunn.lock();
            wireguard_tunnel::tunn_manager::send_relay_message(
                &mut tunn,
                gateway_ip,
                self.assigned_ip,
                &buf,
                &mut dst_buf,
            )
            .context("Failed to encrypt packet")?
        };

        // Send via UDP
        if let Some(packet) = encrypted {
            let endpoint = *self.endpoint.read();
            anyhow::ensure!(endpoint.port() != 0, "agent endpoint is unknown");
            udp_socket
                .send_to(&packet, endpoint)
                .await
                .context("Failed to send UDP packet")?;
        }

        Ok(())
    }

    /// Get the number of active streams
    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }
}

impl std::fmt::Debug for AgentPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentPeer")
            .field("agent_id", &self.agent_id)
            .field("name", &self.name)
            .field("assigned_ip", &self.assigned_ip)
            .field(
                "advertised_subnets",
                &self.route_state().map(|route_state| route_state.subnets),
            )
            .field("endpoint", &self.endpoint)
            .field("active_streams", &self.active_stream_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> AgentPeer {
        let gateway_private_key = wireguard_tunnel::StaticSecret::from([7u8; 32]);
        let agent_private_key = wireguard_tunnel::StaticSecret::from([9u8; 32]);

        AgentPeer::new(
            WireGuardPeerConfig {
                agent_id: Uuid::new_v4(),
                name: "test-agent".to_owned(),
                public_key: wireguard_tunnel::PublicKey::from(&agent_private_key),
                assigned_ip: Ipv4Addr::new(10, 10, 0, 2),
            },
            gateway_private_key,
            Ipv4Addr::new(10, 10, 0, 1),
            1,
        )
        .expect("test peer should build")
    }

    #[test]
    fn update_routes_replaces_subnets() {
        let peer = test_peer();

        peer.update_routes(10, vec!["192.168.100.0/24".parse().expect("valid CIDR")]);
        assert!(peer.can_reach(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 42))));
        assert!(!peer.can_reach(IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1))));

        peer.update_routes(11, vec!["10.20.0.0/16".parse().expect("valid CIDR")]);
        assert!(!peer.can_reach(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 42))));
        assert!(peer.can_reach(IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1))));
    }

    #[test]
    fn update_routes_preserves_received_at_for_same_epoch() {
        let peer = test_peer();

        peer.update_routes(10, vec!["192.168.100.0/24".parse().expect("valid CIDR")]);
        let first_state = peer.route_state().expect("route state should exist");

        std::thread::sleep(Duration::from_millis(5));

        peer.update_routes(10, vec!["10.20.0.0/16".parse().expect("valid CIDR")]);
        let second_state = peer.route_state().expect("route state should exist");

        assert_eq!(first_state.received_at, second_state.received_at);
        assert!(second_state.updated_at >= first_state.updated_at);
        assert_eq!(second_state.subnets, vec!["10.20.0.0/16".parse().expect("valid CIDR")]);
    }

    #[test]
    fn clear_routes_if_offline_drops_runtime_routes() {
        let peer = test_peer();

        peer.update_routes(10, vec!["192.168.100.0/24".parse().expect("valid CIDR")]);
        *peer.last_packet_at.write() = Some(Instant::now() - Duration::from_secs(31));

        peer.clear_routes_if_offline(Duration::from_secs(30));

        assert!(peer.route_state().is_none());
        assert!(!peer.can_reach(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 42))));
    }
}
