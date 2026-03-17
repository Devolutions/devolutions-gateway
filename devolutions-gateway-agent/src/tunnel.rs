use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex as BlockingMutex;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, trace, warn};
use tunnel_proto::{RelayMessage, RelayMsgType, RouteAdvertisement};
use uuid::Uuid;
use wireguard_tunnel::{Tunn, TunnResult};

use crate::config::RuntimeConfig;

/// Manages the WireGuard tunnel and relay protocol
pub struct TunnelManager {
    /// Agent ID
    agent_id: Uuid,

    /// Gateway UDP endpoint
    gateway_endpoint: SocketAddr,

    /// WireGuard tunnel state
    tunn: Arc<BlockingMutex<Tunn>>,

    /// UDP socket for WireGuard traffic
    udp_socket: Arc<UdpSocket>,

    /// Active TCP streams (stream_id -> OwnedWriteHalf)
    active_streams: Arc<DashMap<u32, Arc<AsyncMutex<OwnedWriteHalf>>>>,

    /// Agent's tunnel IP
    assigned_ip: std::net::Ipv4Addr,

    /// Gateway's tunnel IP
    gateway_ip: std::net::Ipv4Addr,

    /// Subnets currently advertised to Gateway
    advertise_subnets: Vec<ipnetwork::Ipv4Network>,

    /// Stable epoch for this agent process lifetime
    advertise_epoch: u64,
}

impl TunnelManager {
    /// Create a new tunnel manager
    pub async fn new(config: &RuntimeConfig) -> Result<Self> {
        // Bind UDP socket to any available port
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket")?;

        let local_addr = udp_socket.local_addr()?;
        info!(?local_addr, "UDP socket bound");

        let gateway_endpoint = tokio::net::lookup_host(&config.gateway_endpoint)
            .await
            .with_context(|| format!("Failed to resolve gateway endpoint {}", config.gateway_endpoint))?
            .next()
            .with_context(|| format!("No addresses resolved for gateway endpoint {}", config.gateway_endpoint))?;

        let persistent_keepalive = config
            .keepalive_interval
            .unwrap_or(25)
            .try_into()
            .context("keepalive_interval exceeds u16 range")?;

        // Create WireGuard tunnel
        let tunn = Tunn::new(
            config.private_key.clone(),
            config.gateway_public_key,
            None, // No preshared key
            Some(persistent_keepalive),
            0,    // Index (not used)
            None, // No rate limiter
        );

        Ok(Self {
            agent_id: config.agent_id,
            gateway_endpoint,
            tunn: Arc::new(BlockingMutex::new(tunn)),
            udp_socket: Arc::new(udp_socket),
            active_streams: Arc::new(DashMap::new()),
            assigned_ip: config.assigned_ip,
            gateway_ip: config.gateway_ip,
            advertise_subnets: config.advertise_subnets.clone(),
            advertise_epoch: rand::random(),
        })
    }

    /// Run the tunnel event loop
    pub async fn run(&self) -> Result<()> {
        info!(
            agent_id = %self.agent_id,
            gateway = %self.gateway_endpoint,
            "Starting WireGuard tunnel"
        );

        // Initiate handshake
        self.initiate_handshake().await?;
        self.send_route_advertisement().await?;

        let mut timer = tokio::time::interval(Duration::from_millis(250));
        let mut advertise_timer = tokio::time::interval(Duration::from_secs(5));
        let mut udp_buf = vec![0u8; 65536];
        let mut dst_buf = vec![0u8; 65536];

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    self.handle_timer(&mut dst_buf).await?;
                }

                _ = advertise_timer.tick() => {
                    self.send_route_advertisement().await?;
                }

                result = self.udp_socket.recv_from(&mut udp_buf) => {
                    let (n, addr) = result?;
                    if let Err(e) = self.handle_udp_packet(&udp_buf[..n], addr, &mut dst_buf).await {
                        warn!(error = ?e, "Failed to handle UDP packet");
                    }
                }
            }
        }
    }

    /// Initiate WireGuard handshake
    async fn initiate_handshake(&self) -> Result<()> {
        let mut dst_buf = vec![0u8; 65536];

        info!("Initiating WireGuard handshake with gateway");

        // Trigger handshake by trying to encapsulate a dummy packet
        // This will cause WireGuard to initiate handshake if needed
        let dummy_packet = wireguard_tunnel::ip_packet::build_ip_packet(
            self.assigned_ip,
            self.gateway_ip,
            &[0u8; 0], // Empty payload to trigger handshake
        )?;

        let packets = {
            let mut tunn = self.tunn.lock();
            tunn.update_timers(&mut dst_buf);

            let mut packets = Vec::new();

            // Try to encapsulate - this will trigger handshake initiation
            match tunn.encapsulate(&dummy_packet, &mut dst_buf) {
                TunnResult::WriteToNetwork(encrypted) => {
                    packets.push(Bytes::copy_from_slice(encrypted));
                }
                TunnResult::Err(e) => {
                    warn!(?e, "Encapsulate returned error (expected during handshake)");
                }
                TunnResult::Done => {}
                _ => {}
            }

            // Flush any pending output (handshake packets)
            loop {
                match tunn.decapsulate(None, &[], &mut dst_buf) {
                    TunnResult::WriteToNetwork(encrypted) => {
                        packets.push(Bytes::copy_from_slice(encrypted));
                    }
                    TunnResult::Done => break,
                    TunnResult::Err(e) => {
                        anyhow::bail!("Handshake initiation error: {:?}", e);
                    }
                    _ => {}
                }
            }
            packets
        };

        // Send handshake packets
        info!("Generated {} handshake packets", packets.len());
        for (i, packet) in packets.iter().enumerate() {
            info!(packet_index = i, packet_len = packet.len(), ?self.gateway_endpoint, "Sending handshake packet");
            self.udp_socket.send_to(packet, self.gateway_endpoint).await?;
        }

        debug!("Handshake initiation packets sent");
        Ok(())
    }

    /// Handle incoming UDP packet from gateway
    async fn handle_udp_packet(&self, packet: &[u8], peer_addr: SocketAddr, dst: &mut [u8]) -> Result<()> {
        // Decrypt with WireGuard and extract relay message (if any)
        let (relay_msg_opt, handshake_response) = {
            let mut tunn = self.tunn.lock();
            match tunn.decapsulate(Some(peer_addr.ip()), packet, dst) {
                TunnResult::WriteToTunnelV4(ip_packet, _) => {
                    // Extract relay protocol payload
                    let payload = wireguard_tunnel::ip_packet::extract_payload(ip_packet)
                        .context("Failed to extract relay payload from IP packet")?;

                    // Decode relay message
                    let relay_msg = RelayMessage::decode(&payload[..]).context("Failed to decode relay message")?;

                    trace!(
                        stream_id = relay_msg.stream_id,
                        msg_type = ?relay_msg.msg_type,
                        "Received relay message"
                    );

                    (Some(relay_msg), None)
                }
                TunnResult::WriteToNetwork(response) => {
                    // Handshake response
                    (None, Some(Bytes::copy_from_slice(response)))
                }
                TunnResult::Done => (None, None),
                TunnResult::Err(e) => {
                    anyhow::bail!("WireGuard decapsulate error: {:?}", e);
                }
                _ => (None, None),
            }
        }; // tunn lock released

        // Send handshake response if any
        if let Some(response) = handshake_response {
            self.udp_socket.send_to(&response, peer_addr).await?;
        }

        // Handle relay message if we got one
        if let Some(relay_msg) = relay_msg_opt {
            self.handle_relay_message(relay_msg).await?;
        }

        // CRITICAL: Flush loop (boringtun requirement)
        let flush_packets = {
            let mut tunn = self.tunn.lock();
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
        }; // tunn lock released

        // Send flush packets
        for packet in flush_packets {
            self.udp_socket.send_to(&packet, peer_addr).await?;
        }

        Ok(())
    }

    /// Handle timer tick (WireGuard keepalives, rekeys, etc.)
    async fn handle_timer(&self, dst: &mut [u8]) -> Result<()> {
        let packets = {
            let mut tunn = self.tunn.lock();
            wireguard_tunnel::tunn_manager::handle_timer_tick(&mut tunn, dst)
                .context("timer tick failed")?
        };

        for packet in packets {
            self.udp_socket.send_to(&packet, self.gateway_endpoint).await?;
        }

        Ok(())
    }

    /// Handle relay protocol message from gateway
    async fn handle_relay_message(&self, msg: RelayMessage) -> Result<()> {
        match msg.msg_type {
            RelayMsgType::Connect => {
                // Gateway wants us to connect to a target
                let target = String::from_utf8(msg.payload.to_vec()).context("Invalid UTF-8 in CONNECT target")?;

                info!(
                    stream_id = msg.stream_id,
                    target = %target,
                    "Received CONNECT request"
                );

                // Spawn task to handle connection
                let self_clone = Self {
                    agent_id: self.agent_id,
                    gateway_endpoint: self.gateway_endpoint,
                    tunn: Arc::clone(&self.tunn),
                    udp_socket: Arc::clone(&self.udp_socket),
                    active_streams: Arc::clone(&self.active_streams),
                    assigned_ip: self.assigned_ip,
                    gateway_ip: self.gateway_ip,
                    advertise_subnets: self.advertise_subnets.clone(),
                    advertise_epoch: self.advertise_epoch,
                };

                tokio::spawn(async move {
                    if let Err(e) = self_clone.handle_connect(msg.stream_id, &target).await {
                        error!(
                            stream_id = msg.stream_id,
                            error = ?e,
                            "Failed to handle CONNECT"
                        );

                        // Send ERROR message
                        let error_msg = format!("{:#}", e);
                        if let Ok(err_relay_msg) = RelayMessage::error(msg.stream_id, &error_msg) {
                            let _ = self_clone.send_relay_message(&err_relay_msg).await;
                        }
                    }
                });
            }

            RelayMsgType::Data => {
                // Gateway sending data to forward to target
                if let Some(stream) = self.active_streams.get(&msg.stream_id) {
                    let stream = Arc::clone(&stream);
                    let mut tcp = stream.lock().await;
                    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut *tcp, &msg.payload).await {
                        warn!(
                            stream_id = msg.stream_id,
                            error = ?e,
                            "Failed to write to TCP stream"
                        );
                        self.active_streams.remove(&msg.stream_id);

                        let error_msg = format!("Failed to write to target stream: {e}");
                        if let Ok(error_relay_msg) = RelayMessage::error(msg.stream_id, &error_msg) {
                            let _ = self.send_relay_message(&error_relay_msg).await;
                        }
                    }
                }
            }

            RelayMsgType::Close => {
                // Gateway closing stream
                debug!(stream_id = msg.stream_id, "Received CLOSE from gateway");
                self.active_streams.remove(&msg.stream_id);
            }

            RelayMsgType::Connected | RelayMsgType::Error => {
                // These are agent -> gateway messages, should not receive them
                warn!(
                    stream_id = msg.stream_id,
                    msg_type = ?msg.msg_type,
                    "Received unexpected message type from gateway"
                );
            }

            RelayMsgType::RouteAdvertise => {
                warn!(
                    stream_id = msg.stream_id,
                    "Received unexpected ROUTE_ADVERTISE from gateway"
                );
            }
        }

        Ok(())
    }

    /// Handle CONNECT message: establish TCP connection and start bridge
    async fn handle_connect(&self, stream_id: u32, target: &str) -> Result<()> {
        let connect_target = normalize_connect_target(target);
        let socket_addr = resolve_and_validate_target(&self.advertise_subnets, connect_target)
            .await
            .with_context(|| format!("Target {} is not allowed for this agent", target))?;

        // Connect to target
        let tcp_stream = TcpStream::connect(socket_addr)
            .await
            .with_context(|| format!("Failed to connect to {}", target))?;

        info!(
            stream_id,
            target = %target,
            "Successfully connected to target"
        );

        // Split the stream for bidirectional communication
        let (read_half, write_half) = tcp_stream.into_split();

        // Store write half for gateway->target direction
        self.active_streams
            .insert(stream_id, Arc::new(AsyncMutex::new(write_half)));

        // Send CONNECTED message
        let connected_msg = RelayMessage::connected(stream_id).context("Failed to create CONNECTED message")?;
        self.send_relay_message(&connected_msg).await?;

        // Start bidirectional bridge (TCP -> relay) for read direction
        let self_clone = Self {
            agent_id: self.agent_id,
            gateway_endpoint: self.gateway_endpoint,
            tunn: Arc::clone(&self.tunn),
            udp_socket: Arc::clone(&self.udp_socket),
            active_streams: Arc::clone(&self.active_streams),
            assigned_ip: self.assigned_ip,
            gateway_ip: self.gateway_ip,
            advertise_subnets: self.advertise_subnets.clone(),
            advertise_epoch: self.advertise_epoch,
        };

        tokio::spawn(async move {
            if let Err(e) = self_clone.tcp_read_to_relay_bridge(stream_id, read_half).await {
                self_clone.active_streams.remove(&stream_id);
                debug!(
                    stream_id,
                    error = ?e,
                    "TCP to relay bridge terminated"
                );

                if let Ok(close_msg) = RelayMessage::close(stream_id) {
                    let _ = self_clone.send_relay_message(&close_msg).await;
                }
            }
        });

        Ok(())
    }

    /// Bridge TCP stream to relay protocol (read from TCP, send DATA to gateway)
    async fn tcp_read_to_relay_bridge(&self, stream_id: u32, mut read_half: OwnedReadHalf) -> Result<()> {
        use tokio::io::AsyncReadExt;

        let mut buf = vec![0u8; 8192];

        loop {
            let n = read_half.read(&mut buf).await?;

            if n == 0 {
                // EOF, send CLOSE
                debug!(stream_id, "TCP stream EOF, sending CLOSE");
                let close_msg = RelayMessage::close(stream_id)?;
                self.send_relay_message(&close_msg).await?;
                self.active_streams.remove(&stream_id);
                break;
            }

            // Send DATA message
            let data_msg = RelayMessage::data(stream_id, Bytes::copy_from_slice(&buf[..n]))?;
            self.send_relay_message(&data_msg).await?;
        }

        Ok(())
    }

    /// Send a relay message to gateway via WireGuard tunnel
    async fn send_relay_message(&self, msg: &RelayMessage) -> Result<()> {
        // Encode relay message
        let mut buf = bytes::BytesMut::new();
        msg.encode(&mut buf).context("Failed to encode relay message")?;

        // Encrypt with WireGuard
        let mut dst_buf = vec![0u8; 65536];
        let encrypted = {
            let mut tunn = self.tunn.lock();
            wireguard_tunnel::tunn_manager::send_relay_message(
                &mut tunn,
                self.assigned_ip,
                self.gateway_ip,
                &buf,
                &mut dst_buf,
            )
            .context("Failed to encrypt packet")?
        };

        // Send via UDP
        if let Some(packet) = encrypted {
            self.udp_socket
                .send_to(&packet, self.gateway_endpoint)
                .await
                .context("Failed to send UDP packet")?;
        }

        Ok(())
    }

    async fn send_route_advertisement(&self) -> Result<()> {
        let advertisement = RouteAdvertisement::new(self.advertise_epoch, self.advertise_subnets.clone());
        let msg = RelayMessage::route_advertise(&advertisement).context("Failed to create route advertisement")?;
        self.send_relay_message(&msg).await?;
        debug!(
            agent_id = %self.agent_id,
            epoch = self.advertise_epoch,
            subnet_count = advertisement.subnets.len(),
            "Sent route advertisement"
        );
        Ok(())
    }
}

fn normalize_connect_target(target: &str) -> &str {
    target.split_once("://").map(|(_, rest)| rest).unwrap_or(target)
}

async fn resolve_and_validate_target(advertise_subnets: &[ipnetwork::Ipv4Network], target: &str) -> Result<SocketAddr> {
    let resolved = tokio::net::lookup_host(target)
        .await
        .with_context(|| format!("Failed to resolve target {}", target))?
        .collect::<Vec<_>>();

    resolved
        .into_iter()
        .find(|addr| target_is_allowed(advertise_subnets, addr.ip()))
        .with_context(|| format!("No allowed target addresses resolved for {}", target))
}

fn target_is_allowed(advertise_subnets: &[ipnetwork::Ipv4Network], target_ip: IpAddr) -> bool {
    match target_ip {
        IpAddr::V4(ipv4) => advertise_subnets.iter().any(|subnet| subnet.contains(ipv4)),
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use ipnetwork::Ipv4Network;

    use super::{normalize_connect_target, target_is_allowed};

    #[test]
    fn normalize_connect_target_strips_scheme() {
        assert_eq!(normalize_connect_target("tcp://localhost:8080"), "localhost:8080");
        assert_eq!(normalize_connect_target("http://127.0.0.1:80"), "127.0.0.1:80");
    }

    #[test]
    fn normalize_connect_target_keeps_plain_host_port() {
        assert_eq!(normalize_connect_target("localhost:8080"), "localhost:8080");
    }

    #[test]
    fn target_is_allowed_requires_ipv4_in_advertised_subnets() {
        let advertise_subnets = vec![Ipv4Network::new("127.0.0.0".parse().expect("valid ip"), 8).expect("valid cidr")];

        assert!(target_is_allowed(
            &advertise_subnets,
            "127.0.0.1".parse().expect("valid ip")
        ));
        assert!(!target_is_allowed(
            &advertise_subnets,
            "10.0.0.1".parse().expect("valid ip")
        ));
        assert!(!target_is_allowed(&advertise_subnets, "::1".parse().expect("valid ip")));
    }
}
