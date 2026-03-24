# Agent Tunnel QUIC Rewrite Notes

## Position

I think the QUIC-based agent tunnel should be implemented as a new design on a new branch from `master`, not as an incremental evolution of `fix/wireguard-agent-routing-hardening`.

The existing WireGuard branch is still valuable, but mainly as:

- a product semantics reference
- a routing and enrollment reference
- a source of test scenarios
- a source of failure cases to avoid repeating

It should not be treated as the implementation base for QUIC v1.

## Why I Favor a Rewrite

The current implementation is not just "using WireGuard as a transport". It is structurally shaped around WireGuard concepts across the whole stack.

Examples in the current codebase:

- Gateway runtime state directly stores `wireguard_listener` in [devolutions-gateway/src/lib.rs](D:\devolutions-gateway\devolutions-gateway\src\lib.rs).
- Service bootstrap directly initializes `WireGuardListener` in [devolutions-gateway/src/service.rs](D:\devolutions-gateway\devolutions-gateway\src\service.rs).
- Runtime config uses `WireGuardConf` and `WireGuardPeerConfig` in [devolutions-gateway/src/config.rs](D:\devolutions-gateway\devolutions-gateway\src\config.rs).
- Agent persistence stores WireGuard identity and tunnel addressing in [devolutions-gateway/src/agent_store.rs](D:\devolutions-gateway\devolutions-gateway\src\agent_store.rs).
- Enrollment API returns WireGuard-specific fields in [devolutions-gateway/src/api/agents.rs](D:\devolutions-gateway\devolutions-gateway\src\api\agents.rs).
- Agent config is WireGuard-shaped in [devolutions-gateway-agent/src/config.rs](D:\devolutions-gateway\devolutions-gateway-agent\src\config.rs).
- The relay data path simulates streams on top of datagrams with `stream_id`, `DATA`, and `CLOSE` in [crates/tunnel-proto/src/message.rs](D:\devolutions-gateway\crates\tunnel-proto\src\message.rs).
- `VirtualTcpStream` is a WireGuard relay shim, not a general tunnel abstraction, in [devolutions-gateway/src/wireguard/stream.rs](D:\devolutions-gateway\devolutions-gateway\src\wireguard\stream.rs).

This matters because QUIC changes the transport model, not just the crypto primitive.

### Deep Dive: WireGuard-Specific Constraints

The current architecture has fundamental reliability issues rooted in the UDP-based transport:

**Agent-side packet flow** (from [devolutions-gateway-agent/src/tunnel.rs](D:\devolutions-gateway\devolutions-gateway-agent\src\tunnel.rs)):
```rust
TunnelManager {
    tunn: Arc<BlockingMutex<Tunn>>,  // boringtun - no retransmit
    udp_socket: Arc<UdpSocket>,       // raw UDP - lossy
    active_streams: Arc<DashMap<u32, Arc<AsyncMutex<OwnedWriteHalf>>>>,
}
```

**Problem**: TCP data → RelayMessage::Data → IPv4 packet (Protocol 253) → WireGuard encrypt → UDP packet. The tunnel does not preserve a single reliable byte stream. Packet loss at the relay layer turns into corruption, instability, or session breakage instead of orderly retransmission by the tunnel transport.

**Gateway-side multiplexing** (from [devolutions-gateway/src/wireguard/listener.rs](D:\devolutions-gateway\devolutions-gateway\src\wireguard\listener.rs)):
```rust
// ~1600 lines implementing:
// - WireGuard handshake parsing
// - Peer index mapping (receiver_idx → agent_id)
// - IP packet decapsulation
// - RelayMessage extraction from Protocol 253 packets
// - mpsc channel bridging to VirtualTcpStream
```

All of this complexity exists solely to work around WireGuard's datagram nature. QUIC eliminates this entire layer.

With QUIC:

- a single long-lived connection already exists
- multiplexing is native
- reliability is native
- flow control is native
- per-session streams are native
- stream close is native

Trying to preserve too much of the WireGuard runtime would keep the old wrong abstractions alive.

## What Should Be Reused Conceptually

These ideas from the WireGuard branch are good and should survive the rewrite:

- `jet_agent_id` remains the explicit switch for agent routing
- enrollment remains token-based
- the agent advertises reachable subnets
- Gateway tracks agent online/offline state
- Gateway validates that a chosen agent can reach the requested target
- Gateway exposes agent status and route visibility to UI and APIs
- the forwarding path still wants an `AsyncRead + AsyncWrite` server-side stream abstraction

In short:

- keep the control plane semantics
- replace the transport and identity model

### Concrete Examples to Preserve

**Route advertisement logic** (from [devolutions-gateway/src/wireguard/peer.rs](D:\devolutions-gateway\devolutions-gateway\src\wireguard\peer.rs)):
```rust
pub fn can_reach(&self, target_ip: IpAddr) -> bool {
    self.route_state()
        .map(|route_state| match target_ip {
            IpAddr::V4(ipv4) => route_state.subnets.iter()
                .any(|subnet| subnet.contains(ipv4)),
            IpAddr::V6(_) => false,
        })
        .unwrap_or(false)
}
```
✅ **Strong candidate for semantic reuse** - the algorithm and validation logic can be preserved, though surrounding type models and lifecycle handling will need fresh design appropriate to QUIC.

**Agent selection for routing** (from [devolutions-gateway/src/wireguard/listener.rs](D:\devolutions-gateway\devolutions-gateway\src\wireguard\listener.rs)):
```rust
pub fn select_agent_for_target(&self, target_ip: IpAddr) -> Option<Arc<AgentPeer>> {
    self.registry
        .peers
        .iter()
        .filter(|e| e.value().is_online(AGENT_OFFLINE_TIMEOUT))
        .filter_map(|entry| {
            let route_state = peer.route_state()?;
            let matches = /* subnet check */;
            if matches {
                Some((route_state.received_at, peer))
            } else {
                None
            }
        })
        .max_by_key(|(received_at, _)| *received_at)
        .map(|(_, peer)| peer)
}
```
✅ **Preserve this routing hardening logic semantically** - the algorithm for selecting agents with overlapping routes and handling offline agents is proven correct and should be reused, though the implementation will be adapted to QUIC data structures.

**Enrollment token mechanism** (from [devolutions-gateway/src/enrollment_store.rs](D:\devolutions-gateway\devolutions-gateway\src\enrollment_store.rs)):

The actual implementation uses hashed persisted token records. The token generation and SHA-256 based verification flow should be preserved. Only the enrollment response (what's returned to the agent after successful verification) needs to change from WireGuard keys to TLS certificate material.

✅ **Preserve token issuance and validation semantics** - the cryptographic token flow is sound and should be reused.

**Agent registry storage** (from [devolutions-gateway/src/agent_store.rs](D:\devolutions-gateway\devolutions-gateway\src\agent_store.rs)):
```rust
pub struct AgentRecord {
    pub agent_id: Uuid,
    pub name: String,
    pub public_key: String,        // ❌ Change to cert_fingerprint
    pub assigned_ip: Ipv4Addr,     // ❌ Remove - QUIC doesn't need tunnel IPs
    pub enrolled_at_unix: u64,
}
```
⚠️ **Keep the storage pattern**, change the fields to QUIC-appropriate identity.

## What Should Not Be Reused

These parts are WireGuard-specific and should be discarded for QUIC v1:

- tunnel IP allocation
- fake IPv4 packet wrapping
- boringtun-specific event loops
- WireGuard public key enrollment identity
- `assigned_ip` as a core agent attribute
- `DATA` and `CLOSE` framing as a transport requirement
- `stream_id` as a transport-level multiplexing mechanism
- `WireGuardListener`, `WireGuardHandle`, and `VirtualTcpStream` as the new architecture basis

## Important Terminology Correction

If v1 uses raw QUIC streams with custom control framing, it is not full MASQUE.

It is more accurate to call it one of:

- QUIC-based agent tunnel
- MASQUE-inspired agent tunnel
- QUIC tunnel v1

This matters because full MASQUE would imply at least some real HTTP/3 Extended CONNECT semantics. If v1 does not implement that, the project should not claim RFC-level MASQUE compliance.

## Branch Recommendation

I recommend:

- start from `master`
- create a new branch such as `feat/quic-agent-tunnel-v1`

I do not recommend:

- continuing directly on `fix/wireguard-agent-routing-hardening`
- first refactoring all WireGuard code into abstract transport interfaces and then swapping the backend

That intermediate refactor would likely consume time while preserving shapes we should stop using.

## Practical Architecture for v1

### Gateway side

- New module namespace, for example `devolutions-gateway/src/agent_tunnel/`
- Long-lived QUIC listener and agent connection manager
- Control stream per connected agent
- One QUIC bidirectional stream per proxied TCP session
- Route registry and agent registry independent from WireGuard terms
- New server-side stream wrapper backed by QUIC streams instead of relay-message mpsc queues

**Key implementation changes (ILLUSTRATIVE PSEUDOCODE):**
```rust
// OLD: WireGuard-based (devolutions-gateway/src/lib.rs)
pub struct DgwState {
    wireguard_listener: Option<Arc<WireGuardHandle>>,  // ❌ Remove
}

// NEW: QUIC-based (conceptual structure)
pub struct DgwState {
    agent_tunnel_listener: Option<Arc<AgentTunnelListener>>,  // ✅ Add
}
```

**Listener architecture (CONCEPTUAL MODULE SKETCH - not final API):**
```rust
// Illustrative structure - actual QUIC library integration will differ
pub struct AgentTunnelListener {
    quic_endpoint: quiche::Connection,
    agent_registry: Arc<AgentRegistry>,
    control_streams: Arc<DashMap<Uuid, ControlStreamHandle>>,
}

impl AgentTunnelListener {
    pub async fn accept_agent_connection(&self) -> Result<QuicAgent> {
        // 1. Accept QUIC connection
        // 2. Verify mTLS client certificate
        // 3. Extract agent_id from certificate
        // 4. Register in agent_registry
        // 5. Spawn control stream handler
        // 6. Spawn data stream acceptor
    }

    pub async fn open_session_to_agent(
        &self,
        agent_id: Uuid,
        target: TargetAddr,
    ) -> Result<QuicStream> {
        // 1. Get agent from registry
        // 2. Validate agent can reach target (existing logic)
        // 3. Open new QUIC bidirectional stream
        // 4. Send Connect message
        // 5. Wait for Connected response
        // 6. Return stream (implements AsyncRead + AsyncWrite)
    }
}
```

### Agent side

- Long-lived outbound QUIC connection to Gateway
- Control stream opened immediately after connect
- Periodic heartbeat or liveness signal on the control stream
- Route advertisement on the control stream
- For each incoming data stream:
  - read initial connect request
  - validate target against `advertise_subnets`
  - open TCP socket
  - bridge QUIC stream to TCP stream

**Key implementation changes (ILLUSTRATIVE PSEUDOCODE):**
```rust
// OLD: WireGuard-based (devolutions-gateway-agent/src/tunnel.rs)
pub struct TunnelManager {
    tunn: Arc<BlockingMutex<Tunn>>,              // ❌ Remove boringtun
    udp_socket: Arc<UdpSocket>,                  // ❌ Remove raw UDP
    active_streams: Arc<DashMap<u32, ...>>,      // ❌ Remove manual stream tracking
}

// NEW: QUIC-based (conceptual - actual API depends on chosen library)
pub struct QuicTunnelClient {
    quic_connection: quiche::Connection,         // ✅ Single QUIC connection
    control_stream: ControlStreamHandle,         // ✅ Dedicated control channel
    advertise_subnets: Vec<Ipv4Network>,
    advertise_epoch: u64,
}

impl QuicTunnelClient {
    pub async fn run(&self) -> Result<()> {
        // Main event loop
        loop {
            tokio::select! {
                // Handle incoming data streams from Gateway
                Some(stream) = self.accept_stream() => {
                    tokio::spawn(self.handle_session_stream(stream));
                }

                // Send periodic route advertisements
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    self.advertise_routes().await?;
                }

                // Send heartbeat
                _ = tokio::time::sleep(Duration::from_secs(15)) => {
                    self.send_heartbeat().await?;
                }
            }
        }
    }

    async fn handle_session_stream(&self, mut stream: QuicStream) -> Result<()> {
        // 1. Read Connect message
        let connect_msg = ConnectMessage::decode(&mut stream).await?;

        // 2. Validate target is in advertised subnets
        if !self.can_reach(&connect_msg.target) {
            return Err(Error::Unauthorized);
        }

        // 3. Open TCP connection to target
        let tcp_stream = TcpStream::connect(&connect_msg.target).await?;

        // 4. Send Connected response
        ConnectedMessage::encode(&mut stream).await?;

        // 5. Bridge QUIC stream ↔ TCP stream (zero-copy)
        // NO DATA FRAMING NEEDED - QUIC stream IS the reliable byte stream!
        tokio::io::copy_bidirectional(&mut stream, &mut tcp_stream).await?;

        Ok(())
    }
}
```

### Enrollment

Keep:

- single-use enrollment token
- requested name
- UI-generated enrollment string

Change:

- issue QUIC/mTLS credentials instead of WireGuard peer data
- stop returning `gateway_public_key`, `assigned_ip`, and `gateway_ip`

## Recommended Protocol Shape

### Control stream

Use structured messages for:

- `RouteAdvertisement`
- `Ping`
- `Pong`
- `AgentStatus`
- optional future `Reconfigure`

This can live in a new crate such as `crates/agent-tunnel-proto`.

**Concrete protocol definition:**
```rust
// crates/agent-tunnel-proto/src/control.rs

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Agent → Gateway: Advertise reachable subnets
    RouteAdvertise {
        protocol_version: u16,  // Protocol version (e.g., 1)
        epoch: u64,
        subnets: Vec<Ipv4Network>,
    },

    /// Agent → Gateway: Heartbeat (keepalive)
    Heartbeat {
        protocol_version: u16,
        timestamp: u64,
        active_streams: u32,
    },

    /// Gateway → Agent: Heartbeat acknowledgment
    HeartbeatAck {
        protocol_version: u16,
        timestamp: u64,
    },

    /// Gateway → Agent: Request agent status
    StatusRequest {
        protocol_version: u16,
    },

    /// Agent → Gateway: Agent status response
    StatusResponse {
        protocol_version: u16,
        version: String,
        uptime_secs: u64,
        memory_usage_mb: u64,
    },
}

impl ControlMessage {
    pub async fn encode<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        // Length-prefixed bincode encoding
        let payload = bincode::serialize(self)?;
        writer.write_u32(payload.len() as u32).await?;
        writer.write_all(&payload).await?;
        Ok(())
    }

    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let len = reader.read_u32().await?;
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf).await?;
        Ok(bincode::deserialize(&buf)?)
    }
}
```

**Why bincode + length prefix:**
- Efficient binary encoding (smaller than JSON/protobuf)
- Type-safe Rust serialization
- Simple framing (4-byte length + payload)
- Control messages are infrequent, so encoding overhead is negligible

**IMPORTANT**: If using `bincode`, the protocol MUST include:
- A **protocol version field** in every message (see `protocol_version: u16` in examples above)
- An explicit **compatibility policy** between agent and gateway versions
- Version negotiation during connection establishment (e.g., gateway rejects unsupported versions)

**Example version handling:**
```rust
const CURRENT_PROTOCOL_VERSION: u16 = 1;
const MIN_SUPPORTED_VERSION: u16 = 1;

fn validate_message_version(msg_version: u16) -> Result<()> {
    anyhow::ensure!(
        msg_version >= MIN_SUPPORTED_VERSION,
        "Protocol version {} too old (min: {})", msg_version, MIN_SUPPORTED_VERSION
    );
    anyhow::ensure!(
        msg_version <= CURRENT_PROTOCOL_VERSION,
        "Protocol version {} too new (current: {})", msg_version, CURRENT_PROTOCOL_VERSION
    );
    Ok(())
}
```

Without version management, binary format evolution becomes brittle.

### Data streams

Each proxied connection gets a dedicated QUIC bidirectional stream.

Suggested behavior:

1. Gateway opens a bidi stream.
2. Gateway sends a small connect request frame with target metadata.
3. Agent replies with connect success or connect failure.
4. After that, both sides exchange raw bytes directly.
5. QUIC stream close maps to proxied connection close.

I do not recommend carrying old relay `DATA` or `CLOSE` frames on top of QUIC streams.

**Concrete session protocol:**
```rust
// crates/agent-tunnel-proto/src/connect.rs

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectMessage {
    pub protocol_version: u16,  // Protocol version (e.g., 1)
    pub target: String,  // "192.168.1.100:22" or "hostname:port"
    pub session_id: Uuid, // For logging/correlation
    pub protocol: String, // "ssh", "rdp", "vnc", etc.
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectResponse {
    Success { protocol_version: u16 },
    Error { protocol_version: u16, reason: String },
}

impl ConnectMessage {
    pub async fn send<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        // Same length-prefix encoding as control messages
        let payload = bincode::serialize(self)?;
        writer.write_u32(payload.len() as u32).await?;
        writer.write_all(&payload).await?;
        Ok(())
    }
}

// After Connect/Connected exchange, the stream becomes a raw byte pipe:
// Gateway: [Connect msg] → [raw TCP bytes] →
// Agent:   ← [Connected response] ← [raw TCP bytes]
```

**Critical difference from WireGuard POC:**
```rust
// OLD (tunnel-proto): Manual DATA framing
RelayMessage::Data {
    stream_id: u32,
    payload: Vec<u8>,  // ❌ Unnecessary overhead!
}

// NEW: No framing after handshake
// QUIC stream = reliable byte stream
// Just copy bytes: tcp.read() → quic_stream.write()
```

**Performance benefits:**
- Less unnecessary application framing
- Fewer copies and less buffer choreography
- Simpler and more direct byte forwarding
- QUIC handles packetization, reliability, and flow control at the transport layer

The quantitative impact will be measured in Phase 4 testing.

## What the Existing Branch Is Still Good For

Even if implementation starts from scratch, the WireGuard branch remains useful for:

- route advertisement rules
- target validation behavior
- explicit `jet_agent_id` opt-in routing
- agent status API expectations
- enrollment UX expectations
- end-to-end manual test flows

The right mindset is:

- inherit the product contract
- do not inherit the transport implementation

## Suggested Module Layout

### Gateway

- `devolutions-gateway/src/agent_tunnel/mod.rs`
- `devolutions-gateway/src/agent_tunnel/config.rs`
- `devolutions-gateway/src/agent_tunnel/listener.rs`
- `devolutions-gateway/src/agent_tunnel/registry.rs`
- `devolutions-gateway/src/agent_tunnel/stream.rs`
- `devolutions-gateway/src/agent_tunnel/enrollment.rs`

### Shared proto

- `crates/agent-tunnel-proto/src/lib.rs`
- `crates/agent-tunnel-proto/src/control.rs`
- `crates/agent-tunnel-proto/src/connect.rs`

### Agent client

- keep `devolutions-gateway-agent` initially as the host for the new tunnel client
- later decide whether to split a `cdylib` for real Devolutions Agent integration

## Scope I Would Enforce for v1

To stay realistic for a two-month project, I would constrain v1 to:

- Linux agent first
- single Gateway instance
- TCP only
- raw QUIC streams, not full MASQUE
- standalone Rust agent binary first
- basic mTLS enrollment
- route advertisement, heartbeat, reconnect, and multiple concurrent streams

I would explicitly defer:

- full RFC MASQUE support
- HTTP/3 path-based routing semantics
- Windows host integration into the Devolutions Agent product
- HA clustering
- IPv6

## Risk Assessment

### Main technical risks

- selecting and integrating the QUIC stack cleanly
- certificate issuance and rotation design
- reconnect and state recovery behavior
- operational coexistence with existing HTTPS/TLS listener expectations
- test coverage for long-running sessions and high-throughput flows

### Main project risk

The biggest project risk is not QUIC itself. It is trying to solve too many end states in one effort:

- new transport
- new enrollment identity model
- new server runtime
- new product integration host
- possible MASQUE compliance

That should be split.

## Suggested Delivery Sequence

1. Build a new shared control protocol crate.
2. Build Gateway-side QUIC listener and agent registry.
3. Build standalone Rust agent QUIC client.
4. Reconnect `connect_target()` to the new agent tunnel path.
5. Replace enrollment DTOs and persistence with QUIC-oriented identity.
6. Add end-to-end tests for SSH and large data transfer scenarios.
7. Only after that, decide whether to integrate into the Devolutions Agent host process.

### Phase 0: QUIC Stack Integration (Week 1)

**Goal:** Validate quiche works with our architecture and prove basic connectivity.

**Deliverables:**
```rust
// Minimal proof-of-concept
// gateway-poc/src/main.rs
use quiche;
use tokio;

async fn gateway_poc() {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file("gateway-cert.pem")?;
    config.load_priv_key_from_pem_file("gateway-key.pem")?;
    config.verify_peer(true);  // Require client cert

    let socket = UdpSocket::bind("0.0.0.0:4433").await?;
    // Accept QUIC connection, verify mTLS, open stream, echo bytes
}

// agent-poc/src/main.rs
async fn agent_poc() {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file("agent-cert.pem")?;
    config.load_priv_key_from_pem_file("agent-key.pem")?;

    // Connect to gateway, send/recv on a stream
}
```

**Validation criteria:**
- [ ] Can establish QUIC connection with mTLS
- [ ] Can open bidirectional stream
- [ ] Can send large data volume (1GB+) without loss
- [ ] Measure and compare latency overhead against direct TCP and WireGuard POC
- [ ] `top` command over QUIC-proxied SSH doesn't crash (critical reliability test)
- [ ] **Prove deployment feasibility**: QUIC service can be hosted in actual target environment

**Code reference:** Study existing enrollment flow in [devolutions-gateway/src/enrollment_store.rs](D:\devolutions-gateway\devolutions-gateway\src\enrollment_store.rs) for token generation patterns.

### Phase 1: Protocol Crate (Week 1-2)

**Goal:** Define wire protocol independent of transport.

**Deliverables:**
- `crates/agent-tunnel-proto/` with control and session message types
- Comprehensive unit tests for encode/decode
- Property-based tests with proptest for fuzzing

**Code to write:**
```rust
// crates/agent-tunnel-proto/src/lib.rs
pub mod control;
pub mod session;
pub mod error;

// Re-export main types
pub use control::ControlMessage;
pub use session::{ConnectMessage, ConnectResponse};
```

**Tests to add:**
```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn control_message_roundtrip(msg: ControlMessage) {
            let mut buf = Vec::new();
            msg.encode(&mut buf).unwrap();
            let decoded = ControlMessage::decode(&buf[..]).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn large_route_advertisement() {
        // Test with 1000+ subnets (stress test)
        let subnets: Vec<_> = (0..1000)
            .map(|i| format!("10.{}.0.0/16", i % 256).parse().unwrap())
            .collect();

        let msg = ControlMessage::RouteAdvertise {
            epoch: 42,
            subnets,
        };

        // Should encode/decode without panic or excessive memory
    }
}
```

### Phase 2: Gateway Listener (Week 2-3)

**Goal:** Accept QUIC connections from agents, manage registry.

**Deliverables:**
- `devolutions-gateway/src/agent_tunnel/listener.rs`
- `devolutions-gateway/src/agent_tunnel/registry.rs`
- Integration with existing `DgwState`

**Key integration point:**
```rust
// devolutions-gateway/src/lib.rs
pub struct DgwState {
    pub conf_handle: ConfHandle,
    pub sessions: SessionManager,
    pub subscriber_tx: SubscriberSender,
    pub shutdown_signal: ShutdownSignal,

    // NEW: Replace wireguard_listener with agent_tunnel_listener
    pub agent_tunnel_listener: Option<Arc<AgentTunnelListener>>,
}
```

**Initialization in service.rs:**
```rust
// devolutions-gateway/src/service.rs
pub fn build_gateway_service(...) -> Result<Gateway> {
    // ...

    let agent_tunnel_listener = if conf.agent_tunnel.enabled {
        Some(Arc::new(
            AgentTunnelListener::new(
                conf.agent_tunnel.clone(),
                agent_store,
                shutdown_signal.clone(),
            )
            .await?
        ))
    } else {
        None
    };

    let state = DgwState {
        // ...
        agent_tunnel_listener,
    };

    // ...
}
```

**Route lookup integration:**
```rust
// devolutions-gateway/src/api/fwd.rs
async fn handle_fwd(...) {
    // Existing token parsing
    let claims = parse_association_token(...)?;

    // NEW: If jet_agent_id is set, route through agent tunnel
    if let Some(agent_id) = claims.jet_agent_id {
        let tunnel = state.agent_tunnel_listener
            .as_ref()
            .context("Agent tunnel not enabled")?;

        let mut stream = tunnel
            .open_session_to_agent(agent_id, target_addr)
            .await?;

        // Bridge WebSocket ↔ QUIC stream
        tokio::io::copy_bidirectional(&mut ws, &mut stream).await?;
    } else {
        // Direct connection (existing logic)
        let tcp_stream = TcpStream::connect(target_addr).await?;
        // ...
    }
}
```

### Phase 3: Agent Client (Week 3-4)

**Goal:** Standalone Rust agent that can connect and proxy.

**Deliverables:**
- `devolutions-gateway-agent/src/quic_tunnel.rs` (replace `tunnel.rs`)
- Integration with existing config and enrollment

**Key change:**
```rust
// devolutions-gateway-agent/src/main.rs
match cli.command {
    Commands::Run { config, advertise_subnets } => {
        let agent_config = AgentConfig::from_file(&config)?;

        // NEW: QUIC-based tunnel (not WireGuard)
        let tunnel_client = QuicTunnelClient::new(&agent_config).await?;

        tunnel_client.run().await?;
    }

    Commands::Enroll { enrollment_string, config, advertise_subnets } => {
        // Parse enrollment string
        let enrollment = parse_enrollment_string(&enrollment_string)?;

        // NEW: Request TLS certificate instead of WireGuard keys
        let (cert, key) = enroll_and_get_certificate(&enrollment).await?;

        // Write config with cert/key paths
        let agent_config = AgentConfig {
            agent_id: enrollment.agent_id,
            name: enrollment.agent_name,
            gateway_url: enrollment.gateway_url,
            client_cert: cert,
            client_key: key,
            advertise_subnets,
        };

        agent_config.save_to_file(&config)?;
    }
}
```

### Phase 4: End-to-End Testing (Week 4-5)

**Goal:** Validate reliability under stress.

**Test scenarios:**
```bash
# 1. SSH session with large output
ssh -o ProxyCommand='./test-proxy %h %p' target-host 'cat /dev/urandom | head -c 100000000'

# 2. top command (the killer test from WireGuard POC)
ssh -o ProxyCommand='./test-proxy %h %p' target-host 'top'
# Expected: Does NOT crash after 30 seconds

# 3. Multiple concurrent sessions
for i in {1..10}; do
  ssh -o ProxyCommand='./test-proxy %h %p' target-host 'sleep 60' &
done
wait

# 4. Agent reconnection (NOT connection migration)
# - Start SSH session
# - Stop agent process
# - Wait 5 seconds
# - Start agent process
# Expected: Agent reconnects successfully, can accept new sessions
# NOT expected: Old session survives (it won't - connection was closed)

# 5. Large file transfer
scp -o ProxyCommand='./test-proxy %h %p' /dev/zero target-host:/dev/null
# Transfer 10GB, measure throughput
```

**Performance benchmarks to collect:**
| Metric | WireGuard POC | QUIC Expectation | Notes |
|--------|---------------|------------------|-------|
| Throughput | Measure baseline | Compare to baseline | QUIC may be faster (fewer layers) |
| Latency overhead | Measure baseline | Compare to baseline | Should be comparable or better |
| `top` stability | ❌ Crashes | ✅ Should be stable | Critical reliability fix |
| Reconnect time | N/A | Measure | Agent reconnect after failure |
| Memory per session | Measure baseline | Compare to baseline | Likely lower (no IP buffers) |

All numeric targets will be determined empirically during testing, not specified upfront.

## Technology Stack Deep Dive

### QUIC Library: quiche vs quinn vs s2n-quic

Current WireGuard POC uses:
```toml
# crates/wireguard-tunnel/Cargo.toml
[dependencies]
boringtun = "0.7"  # ~6000 lines, single-purpose WireGuard implementation
```

For QUIC, three main options:

#### Option 1: quiche (Cloudflare) ✅ **PREFERRED CANDIDATE**
```toml
[dependencies]
quiche = "0.22"
tokio-quiche = "0.2"
```

**Pros:**
- Battle-tested at Cloudflare scale (millions of requests/sec)
- Sans-IO design (we control the event loop)
- Full TLS 1.3 mTLS support built-in
- Connection migration (survives IP changes)
- Used by Apple iCloud Private Relay for MASQUE
- Cloudflare blog: "We migrated WARP from WireGuard to MASQUE using quiche" (exact our migration!)

**Cons:**
- Lower-level API (more control but more code)
- Requires careful integration with Tokio

**Integration estimate:** ~2000 lines for listener + client

#### Option 2: quinn (async-first)
```toml
[dependencies]
quinn = "0.11"
```

**Pros:**
- Native Tokio integration (simpler API)
- Higher-level abstractions
- Good for rapid prototyping

**Cons:**
- Less production proven at scale
- Less flexible for custom framing
- No official MASQUE examples

**Integration estimate:** ~1000 lines but less battle-tested

#### Option 3: s2n-quic (AWS)
```toml
[dependencies]
s2n-quic = "1.44"
```

**Pros:**
- Formal verification of security properties
- Good performance in AWS benchmarks

**Cons:**
- Newer, less ecosystem tooling
- Opinionated about event loop structure

**Initial hypothesis:**
**quiche** is the strongest candidate because:
1. Proven migration path (Cloudflare WARP did exactly this migration)
2. Mature mTLS support
3. Sans-IO design allows flexible integration with existing Tokio infrastructure
4. Battle-tested at Cloudflare scale

**However:**
- This choice must be **validated in Phase 0** before committing
- If the primary goal is to ship in 2 months, **quinn deserves serious consideration** for its higher-level API
- The final decision should be driven by the Phase 0 spike, not architectural preference alone

### Dependency Changes

**Remove from Cargo.toml:**
```toml
# crates/wireguard-tunnel/Cargo.toml
[dependencies]
boringtun = "0.7"      # ❌ Delete entire crate
smoltcp = "0.11"       # ❌ No longer need userspace IP stack
```

**Add to Cargo.toml:**
```toml
# crates/agent-tunnel-quic/Cargo.toml
[dependencies]
quiche = { version = "0.22", features = ["boringssl-boring-crate"] }
tokio-quiche = "0.2"
bincode = "1.3"        # For control protocol encoding
ipnetwork = "0.20"     # Already used, keep for subnet logic
dashmap = "6.0"        # Already used for agent registry
parking_lot = "0.12"   # Already used
tracing = "0.1"        # Already used

[build-dependencies]
boring-sys = "4.0"     # BoringSSL (required by quiche)
```

**Certificate generation:**
```toml
[dependencies]
rcgen = "0.13"         # For self-signed CA and client certs
x509-parser = "0.16"   # For cert validation and fingerprinting
```

### mTLS Certificate Architecture

**Current WireGuard approach** (from [devolutions-gateway-agent/src/config.rs](D:\devolutions-gateway\devolutions-gateway-agent\src\config.rs)):
```rust
pub struct AgentConfig {
    pub private_key: x25519_dalek::StaticSecret,    // ❌ WireGuard-specific
    pub gateway_public_key: x25519_dalek::PublicKey, // ❌ WireGuard-specific
}
```

**New QUIC/mTLS approach:**
```rust
pub struct AgentConfig {
    pub agent_id: Uuid,
    pub name: String,
    pub gateway_url: String,

    // TLS identity (mTLS)
    pub client_cert_path: PathBuf,   // ✅ X.509 certificate
    pub client_key_path: PathBuf,    // ✅ Private key (RSA/ECDSA)

    // Gateway CA for validation
    pub gateway_ca_cert_path: PathBuf, // ✅ Trust anchor

    // Route configuration
    pub advertise_subnets: Vec<Ipv4Network>,
}
```

**Certificate issuance flow (ILLUSTRATIVE PSEUDOCODE - not final implementation):**
```rust
// Conceptual flow - actual API will depend on CA library choice

pub async fn enroll_agent(
    token: &EnrollmentToken,
    agent_name: String,
    csr: CertificateSigningRequest,
) -> Result<EnrollmentResult> {
    // 1. Validate token (existing logic from enrollment_store.rs)
    verify_enrollment_token(token)?;

    // 2. Generate client certificate
    let agent_id = Uuid::new_v4();

    let mut cert_params = rcgen::CertificateParams::new(vec![
        format!("agent-{}", agent_id),
    ])?;

    cert_params.distinguished_name = rcgen::DistinguishedName::new();
    cert_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("Devolutions Agent {}", agent_name),
    );

    // Embed agent_id in certificate SAN (Subject Alternative Name)
    cert_params.subject_alt_names.push(
        rcgen::SanType::URI(format!("urn:uuid:{}", agent_id))
    );

    // Short validity (1 year) - forces rotation
    cert_params.not_before = OffsetDateTime::now_utc();
    cert_params.not_after = OffsetDateTime::now_utc() + Duration::days(365);

    // Sign with Gateway's CA key
    let ca_cert = load_gateway_ca_cert()?;
    let ca_key = load_gateway_ca_key()?;

    let cert = cert_params.signed_by(&csr, &ca_cert, &ca_key)?;

    // 3. Store in agent_store
    let record = AgentRecord {
        agent_id,
        name: agent_name.clone(),
        cert_fingerprint: cert.fingerprint_sha256(),  // For revocation
        enrolled_at_unix: SystemTime::now().as_secs(),
    };

    agent_store.add(record)?;

    Ok(EnrollmentResult {
        agent_id,
        agent_name,
        client_cert: cert.pem(),
        gateway_ca_cert: ca_cert.pem(),
        gateway_url: conf.agent_tunnel.listen_url.clone(),
    })
}
```

**Certificate validation in QUIC handshake (ILLUSTRATIVE PSEUDOCODE):**
```rust
// Conceptual validation flow - actual API depends on QUIC library

impl AgentTunnelListener {
    async fn accept_connection(&mut self) -> Result<QuicAgent> {
        // 1. Accept QUIC connection
        let conn = self.endpoint.accept().await?;

        // 2. Extract client certificate from TLS handshake
        let peer_cert = conn.peer_identity()
            .context("Client did not present certificate")?;

        // 3. Parse certificate and extract agent_id from SAN
        let cert = x509_parser::parse_x509_certificate(peer_cert)?;

        let agent_id = cert.subject_alternative_name()?
            .filter_map(|san| {
                if let GeneralName::URI(uri) = san {
                    uri.strip_prefix("urn:uuid:")
                        .and_then(|s| Uuid::parse_str(s).ok())
                } else {
                    None
                }
            })
            .next()
            .context("Certificate does not contain agent_id")?;

        // 4. Verify agent exists in registry
        let agent_record = self.agent_store.get(&agent_id)
            .context("Unknown agent")?;

        // 5. Verify certificate fingerprint matches stored value
        let presented_fingerprint = cert.fingerprint_sha256();
        anyhow::ensure!(
            presented_fingerprint == agent_record.cert_fingerprint,
            "Certificate fingerprint mismatch"
        );

        // 6. Create QuicAgent handle
        Ok(QuicAgent {
            agent_id,
            name: agent_record.name.clone(),
            connection: conn,
            last_seen: AtomicInstant::now(),
        })
    }
}
```

## Common Pitfalls to Avoid

### Pitfall 1: Attempting to preserve `VirtualTcpStream`

**Why it's tempting:**
The existing `VirtualTcpStream` in [devolutions-gateway/src/wireguard/stream.rs](D:\devolutions-gateway\devolutions-gateway\src\wireguard\stream.rs) implements `AsyncRead + AsyncWrite`, which is exactly what the forwarding code expects.

**Why it's wrong:**
`VirtualTcpStream` exists solely to paper over the fact that WireGuard provides datagrams, not streams. It uses internal mpsc channels to simulate stream semantics:

```rust
// devolutions-gateway/src/wireguard/stream.rs (156 lines)
pub struct VirtualTcpStream {
    read_queue: mpsc::UnboundedReceiver<Bytes>,  // ❌ Unnecessary with QUIC
    write_tx: mpsc::UnboundedSender<RelayMessage>, // ❌ Unnecessary with QUIC
}
```

**With QUIC:**
```rust
// QUIC streams provide byte stream semantics natively
// A thin adapter may be needed depending on the chosen library's API
// But do NOT preserve VirtualTcpStream's internal mpsc queue mechanics

// Conceptual usage (actual API depends on library integration):
let mut quic_stream = agent.open_stream().await?;
// Bridge directly - no manual DATA/CLOSE framing
tokio::io::copy_bidirectional(&mut ws, &mut quic_stream).await?;
```

**Key point:**
- Do not preserve VirtualTcpStream's internal mechanics (mpsc channels)
- Prefer a thin QUIC stream adapter appropriate to the chosen library
- The adapter should be simpler than VirtualTcpStream because QUIC provides stream semantics natively

### Pitfall 2: UDP 443 Deployment Constraints

**Reality Check:**
TCP 443 and UDP 443 are different transport sockets and can normally bind separately on the same host without conflict. The real challenge is not socket coexistence but **deployment environment exposure**.

**Key deployment questions:**

1. **Does the hosting platform expose UDP 443?**
   - Some cloud providers block UDP by default
   - Reverse proxies (nginx, Cloudflare) may not forward UDP
   - Container platforms may not expose UDP ports

2. **Is UDP enabled in the current deployment?**
   - Check if Gateway's current hosting supports UDP traffic
   - Verify firewall rules allow inbound UDP
   - Test if load balancers pass UDP through

3. **How are TLS certificates managed?**
   - QUIC needs TLS 1.3 certificate (usually same as HTTPS)
   - Certificate provisioning must work for both TCP and UDP listeners
   - Let's Encrypt ALPN challenges may need adjustment

**Solutions:**

**Option A: Use same port number, different protocols (simplest)**
```rust
// TCP 443 for HTTPS (existing)
let tcp_listener = TcpListener::bind("0.0.0.0:443")?;

// UDP 443 for QUIC (new - separate socket, no conflict)
let udp_socket = UdpSocket::bind("0.0.0.0:443")?;
```
✅ No socket conflict (TCP and UDP are separate)
⚠️ Requires UDP 443 to be exposed in deployment

**Option B: Separate UDP port (fallback)**
```toml
[agent_tunnel]
listen_port = 4433  # UDP 4433 for QUIC if UDP 443 unavailable
```
✅ Works immediately
❌ Requires additional firewall rule
❌ Not the "single port" ideal

**Recommendation for v1:**
- **Target UDP 443** as the primary design
- **Phase 0 must validate** that UDP 443 works in actual deployment environment
- Keep Option B as fallback if deployment constraints force it

### Pitfall 3: Conflating Connection Migration with Reconnection

**Important distinction:**

**QUIC Path Migration** = Same connection survives IP address change
- Connection ID stays the same
- No re-handshake needed
- Existing streams continue without interruption
- Example: Laptop switches from WiFi to cellular

**Reconnection after closure** = New connection after old one failed
- New connection ID
- New TLS handshake
- Old streams are lost
- Example: Agent process restart, network timeout

**For v1 agent tunnel:**

1. **Path migration** is a nice-to-have but not critical
   - Most agents have stable IPs (server in datacenter)
   - Mobile agents are not the primary use case
   - QUIC supports this natively if enabled

2. **Reconnection** is essential
   - Agent must be able to reconnect after network failure
   - Gateway must recognize returning agent via mTLS cert
   - Route advertisements must be re-sent after reconnect
   - **Active proxied sessions will be lost** - this is expected behavior

**Correct implementation:**
```rust
// quiche configuration (illustrative)
let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
config.set_max_idle_timeout(120_000);   // 2 minutes idle before connection timeout

// In agent - handle reconnection (NOT migration)
impl QuicTunnelClient {
    async fn run(&self) -> Result<()> {
        loop {
            // If connection closes, establish NEW connection
            if self.connection.is_closed() {
                warn!("Connection closed, reconnecting...");
                self.connection = self.establish_new_connection().await?;

                // Re-authenticate with same mTLS cert
                // Re-send route advertisement
                self.advertise_routes().await?;

                // Note: active streams from old connection are gone
            }

            // ...
        }
    }
}
```

**Test scenario for Phase 4:**
```bash
# NOT testing connection migration:
# 1. Start agent
# 2. Stop agent process
# 3. Start agent again
# Expected: Agent reconnects, can accept new sessions
# NOT expected: Old sessions survive (they won't)
```

### Pitfall 4: Forgetting about MTU

**WireGuard POC issue:**
The `top` command crash is likely caused by:
1. `top` generates large bursts of data
2. Exceeds path MTU
3. IP fragmentation occurs at WireGuard layer
4. UDP fragment loss → permanent data loss

**QUIC's advantage:**
QUIC has built-in path MTU discovery (PMTUD) and automatic packet sizing:
```rust
// quiche automatically handles MTU
let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
// Default initial MTU is 1200 bytes (safe for all networks)
// quiche will probe for larger MTU and adapt

// No manual MTU configuration needed!
```

But we should still test:
```bash
# Force low MTU to validate QUIC handles it
sudo ip link set eth0 mtu 1280
ssh via_agent 'top'  # Should NOT crash
```

## Final Recommendation

If the team has two months and wants a production-worthy result, the cleanest strategy is:

- new branch from `master`
- new `agent_tunnel` architecture
- reuse only the control-plane semantics from the WireGuard branch
- do not carry forward WireGuard-shaped runtime and storage models

That is the direction I would defend in review.

## Code Size Estimate (Qualitative)

Based on analysis of current codebase, the QUIC rewrite is expected to be **significantly smaller** than the WireGuard POC:

**Why the rewrite should be simpler:**
1. No custom stream multiplexing (QUIC provides native streams)
2. No IP packet construction/parsing
3. No DATA/CLOSE message framing on top of streams
4. No smoltcp userspace IP stack integration
5. No boringtun event loop choreography

**Expected scope reduction:**
- Transport layer: Substantially smaller (QUIC handles reliability, flow control, multiplexing)
- Protocol layer: Simpler (no transport-level framing)
- Agent client: Cleaner (no IP encapsulation)
- Gateway listener: More straightforward (fewer abstraction layers)

**Rough time estimate for planning:**
- Phase 0 (POC): 1 week
- Phase 1 (Protocol): 1-2 weeks
- Phase 2 (Gateway): 2-3 weeks
- Phase 3 (Agent): 1-2 weeks
- Phase 4 (Testing): 2 weeks
- **Total: ~7-10 weeks**

This is directional guidance, not a firm commitment. The Phase 0 spike will refine the estimate based on actual library integration complexity.

## Direct Code Reuse Opportunities

While the transport layer must be rewritten, some code can be copied directly with minimal changes:

### 1. Route Advertisement Logic (High Semantic Reuse)

From [devolutions-gateway/src/wireguard/peer.rs](D:\devolutions-gateway\devolutions-gateway\src\wireguard\peer.rs):
```rust
// ✅ Strong candidate for semantic preservation
pub fn can_reach(&self, target_ip: IpAddr) -> bool {
    self.route_state()
        .map(|route_state| match target_ip {
            IpAddr::V4(ipv4) => route_state.subnets.iter()
                .any(|subnet| subnet.contains(ipv4)),
            IpAddr::V6(_) => false,
        })
        .unwrap_or(false)
}

pub fn route_state(&self) -> Option<RouteAdvertisementState> {
    self.route_state.read().clone()
}

pub fn update_routes(&self, epoch: u64, subnets: Vec<Ipv4Network>) {
    let mut state = self.route_state.write();
    *state = Some(RouteAdvertisementState {
        epoch,
        subnets,
        received_at: Instant::now(),
    });
}
```

**Change required:** Adapt type models and timestamps to QUIC structures, preserve the validation semantics.

### 2. Agent Selection for Overlapping Routes (High Semantic Reuse)

From [devolutions-gateway/src/wireguard/listener.rs](D:\devolutions-gateway\devolutions-gateway\src\wireguard\listener.rs):
```rust
// ✅ Algorithm and logic are proven correct - preserve semantics
pub fn select_agent_for_target(&self, target_ip: IpAddr) -> Option<Arc<QuicAgent>> {
    self.registry
        .agents  // Changed from .peers
        .iter()
        .filter(|e| e.value().is_online(AGENT_OFFLINE_TIMEOUT))
        .filter_map(|entry| {
            let agent = entry.value();
            let route_state = agent.route_state()?;
            let matches = match target_ip {
                IpAddr::V4(ipv4) => route_state.subnets.iter()
                    .any(|subnet| subnet.contains(ipv4)),
                IpAddr::V6(_) => false,
            };

            if matches {
                Some((route_state.received_at, Arc::clone(agent)))
            } else {
                None
            }
        })
        .max_by_key(|(received_at, _)| *received_at)
        .map(|(_, agent)| agent)
}
```

**This routing logic is proven correct and should not be reimplemented from scratch.**

### 3. Enrollment Token Storage (Moderate Semantic Reuse)

From [devolutions-gateway/src/enrollment_store.rs](D:\devolutions-gateway\devolutions-gateway\src\enrollment_store.rs):

**Core mechanism reusable:**
- SHA-256 hashed token validation
- Time-based expiration checking
- Single-use consumption semantics
- Constant-time comparison for security

**Enrollment flow stays similar:**
1. Gateway issues token via `/enrollment-tokens` API
2. Token consists of `token_id.base64(secret)`
3. Agent presents token during enrollment handshake
4. Gateway verifies hash, checks expiration, consumes token
5. Gateway returns **client certificate** instead of WireGuard config

**Critical difference:**
```rust
// OLD (WireGuard): enrollment_store.rs returns WireGuardPeerConfig
pub fn enroll_agent(...) -> Result<WireGuardPeerConfig> { ... }

// NEW (QUIC): returns PEM-encoded client certificate
pub fn enroll_agent_quic(...) -> Result<ClientCertificate> { ... }
```

The existing `EnrollmentStore` persistence, token generation APIs, and validation logic remain structurally useful. Only the enrollment **response payload** changes (cert bundle instead of WireGuard keys).

**Implementation note:** Read the actual [enrollment_store.rs](D:\devolutions-gateway\devolutions-gateway\src\enrollment_store.rs) implementation before migration — the token issuance and persistence mechanics differ from the simplified examples above.

### 4. Agent Status API (High API Contract Reuse)

From [devolutions-gateway/src/api/agents.rs](D:\devolutions-gateway\devolutions-gateway\src\api\agents.rs):
```rust
// ✅ API contract should be preserved, implementation adapts to QUIC backend
#[derive(Serialize)]
pub struct AgentStatusResponse {
    pub agent_id: Uuid,
    pub name: String,
    pub online: bool,
    pub last_seen: Option<u64>,
    pub advertised_subnets: Vec<String>,
    pub active_streams: u32,
}

pub async fn list_agents(
    State(state): State<DgwState>,
) -> Result<Json<Vec<AgentStatusResponse>>, HttpError> {
    let listener = state.agent_tunnel_listener  // Changed from wireguard_listener
        .as_ref()
        .context("Agent tunnel not enabled")?;

    let agents = listener.list_agents();  // Same semantics, different backend

    let response = agents.into_iter()
        .map(|agent| AgentStatusResponse {
            agent_id: agent.agent_id,
            name: agent.name.clone(),
            online: agent.is_online(AGENT_OFFLINE_TIMEOUT),
            last_seen: agent.last_seen(),
            advertised_subnets: agent.advertised_subnets(),
            active_streams: agent.active_stream_count(),
        })
        .collect();

    Ok(Json(response))
}
```

**The API contract stays the same, internal implementation changes.**

### 5. Test Scenarios (Directly Reusable)

From [WIREGUARD_TESTING.md](D:\devolutions-gateway\WIREGUARD_TESTING.md):
```bash
# ✅ Test scenarios and validation criteria are transport-independent
# Test 1: Basic connectivity
./test-client.ps1 -Token "<token>"

# Test 2: Large data transfer
ssh via_agent 'cat /dev/urandom | head -c 100000000'

# Test 3: top command (the critical reliability test)
ssh via_agent 'top'

# Test 4: Multiple concurrent sessions
for i in {1..10}; do
  ssh via_agent 'sleep 60' &
done
```

**Test scenarios and validation goals are reusable, but scripts will require adaptation:**
- Listening port may change (depends on deployment: dedicated UDP 443 vs separate port)
- Enrollment API output format changes (client cert instead of WireGuard config)
- Agent CLI flags and configuration format may change
- Proxy command invocation may differ

**Reusable test validation criteria:**
- Route advertisement and subnet reachability
- Concurrent session handling
- Connection stability under sustained load (e.g., `top` command)
- Enrollment token lifecycle (generation, consumption, expiration)

## Implementation Details

This section provides the missing concrete details needed to start implementation. These specifications fill gaps identified during architecture review.

### Agent Enrollment Flow (Complete Sequence)

**Enrollment is a two-phase process:**

1. **Token Generation** (Admin → Gateway API)
2. **Agent Registration** (Agent → Gateway API → Certificate Issuance)

#### Phase 1: Token Generation (Admin/UI Action)

**API Endpoint:**
```http
POST /jet/agent-enrollment/tokens
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "prod-backend-agent-01",
  "validity_duration_secs": 3600
}
```

**Response:**
```json
{
  "token_id": "550e8400-e29b-41d4-a716-446655440000",
  "enrollment_token": "550e8400-e29b-41d4-a716-446655440000.dGhpc2lzYXNlY3JldA",
  "expires_at": "2026-03-19T15:30:00Z"
}
```

**Backend Logic:**
```rust
// devolutions-gateway/src/api/agent_enrollment.rs

pub async fn create_enrollment_token(
    State(enrollment_store): State<Arc<EnrollmentStore>>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, ApiError> {
    // Generate token using existing enrollment_store.rs mechanism
    let token_id = Uuid::new_v4();
    let secret = generate_random_bytes(32);
    let expires_at = SystemTime::now() + Duration::from_secs(req.validity_duration_secs);

    let token_hash = compute_sha256_hash(&token_id, &secret);

    enrollment_store.insert_token(EnrollmentTokenRecord {
        token_id,
        token_hash,
        agent_name: req.name.clone(),
        expires_at,
        consumed: false,
    })?;

    let enrollment_token = format!("{}.{}",
        token_id,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&secret)
    );

    Ok(Json(CreateTokenResponse {
        token_id,
        enrollment_token,
        expires_at: expires_at.into(),
    }))
}
```

#### Phase 2: Agent Registration (Agent-Initiated)

**Step 1: Agent generates CSR**

When agent starts without credentials:
```rust
// devolutions-gateway-agent/src/enrollment.rs

pub async fn enroll_agent(
    gateway_url: &str,
    enrollment_token: &str,
    agent_name: &str,
) -> Result<EnrollmentCredentials> {
    // 1. Generate key pair (ECDSA P-256 preferred for performance)
    let private_key = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    // 2. Create CSR
    let mut params = rcgen::CertificateParams::new(vec![
        format!("agent.{}", agent_name.to_lowercase())
    ])?;

    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        agent_name,
    );

    let csr = params.serialize_request(&private_key)?;

    // 3. Submit enrollment request
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/jet/agent-enrollment/enroll", gateway_url))
        .header("Content-Type", "application/json")
        .json(&EnrollRequest {
            enrollment_token: enrollment_token.to_owned(),
            agent_name: agent_name.to_owned(),
            csr_pem: csr.pem()?,
        })
        .send()
        .await?;

    let enroll_response: EnrollResponse = response.json().await?;

    // 4. Persist credentials locally
    let creds = EnrollmentCredentials {
        agent_id: enroll_response.agent_id,
        agent_name: agent_name.to_owned(),
        gateway_url: gateway_url.to_owned(),
        client_cert_pem: enroll_response.client_cert_pem,
        client_key_pem: private_key.serialize_pem(),
        gateway_ca_cert_pem: enroll_response.gateway_ca_cert_pem,
    };

    persist_credentials(&creds)?;

    Ok(creds)
}
```

**Step 2: Gateway validates and issues certificate**

**API Endpoint:**
```http
POST /jet/agent-enrollment/enroll
Content-Type: application/json

{
  "enrollment_token": "550e8400-e29b-41d4-a716-446655440000.dGhpc2lzYXNlY3JldA",
  "agent_name": "prod-backend-agent-01",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

**Response:**
```json
{
  "agent_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "agent_name": "prod-backend-agent-01",
  "client_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "gateway_ca_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "gateway_tunnel_url": "https://gateway.example.com:443"
}
```

**Backend Logic:**
```rust
// devolutions-gateway/src/api/agent_enrollment.rs

pub async fn enroll_agent_endpoint(
    State(enrollment_store): State<Arc<EnrollmentStore>>,
    State(agent_store): State<Arc<AgentStore>>,
    State(ca_manager): State<Arc<CaManager>>,
    State(config): State<Arc<ConfHandle>>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    // 1. Parse and validate token
    let (token_id, secret) = parse_enrollment_token(&req.enrollment_token)?;

    let token_record = enrollment_store
        .get_token(&token_id)
        .context("Token not found")?;

    anyhow::ensure!(!token_record.consumed, "Token already consumed");
    anyhow::ensure!(
        SystemTime::now() < token_record.expires_at,
        "Token expired"
    );

    let presented_hash = compute_sha256_hash(&token_id, &secret);
    anyhow::ensure!(
        constant_time_compare(&presented_hash, &token_record.token_hash),
        "Invalid token"
    );

    // 2. Parse CSR
    let csr = rcgen::CertificateSigningRequest::from_pem(&req.csr_pem)?;

    // 3. Generate agent_id and sign certificate
    let agent_id = Uuid::new_v4();

    let mut cert_params = rcgen::CertificateParams::from_csr(csr)?;

    // Embed agent_id in SAN (critical for later validation)
    cert_params.subject_alt_names.push(
        rcgen::SanType::URI(format!("urn:uuid:{}", agent_id))
    );

    // Set validity period (1 year)
    cert_params.not_before = rcgen::OffsetDateTime::now_utc();
    cert_params.not_after = rcgen::OffsetDateTime::now_utc()
        + rcgen::Duration::days(365);

    // Sign with CA
    let client_cert = ca_manager.sign_certificate(cert_params)?;
    let cert_fingerprint = compute_cert_fingerprint(&client_cert)?;

    // 4. Store in agent_store
    agent_store.upsert(AgentRecord {
        agent_id,
        name: req.agent_name.clone(),
        cert_fingerprint,
        enrolled_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs(),
    })?;

    // 5. Mark token as consumed
    enrollment_store.mark_consumed(&token_id)?;

    // 6. Return credentials
    Ok(Json(EnrollResponse {
        agent_id,
        agent_name: req.agent_name,
        client_cert_pem: client_cert.pem(),
        gateway_ca_cert_pem: ca_manager.ca_cert_pem(),
        gateway_tunnel_url: config
            .read()
            .unwrap()
            .agent_tunnel
            .listen_url
            .clone(),
    }))
}
```

**Step 3: Agent establishes QUIC connection using certificate**

```rust
// devolutions-gateway-agent/src/tunnel.rs

pub async fn connect_to_gateway(
    creds: &EnrollmentCredentials,
) -> Result<AgentTunnelConnection> {
    // 1. Load credentials
    let client_cert = rustls::Certificate(
        pem::parse(&creds.client_cert_pem)?.contents().to_vec()
    );
    let client_key = rustls::PrivateKey(
        pem::parse(&creds.client_key_pem)?.contents().to_vec()
    );
    let ca_cert = rustls::Certificate(
        pem::parse(&creds.gateway_ca_cert_pem)?.contents().to_vec()
    );

    // 2. Build TLS config
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(&ca_cert)?;

    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(vec![client_cert], client_key)?;

    // 3. Build QUIC config
    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    quic_config.set_application_protos(&[b"devolutions-agent-tunnel/1"])?;
    quic_config.verify_peer(true);

    // 4. Connect
    let local_addr = "0.0.0.0:0".parse()?;
    let socket = tokio::net::UdpSocket::bind(local_addr).await?;

    let gateway_addr = resolve_gateway_addr(&creds.gateway_url).await?;

    let conn = quiche::connect(
        Some(&creds.gateway_url),
        &scid,
        local_addr,
        gateway_addr,
        &mut quic_config,
    )?;

    // QUIC handshake will validate certificate automatically
    // If agent_id doesn't match or cert is revoked, connection will fail

    Ok(AgentTunnelConnection {
        agent_id: creds.agent_id,
        connection: conn,
        socket: Arc::new(socket),
    })
}
```

**Enrollment flow diagram:**
```
Admin/UI                Gateway API              Agent              Gateway Listener
   |                        |                      |                      |
   |--POST /tokens--------->|                      |                      |
   |<---enrollment_token----|                      |                      |
   |                        |                      |                      |
   |  (Admin shares token with agent)              |                      |
   |                                               |                      |
   |                        |<--POST /enroll-------|                      |
   |                        |   (token + CSR)      |                      |
   |                        |                      |                      |
   |                        |--validate token----->|                      |
   |                        |--sign cert---------->|                      |
   |                        |--store agent-------->|                      |
   |                        |--mark consumed------>|                      |
   |                        |                      |                      |
   |                        |---cert bundle------->|                      |
   |                        |                      |                      |
   |                        |                      |--QUIC handshake----->|
   |                        |                      |  (present cert)      |
   |                        |                      |                      |
   |                        |                      |<--validate agent_id--|
   |                        |                      |<--check fingerprint--|
   |                        |                      |                      |
   |                        |                      |<--connection ready---|
```

**Credential persistence on agent:**
```toml
# ~/.devolutions-agent/credentials.toml or /etc/devolutions-agent/credentials.toml

agent_id = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
agent_name = "prod-backend-agent-01"
gateway_url = "https://gateway.example.com:443"

[tls]
client_cert = "/etc/devolutions-agent/cert.pem"
client_key = "/etc/devolutions-agent/key.pem"
gateway_ca_cert = "/etc/devolutions-agent/ca.pem"
```

### CA Certificate Lifecycle Management

**CA certificate is the root of trust for the entire agent tunnel system.**

#### Gateway CA Initialization

**Option 1: Self-signed CA (default for standalone deployments)**

```rust
// devolutions-gateway/src/agent_tunnel/ca_manager.rs

pub struct CaManager {
    ca_cert: rcgen::Certificate,
    ca_key_pair: rcgen::KeyPair,
    ca_cert_pem: String,
}

impl CaManager {
    pub fn load_or_generate(data_dir: &Path) -> Result<Self> {
        let ca_cert_path = data_dir.join("agent-tunnel-ca.pem");
        let ca_key_path = data_dir.join("agent-tunnel-ca.key");

        if ca_cert_path.exists() && ca_key_path.exists() {
            // Load existing CA
            info!("Loading existing CA certificate");
            let ca_cert_pem = std::fs::read_to_string(&ca_cert_path)?;
            let ca_key_pem = std::fs::read_to_string(&ca_key_path)?;

            let ca_cert = rcgen::Certificate::from_params(
                rcgen::CertificateParams::from_ca_cert_pem(&ca_cert_pem)?
            )?;
            let ca_key_pair = rcgen::KeyPair::from_pem(&ca_key_pem)?;

            Ok(Self {
                ca_cert,
                ca_key_pair,
                ca_cert_pem,
            })
        } else {
            // Generate new CA
            info!("Generating new CA certificate");

            let mut params = rcgen::CertificateParams::new(vec![
                "Devolutions Gateway Agent Tunnel CA".to_owned()
            ])?;

            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];

            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                "Devolutions Gateway Agent Tunnel CA",
            );

            params.distinguished_name.push(
                rcgen::DnType::OrganizationName,
                "Devolutions Inc.",
            );

            // 10 year validity for CA
            params.not_before = rcgen::OffsetDateTime::now_utc();
            params.not_after = rcgen::OffsetDateTime::now_utc()
                + rcgen::Duration::days(3650);

            let ca_key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let ca_cert = rcgen::Certificate::from_params(params)?;

            let ca_cert_pem = ca_cert.serialize_pem()?;
            let ca_key_pem = ca_key_pair.serialize_pem();

            // Persist CA (CRITICAL: protect ca.key with filesystem permissions)
            std::fs::write(&ca_cert_path, &ca_cert_pem)?;
            std::fs::write(&ca_key_path, &ca_key_pem)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&ca_key_path,
                    std::fs::Permissions::from_mode(0o600))?;
            }

            info!("CA certificate generated and saved");

            Ok(Self {
                ca_cert,
                ca_key_pair,
                ca_cert_pem,
            })
        }
    }

    pub fn sign_certificate(
        &self,
        params: rcgen::CertificateParams,
    ) -> Result<rcgen::Certificate> {
        let cert = rcgen::Certificate::from_params(params)?;
        let signed_cert_pem = cert.serialize_pem_with_signer(&self.ca_cert)?;

        Ok(rcgen::Certificate::from_params(
            rcgen::CertificateParams::from_ca_cert_pem(&signed_cert_pem)?
        )?)
    }

    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert_pem.clone()
    }
}
```

**Option 2: External CA (enterprise PKI integration)**

```rust
// Configuration option for external CA
#[derive(Debug, Deserialize)]
pub struct AgentTunnelConf {
    pub listen_url: String,
    pub ca_mode: CaMode,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum CaMode {
    #[serde(rename = "self_signed")]
    SelfSigned,

    #[serde(rename = "external")]
    External {
        ca_cert_path: PathBuf,
        ca_key_path: PathBuf,
        // Optional: PKCS#11 HSM support
        pkcs11_module: Option<String>,
        pkcs11_slot: Option<u32>,
    },
}
```

**CA certificate distribution:**
```bash
# Gateway exposes CA cert via public endpoint (read-only)
curl https://gateway.example.com/jet/agent-enrollment/ca.pem

# This allows agents to bootstrap trust before enrollment
```

#### Certificate Revocation

**Simple revocation mechanism (v1):**

```rust
// devolutions-gateway/src/agent_store.rs

pub struct AgentRecord {
    pub agent_id: Uuid,
    pub name: String,
    pub cert_fingerprint: String,  // SHA-256 of DER-encoded cert
    pub enrolled_at_unix: u64,
    pub revoked: bool,  // NEW FIELD
    pub revoked_at_unix: Option<u64>,  // NEW FIELD
}

// Revocation API
pub async fn revoke_agent(
    State(agent_store): State<Arc<AgentStore>>,
    Path(agent_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    agent_store.revoke_agent(&agent_id)?;

    // Close any active QUIC connections for this agent
    // (This happens automatically on next heartbeat check)

    Ok(StatusCode::NO_CONTENT)
}

// Validation during QUIC handshake
impl AgentTunnelListener {
    async fn validate_agent_cert(&self, agent_id: Uuid) -> Result<()> {
        let record = self.agent_store.get(&agent_id)
            .context("Unknown agent")?;

        anyhow::ensure!(!record.revoked, "Agent certificate revoked");

        Ok(())
    }
}
```

**Note:** Full CRL/OCSP support is deferred to v2. For v1, gateway checks revocation status from agent_store during connection establishment and heartbeat.

### Error Handling and Reconnection Strategy

#### Agent-Side Reconnection Logic

```rust
// devolutions-gateway-agent/src/tunnel.rs

pub struct ReconnectionPolicy {
    /// Initial retry delay
    pub initial_delay: Duration,
    /// Maximum retry delay (exponential backoff cap)
    pub max_delay: Duration,
    /// Backoff multiplier
    pub backoff_factor: f64,
    /// Maximum retry attempts before giving up (None = infinite)
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectionPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_factor: 2.0,
            max_attempts: None,  // Retry forever
        }
    }
}

pub async fn maintain_tunnel_connection(
    creds: Arc<EnrollmentCredentials>,
    advertise_subnets: Vec<Ipv4Network>,
    policy: ReconnectionPolicy,
) -> Result<()> {
    let mut attempt = 0;
    let mut current_delay = policy.initial_delay;

    loop {
        attempt += 1;

        if let Some(max_attempts) = policy.max_attempts {
            if attempt > max_attempts {
                error!("Exceeded max reconnection attempts ({})", max_attempts);
                return Err(anyhow!("Failed to establish tunnel"));
            }
        }

        info!(attempt, "Connecting to gateway");

        match connect_and_run_tunnel(&creds, &advertise_subnets).await {
            Ok(()) => {
                // Connection closed gracefully, reset backoff
                warn!("Tunnel connection closed, reconnecting");
                attempt = 0;
                current_delay = policy.initial_delay;
                tokio::time::sleep(current_delay).await;
            }
            Err(e) => {
                error!(error = ?e, attempt, "Tunnel connection failed");

                // Exponential backoff
                tokio::time::sleep(current_delay).await;
                current_delay = std::cmp::min(
                    Duration::from_secs_f64(current_delay.as_secs_f64() * policy.backoff_factor),
                    policy.max_delay,
                );

                // Add jitter to prevent thundering herd
                let jitter = rand::thread_rng().gen_range(0..1000);
                tokio::time::sleep(Duration::from_millis(jitter)).await;
            }
        }
    }
}

async fn connect_and_run_tunnel(
    creds: &EnrollmentCredentials,
    advertise_subnets: &[Ipv4Network],
) -> Result<()> {
    let mut conn = connect_to_gateway(creds).await?;

    info!(agent_id = %conn.agent_id, "Tunnel connected");

    // Open control stream
    let control_stream = conn.open_bidirectional_stream().await?;

    // Send initial route advertisement
    send_route_advertisement(&control_stream, advertise_subnets).await?;

    // Run tunnel until connection fails
    run_tunnel_loop(conn, control_stream).await?;

    Ok(())
}
```

#### Stream-Level Error Handling

```rust
// Gateway side: handle target connection failures

async fn handle_connect_request(
    agent_conn: &QuicConnection,
    stream: QuicStream,
    target: String,
) -> Result<()> {
    // Try to connect to target
    match TcpStream::connect(&target).await {
        Ok(target_stream) => {
            // Send success response
            send_connect_response(&stream, ConnectResponse::Success {
                protocol_version: CURRENT_PROTOCOL_VERSION,
            }).await?;

            // Proxy bytes bidirectionally
            tokio::try_join!(
                copy_stream(&mut stream, &mut target_stream),
                copy_stream(&mut target_stream, &mut stream),
            )?;
        }
        Err(e) => {
            // Send error response
            send_connect_response(&stream, ConnectResponse::Error {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                reason: format!("Connection refused: {}", e),
            }).await?;

            // Close stream
            stream.finish().await?;
        }
    }

    Ok(())
}
```

#### Network Change Handling

```rust
// Agent monitors network changes and reconnects

#[cfg(target_os = "linux")]
async fn monitor_network_changes() -> Result<()> {
    use netlink_sys::{Socket, SocketAddr};
    use rtnetlink::new_connection;

    let (conn, handle, _) = new_connection()?;
    tokio::spawn(conn);

    let mut link_stream = handle.link().get().execute();

    while let Some(msg) = link_stream.try_next().await? {
        info!(?msg, "Network interface changed");
        // Trigger reconnection
        // (In practice, QUIC connection will notice path change automatically)
    }

    Ok(())
}
```

**Critical distinction: QUIC path migration vs reconnection**

```rust
// QUIC connection migration (automatic, same connection)
// - Agent changes IP (WiFi → Ethernet)
// - QUIC lib detects new path, sends PATH_CHALLENGE
// - Connection continues, no application-level reconnect needed
// ✅ Existing streams survive

// Application-level reconnection (new connection)
// - Agent process restarts
// - Gateway restarts
// - Connection idle timeout exceeds max
// ❌ All existing streams are lost
// ✅ Agent establishes new QUIC connection
// ✅ Sends new RouteAdvertisement
// ✅ New proxy connections work, old ones are gone
```

### Deployment Configuration

#### Gateway Configuration (TOML)

```toml
# /etc/devolutions-gateway/gateway.toml

[agent_tunnel]
# QUIC listen address
# UDP 443 requires CAP_NET_BIND_SERVICE on Linux
listen_url = "https://0.0.0.0:443"

# Alternative: use separate port to avoid TCP/UDP 443 conflicts
# listen_url = "https://0.0.0.0:4443"

# CA mode: "self_signed" or "external"
ca_mode = "self_signed"

# For external CA:
# [agent_tunnel.external_ca]
# ca_cert_path = "/etc/pki/gateway-ca.pem"
# ca_key_path = "/etc/pki/gateway-ca.key"

# Connection settings
max_idle_timeout_secs = 300
max_concurrent_streams_per_agent = 100

# Agent offline threshold
agent_offline_timeout_secs = 30

[enrollment]
# Default token validity
default_token_validity_secs = 3600

# Maximum concurrent enrollment requests
max_concurrent_enrollments = 10
```

#### Agent Configuration (TOML)

```toml
# /etc/devolutions-agent/agent.toml

[gateway]
# Gateway URL (must match certificate SAN)
url = "https://gateway.example.com:443"

[identity]
# Path to enrolled credentials
# (Generated during enrollment, do not edit manually)
credentials_file = "/etc/devolutions-agent/credentials.toml"

[routing]
# Subnets this agent can reach
advertise_subnets = [
    "192.168.1.0/24",
    "10.0.0.0/16"
]

# Route advertisement interval (heartbeat)
advertisement_interval_secs = 60

[connection]
# Reconnection policy
initial_retry_delay_secs = 1
max_retry_delay_secs = 60
retry_backoff_factor = 2.0

# Connection keep-alive
keep_alive_interval_secs = 30
```

#### Firewall Rules

**Gateway (public-facing):**
```bash
# Allow UDP 443 for QUIC
sudo ufw allow 443/udp

# Or if using separate port:
# sudo ufw allow 4443/udp
```

**Agent (private network):**
```bash
# Agent only makes outbound connections
# No inbound firewall rules needed

# Ensure outbound UDP 443 (or custom port) is allowed
# Most corporate firewalls allow outbound HTTPS (TCP 443)
# but may block UDP 443 - validate in your environment
```

#### systemd Service Files

**Gateway:**
```ini
# /etc/systemd/system/devolutions-gateway.service

[Unit]
Description=Devolutions Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=devolutions-gateway
Group=devolutions-gateway
ExecStart=/usr/bin/devolutions-gateway \
    --config /etc/devolutions-gateway/gateway.toml
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/devolutions-gateway

[Install]
WantedBy=multi-user.target
```

**Agent:**
```ini
# /etc/systemd/system/devolutions-agent.service

[Unit]
Description=Devolutions Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=devolutions-agent
Group=devolutions-agent
ExecStart=/usr/bin/devolutions-agent \
    --config /etc/devolutions-agent/agent.toml
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/devolutions-agent

[Install]
WantedBy=multi-user.target
```

### API Changes Specification

#### New Endpoints

**1. Create Enrollment Token**
```http
POST /jet/agent-enrollment/tokens
Authorization: Bearer <admin_token>
Content-Type: application/json

Request:
{
  "name": "string",
  "validity_duration_secs": 3600
}

Response (201 Created):
{
  "token_id": "uuid",
  "enrollment_token": "string",
  "expires_at": "ISO8601 timestamp"
}
```

**2. List Enrollment Tokens**
```http
GET /jet/agent-enrollment/tokens
Authorization: Bearer <admin_token>

Response (200 OK):
{
  "tokens": [
    {
      "token_id": "uuid",
      "agent_name": "string",
      "expires_at": "ISO8601 timestamp",
      "consumed": boolean,
      "created_at": "ISO8601 timestamp"
    }
  ]
}
```

**3. Revoke Enrollment Token**
```http
DELETE /jet/agent-enrollment/tokens/{token_id}
Authorization: Bearer <admin_token>

Response (204 No Content)
```

**4. Agent Enrollment (Public Endpoint)**
```http
POST /jet/agent-enrollment/enroll
Content-Type: application/json

Request:
{
  "enrollment_token": "string",
  "agent_name": "string",
  "csr_pem": "string"
}

Response (200 OK):
{
  "agent_id": "uuid",
  "agent_name": "string",
  "client_cert_pem": "string",
  "gateway_ca_cert_pem": "string",
  "gateway_tunnel_url": "string"
}

Error Response (400/401/403):
{
  "error": "string"
}
```

**5. Get Gateway CA Certificate (Public)**
```http
GET /jet/agent-enrollment/ca.pem

Response (200 OK):
Content-Type: application/x-pem-file

-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

#### Modified Endpoints

**6. List Agents (Enhanced)**
```http
GET /jet/agent-tunnel/agents
Authorization: Bearer <admin_token>

Response (200 OK):
{
  "agents": [
    {
      "agent_id": "uuid",
      "name": "string",
      "cert_fingerprint": "string",  // NEW
      "enrolled_at": "ISO8601 timestamp",
      "online": boolean,
      "last_seen_at": "ISO8601 timestamp | null",  // NEW
      "advertised_subnets": ["CIDR", ...],
      "active_streams": number,
      "revoked": boolean  // NEW
    }
  ]
}
```

**7. Revoke Agent**
```http
POST /jet/agent-tunnel/agents/{agent_id}/revoke
Authorization: Bearer <admin_token>

Response (204 No Content)
```

**8. Remove Agent**
```http
DELETE /jet/agent-tunnel/agents/{agent_id}
Authorization: Bearer <admin_token>

Response (204 No Content)
```

### Performance Targets and Load Testing

#### Performance Targets (Non-Functional Requirements)

**Latency targets:**
- **Control plane**: Route advertisement processing < 100ms p99
- **Data plane**: Proxy connection establishment < 500ms p99
- **Additional latency vs direct connection**: < 20ms p50, < 50ms p99

**Throughput targets:**
- **Per-stream throughput**: Match underlying TCP connection (no artificial throttling)
- **Aggregate gateway throughput**: > 1 Gbps with 100 concurrent agents
- **Small packet performance**: > 10,000 packets/sec for SSH-like workloads

**Scalability targets:**
- **Concurrent agents**: 1,000 agents per gateway instance
- **Streams per agent**: 100 concurrent streams per agent
- **Total concurrent streams**: 10,000 streams per gateway instance

**Resource targets:**
- **Gateway memory**: < 100 MB baseline + < 10 MB per 100 agents
- **Agent memory**: < 50 MB baseline + < 1 MB per 10 active streams
- **Gateway CPU**: < 20% with 100 agents, < 2 active streams each

**Reliability targets:**
- **Connection stability**: SSH sessions survive > 1 hour without corruption
- **Reconnection time**: < 5 seconds to re-establish tunnel after network disruption
- **Packet loss resilience**: Maintain stability with < 5% packet loss

#### Phase 4 Load Testing Specification

**Test Environment:**
```
- Gateway: 4 CPU, 8 GB RAM
- Agents: 100 instances (can be containerized)
- Network: Simulated latency (10ms), packet loss (1%)
```

**Test Scenarios:**

**Test 1: Connection Establishment**
```bash
# Goal: Verify enrollment and connection performance
# Success criteria: All agents connect within 30 seconds

for i in {1..100}; do
  TOKEN=$(curl -X POST http://gateway:7171/jet/agent-enrollment/tokens \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"name":"agent-'$i'","validity_duration_secs":3600}' \
    | jq -r '.enrollment_token')

  devolutions-agent enroll \
    --gateway https://gateway:443 \
    --token "$TOKEN" \
    --name "load-test-agent-$i" &
done

wait
```

**Test 2: Concurrent Streams**
```bash
# Goal: Verify stream multiplexing performance
# Success criteria: All streams establish successfully, no corruption

# Start 100 agents, each with 10 concurrent SSH sessions
for agent in agent-{1..100}; do
  for stream in {1..10}; do
    ssh -o ProxyCommand="devolutions-agent proxy $agent %h %p" \
      192.168.1.100 \
      'dd if=/dev/urandom bs=1M count=100' > /dev/null &
  done
done

wait
# Verify: No connection errors, all transfers complete
```

**Test 3: Sustained Load**
```bash
# Goal: Verify long-running connection stability
# Success criteria: All sessions remain stable for 1 hour

for agent in agent-{1..100}; do
  ssh -o ProxyCommand="devolutions-agent proxy $agent %h %p" \
    192.168.1.100 \
    'top -b -d 1' > /dev/null &
done

# Monitor for 1 hour
sleep 3600

# Verify: No sessions crashed, no corrupted output
```

**Test 4: Reconnection Under Packet Loss**
```bash
# Goal: Verify QUIC reliability under adverse conditions
# Success criteria: Sessions recover automatically, no manual intervention

# Inject 5% packet loss
sudo tc qdisc add dev eth0 root netem loss 5%

# Run SSH session
ssh -o ProxyCommand="devolutions-agent proxy agent-1 %h %p" \
  192.168.1.100 \
  'while true; do date; sleep 1; done'

# Verify: Output continues despite packet loss, no corruption
```

**Test 5: Agent Restart Resilience**
```bash
# Goal: Verify reconnection after agent restart
# Success criteria: New sessions work after restart, old sessions gracefully fail

# Start agent and establish sessions
devolutions-agent --config agent.toml &
AGENT_PID=$!

ssh -o ProxyCommand="devolutions-agent proxy agent-1 %h %p" \
  192.168.1.100 \
  'sleep 300' &
OLD_SESSION=$!

sleep 10

# Restart agent
kill $AGENT_PID
devolutions-agent --config agent.toml &

sleep 5

# Verify: Old session terminates, new sessions work
! wait $OLD_SESSION  # Should fail

ssh -o ProxyCommand="devolutions-agent proxy agent-1 %h %p" \
  192.168.1.100 \
  'echo "New session works"'
```

**Performance Metrics to Collect:**
```rust
// devolutions-gateway/src/agent_tunnel/metrics.rs

pub struct TunnelMetrics {
    // Connection metrics
    pub total_agents_connected: AtomicU64,
    pub agents_currently_online: AtomicU64,
    pub total_enrollments: AtomicU64,
    pub failed_enrollments: AtomicU64,

    // Stream metrics
    pub streams_opened_total: AtomicU64,
    pub streams_currently_active: AtomicU64,
    pub streams_failed_total: AtomicU64,

    // Latency histograms (p50, p95, p99)
    pub control_msg_latency: Histogram,
    pub stream_establish_latency: Histogram,

    // Throughput
    pub bytes_sent_total: AtomicU64,
    pub bytes_received_total: AtomicU64,

    // Errors
    pub connection_errors_total: AtomicU64,
    pub stream_errors_total: AtomicU64,
    pub cert_validation_failures: AtomicU64,
}
```

### Migration Strategy from WireGuard

**v1 does NOT support dual-mode operation.** Clean cutover approach:

#### Migration Path

**Phase 1: Deploy QUIC Gateway (parallel to WireGuard)**
```bash
# Deploy QUIC gateway on separate port temporarily
[agent_tunnel]
listen_url = "https://0.0.0.0:4443"  # Non-conflicting port

# Existing WireGuard continues on UDP 51820
[wireguard]
listen_addr = "0.0.0.0:51820"
```

**Phase 2: Enroll Test Agents on QUIC**
```bash
# Provision test agents using new enrollment flow
# Run parallel validation (both WireGuard and QUIC agents active)
```

**Phase 3: Migrate Production Agents**
```bash
# For each agent:
1. Generate new enrollment token
2. Run enrollment: `devolutions-agent enroll --token <TOKEN>`
3. Restart agent to use QUIC tunnel
4. Verify connectivity
5. Remove old WireGuard agent record
```

**Phase 4: Remove WireGuard Code**
```bash
# After all agents migrated:
1. Stop exposing UDP 51820
2. Remove [wireguard] config section
3. Delete wireguard-related code (future PR)
4. Remove wireguard dependencies from Cargo.toml
```

#### Feature Flag Strategy

**NOT RECOMMENDED for v1.** WireGuard and QUIC are architecturally incompatible (different auth, different protocol, different state management).

If dual-mode is required (v2 consideration):
```rust
// Cargo.toml
[features]
default = ["agent-tunnel-quic"]
agent-tunnel-quic = ["quiche", "rustls"]
agent-tunnel-wireguard = ["wireguard-tunnel"]  # Legacy

// devolutions-gateway/src/lib.rs
#[cfg(feature = "agent-tunnel-quic")]
pub mod agent_tunnel;

#[cfg(feature = "agent-tunnel-wireguard")]
pub mod wireguard;
```

#### Rollback Plan

**If QUIC v1 fails in production:**

1. **Immediate**: Revert gateway deployment to last WireGuard build
2. **Agents**: Roll back agent binaries (agents automatically reconnect)
3. **Data**: Agent enrollment tokens and records are separate (no data loss)
4. **Decision Point**: Conduct post-mortem, address failure root cause

**Critical:** Test rollback procedure in Phase 0/1 to ensure it works.

## Migration Checklist

Use this checklist to track the migration:

### Phase 0: Foundation
- [ ] Create `feat/quic-agent-tunnel-v1` branch from `master`
- [ ] Add quiche + tokio-quiche dependencies
- [ ] Write minimal POC (gateway + agent QUIC connection)
- [ ] Verify mTLS client cert authentication works
- [ ] Validate `top` command doesn't crash over QUIC

### Phase 1: Protocol
- [ ] Create `crates/agent-tunnel-proto/`
- [ ] Define `ControlMessage` enum with RouteAdvertise/Heartbeat
- [ ] Define `ConnectMessage` and `ConnectResponse`
- [ ] Implement length-prefix bincode encoding
- [ ] Write roundtrip property tests
- [ ] Benchmark encoding overhead

### Phase 2: Gateway
- [ ] Create `devolutions-gateway/src/agent_tunnel/` module
- [ ] Implement `AgentTunnelListener` with quiche
- [ ] Port agent registry from `wireguard/listener.rs`
- [ ] Port route selection from `wireguard/listener.rs`
- [ ] Implement control stream handler
- [ ] Implement data stream acceptor
- [ ] Integrate with `DgwState`
- [ ] Update `api/fwd.rs` to route via agent tunnel
- [ ] Migrate enrollment API to issue TLS certs
- [ ] Migrate agent status API

### Phase 3: Agent Client
- [ ] Create new `devolutions-gateway-agent/src/quic_tunnel.rs`
- [ ] Implement `QuicTunnelClient` with quiche
- [ ] Implement control stream sender (routes + heartbeat)
- [ ] Implement data stream handler (TCP bridging)
- [ ] Update enrollment flow to request cert
- [ ] Update config format for TLS identity
- [ ] Test reconnection after network interruption

### Phase 4: Testing & Validation
- [ ] Port test scripts from `WIREGUARD_TESTING.md`
- [ ] Run all reliability tests (top, large files, concurrent)
- [ ] Measure throughput vs WireGuard POC
- [ ] Measure latency overhead
- [ ] Test with constrained MTU (1280 bytes)
- [ ] Test certificate rotation
- [ ] Load test with 100+ concurrent agents
- [ ] Soak test (72 hour uptime)

### Phase 5: Documentation
- [ ] Update `FEATURE_BRANCH_MANUAL.md` for QUIC
- [ ] Document certificate management
- [ ] Document troubleshooting steps
- [ ] Update architecture diagrams
- [ ] Write deployment guide

### Phase 6: Integration (Future)
- [ ] Design FFI interface for .NET Agent
- [ ] Implement cdylib for Windows Agent
- [ ] Test memory safety of FFI boundary
- [ ] Document .NET integration

## WireGuard vs QUIC Feature Parity Matrix

| Feature | WireGuard POC | QUIC v1 | Status |
|---------|---------------|---------|--------|
| **Transport** |
| Encryption | ✅ WireGuard Noise | ✅ TLS 1.3 | Different but equivalent |
| Reliability | ❌ None (UDP lossy) | ✅ QUIC native | **QUIC wins** |
| Multiplexing | ✅ Custom stream_id | ✅ QUIC native | **QUIC simpler** |
| Flow control | ❌ None | ✅ QUIC native | **QUIC wins** |
| Connection migration | ❌ Not supported | ✅ Supported | **QUIC wins** |
| **Identity** |
| Agent auth | ✅ X25519 keypair | ✅ mTLS cert | Different but equivalent |
| Enrollment | ✅ Token-based | ✅ Token-based | Same |
| Rotation | ❌ Not implemented | ⚠️ TBD in v2 | Deferred |
| **Routing** |
| Subnet advertisement | ✅ Works | ✅ Same logic | Identical |
| Overlap resolution | ✅ Latest wins | ✅ Same logic | Identical |
| Agent selection | ✅ Works | ✅ Same logic | Identical |
| Validation | ✅ Works | ✅ Same logic | Identical |
| **Operations** |
| Agent status API | ✅ Works | ✅ Same API | Identical |
| Web UI enrollment | ✅ Works | ✅ Same UX | Identical |
| Logging | ✅ Works | ✅ Same semantics | Identical |
| Metrics | ⚠️ Limited | ✅ QUIC built-in | **QUIC better** |
| **Reliability** |
| SSH basic | ✅ Works | ✅ Works | Same |
| top command | ❌ **Crashes** | ✅ **Should work** | **Main fix** |
| Large transfers | ⚠️ Unstable | ✅ Stable | **QUIC wins** |
| Network changes | ❌ Disconnects | ✅ Migrates | **QUIC wins** |
| **Deployment** |
| Port requirement | UDP 51820 | UDP 443 (or 4433) | Different |
| Firewall friendly | ⚠️ Medium | ✅ High (looks like HTTPS) | **QUIC wins** |
| Linux agent | ✅ Works | ✅ Works | Same |
| Windows agent | ⚠️ Not integrated | ⚠️ Future | Same |

**Summary:** QUIC improves reliability and operations while maintaining feature parity on routing and security.

## References and Prior Art

### Cloudflare's Migration (Our Exact Scenario)
- Blog: https://blog.cloudflare.com/zero-trust-warp-with-a-masque/
- Key quote: "We migrated Cloudflare WARP from WireGuard to MASQUE using quiche"
- Same problems: UDP reliability, MTU issues, firewall friendliness
- Same solution: QUIC with custom control protocol (not full RFC MASQUE)

### Apple's MASQUE Implementation
- WWDC talk: https://developer.apple.com/videos/play/wwdc2023/10002/
- Uses quiche under the hood
- mTLS client certificates for device identity
- Connection migration for seamless roaming

### Existing WireGuard Docs (In This Repo)
- [FEATURE_BRANCH_MANUAL.md](D:\devolutions-gateway\FEATURE_BRANCH_MANUAL.md) - User enrollment guide
- [WIREGUARD_TESTING.md](D:\devolutions-gateway\WIREGUARD_TESTING.md) - Test scenarios (all reusable)
- [docs/WIREGUARD_AGENT_TECH_SPEC.md](D:\devolutions-gateway\docs\WIREGUARD_AGENT_TECH_SPEC.md) - Architecture details (deleted but on branch)

### QUIC/MASQUE RFCs
- RFC 9000: QUIC Transport
- RFC 9001: QUIC + TLS 1.3
- RFC 9298: CONNECT-UDP (MASQUE)
- RFC 9484: CONNECT-IP (Extended MASQUE)

All references confirm: Raw QUIC streams with custom control protocol is a valid, proven approach for v1.

## Codex Review Comments

***(comment by Codex) Overall

The document is materially better now.
It moved from a high-level opinion note into something that can support an engineering review.

The strongest improvement is that it now clearly separates:

- control-plane semantics we want to preserve
- transport-layer implementation we want to replace

That is the correct architectural split.

The main weakness is that several code samples read too much like implementation-ready code even though they are really design sketches.
That is most visible in the QUIC and certificate sections.

I recommend keeping those samples, but marking them clearly as pseudocode or illustrative structure.

***(comment by Codex) Position

I agree with this section.

The branch recommendation is now clear and internally consistent:

- new branch from `master`
- old WireGuard branch as reference only

That is the correct framing if the team is intentionally choosing a clean rewrite instead of an incremental transport swap.

***(comment by Codex) Why I Favor a Rewrite

This section is strong.
The repo-grounding is good, and the central argument is correct: the current implementation is WireGuard-shaped across config, runtime state, persistence, APIs, and stream handling.

One sentence in the deep-dive framing is too absolute:

- "If any UDP packet is lost, the inner TCP connection receives permanent gaps but cannot detect them"

The core reliability criticism is valid, but the more precise statement is:

- the tunnel does not preserve a single reliable byte stream
- packet loss at the relay layer turns into corruption, instability, or session breakage instead of orderly retransmission by the tunnel transport

I would tighten that wording.

***(comment by Codex) Deep Dive: WireGuard-Specific Constraints

This subsection is useful.
It explains why the rewrite is not just about replacing cryptography but about removing an entire workaround stack that exists only because the current tunnel is datagram-based.

I agree with the thrust of this section.

***(comment by Codex) What Should Be Reused Conceptually

I agree with this section.

This is the right reuse boundary:

- keep route advertisement semantics
- keep opt-in `jet_agent_id`
- keep online/offline and reachability semantics
- keep enrollment-token semantics
- keep the expectation that the forwarding path ultimately wants a stream abstraction

That is exactly the right level of continuity.

***(comment by Codex) Concrete Examples to Preserve

The route advertisement and agent-selection examples are worth keeping.

The main correction here is that some wording overstates literal reuse.
For example, "Keep this exact logic" is too strong if interpreted as copy-paste implementation guidance.

The right claim is:

- these behaviors and algorithms are strong candidates for direct semantic reuse
- surrounding type models, timestamps, registry shapes, and lifecycle handling will still need fresh design

Also, the enrollment token example does not match the current repository closely enough.
The real implementation in [enrollment_store.rs](D:\devolutions-gateway\devolutions-gateway\src\enrollment_store.rs) is based on hashed persisted token records, not the simplified struct shown in the note.
That example should be corrected so reviewers do not flag it as inconsistent with the repo.

***(comment by Codex) What Should Not Be Reused

I agree with all of the items in this section.

One nuance: `stream_id` should be removed as the transport multiplexing primitive, but some separate correlation identifier may still be useful at the control or logging layer.
So I would phrase this as:

- do not preserve `stream_id` as the data-plane multiplexing mechanism

That would be more precise.

***(comment by Codex) Important Terminology Correction

I agree completely with this section.

If v1 uses raw QUIC streams with custom framing, then it should not be presented as full MASQUE.
Calling it:

- QUIC-based agent tunnel
- MASQUE-inspired tunnel
- QUIC tunnel v1

is much more accurate and will prevent avoidable design-review confusion.

***(comment by Codex) Branch Recommendation

I agree with this section.

The rewrite argument and the branch strategy now line up properly.
This is much cleaner than trying to hedge between refactor-first and rewrite-first.

***(comment by Codex) Practical Architecture for v1

The architecture direction is good.

I agree with:

- long-lived agent connection
- dedicated control stream
- one QUIC bidi stream per proxied TCP session
- route and agent registry free of WireGuard naming

The main issue is the code samples.
Several of them read as if the exact `quiche` API shape is already known.
That is not yet justified.

I recommend relabeling those snippets as:

- pseudocode
- conceptual module sketch
- non-final API draft

That will make the note technically safer.

***(comment by Codex) Gateway Side

I agree with the architecture here.

The rename in `DgwState` from `wireguard_listener` to `agent_tunnel_listener` is a good and concrete recommendation.

My main caution is naming the core object `AgentTunnelListener` too early.
Depending on the chosen QUIC integration model, the central object may feel more like:

- a connection manager
- a gateway-side agent tunnel service
- a QUIC acceptor plus registry

That is a small issue, but worth leaving flexible until the library spike is complete.

***(comment by Codex) Agent Side

The overall flow is correct:

- persistent outbound connection
- immediate control-stream bring-up
- route advertisement
- heartbeat
- per-session incoming streams bridged to TCP

One thing to add explicitly is half-close semantics.
For protocols like SSH, graceful shutdown behavior matters.
The design note should at least mention that stream close handling must preserve sane half-close behavior.

Also, `tokio::io::copy_bidirectional` is a valid intended behavior, but not necessarily a direct drop-in depending on the concrete QUIC stream wrapper that ends up being used.

***(comment by Codex) Enrollment

I agree with the direction.

Keeping the token issuance flow and replacing the returned identity material is the right move.

What still needs more explicit treatment is certificate lifecycle:

- issuance
- renewal
- revocation
- trust anchor distribution

The note mentions some of this later, but this section would be stronger if it acknowledged that certificate lifecycle is a first-class design concern, not just an implementation detail.

***(comment by Codex) Recommended Protocol Shape

This is one of the strongest sections in the document.

The split is correct:

- structured control stream
- per-session QUIC data streams
- no `DATA` or `CLOSE` framing after connect handshake

That is the cleanest protocol model for this codebase if the team is doing a rewrite.

***(comment by Codex) Control Stream

The proposed message types are reasonable.

My main comment is about `bincode`.
It is a pragmatic choice for Rust-to-Rust v1, but it should be presented as a tradeoff, not as an obviously settled choice.

If the protocol uses `bincode`, the note should explicitly require:

- a protocol version field
- compatibility policy between agent and gateway versions

Without that, the format choice is too casual.

***(comment by Codex) Data Streams

I agree with the design here.

The one claim I would remove is the numeric framing-overhead estimate.
The line about saving "~7MB" over a 100MB transfer is too specific and not defensible without a chunk-size assumption.

The real benefit is:

- less unnecessary application framing
- fewer copies and less buffer choreography
- simpler and more direct byte forwarding

That argument is strong enough without speculative numbers.

***(comment by Codex) What the Existing Branch Is Still Good For

I agree with this section entirely.

It correctly positions the WireGuard branch as:

- product reference
- UX reference
- routing-semantics reference
- testing reference

That is exactly how it should be used if the implementation is rebuilt cleanly.

***(comment by Codex) Suggested Module Layout

The layout is reasonable as a starting point.

My only comment is internal consistency.
The note uses both `connect.rs` and `session.rs` in different places.
Pick one structure and stick to it throughout the document so the proposed module tree feels deliberate.

***(comment by Codex) Scope I Would Enforce for v1

This section is strong and necessary.

I agree with the scope cuts:

- Linux first
- TCP only
- standalone Rust agent first
- no full MASQUE
- no Windows host integration in v1

Those are the right constraints if the team wants a real chance of delivering inside two months.

***(comment by Codex) Risk Assessment

This section is good, but one risk should be made more explicit:

- QUIC library fit risk

Not just "QUIC is hard", but:

- the chosen QUIC stack may not fit the runtime, observability, deployment model, or engineering velocity as well as expected

That is important because it can reshape the whole implementation plan.

***(comment by Codex) Suggested Delivery Sequence

The sequence is mostly good.

I like that product-host integration is pushed to the end.
That is the right dependency order.

I would only add one early checkpoint:

- prove the chosen QUIC stack works in the actual deployment model, not just in a lab POC

That should happen very early.

***(comment by Codex) Phase 0: QUIC Stack Integration

This phase is a very good idea.
It is exactly the right place to kill the biggest unknowns first.

The validation criteria are useful, but some are too specific for a planning note.
For example, "<10ms overhead vs raw TCP" is better written as:

- measure and compare latency overhead against direct TCP and the WireGuard POC

That keeps it empirical instead of sounding precommitted.

Also, the code samples here should be marked as pseudocode rather than example-ready source.

***(comment by Codex) Phase 1: Protocol Crate

This section is good.

The property-test direction is appropriate.
The large route-advertisement stress case is also a good inclusion.

No material objections here.

***(comment by Codex) Phase 2: Gateway Listener

This section points at the right integration seams:

- `DgwState`
- forwarding path
- route lookup and stream opening

Again, the main caution is not the architecture but the apparent concreteness of the example code.
The seams are correct even if the final types and constructors differ.

***(comment by Codex) Phase 3: Agent Client

This section is directionally correct.

The main addition I would make is a note about secure storage expectations for the new TLS identity material.
If the design returns cert and key material, the note should say what v1 expects operationally:

- file-based storage for Linux dev agents is acceptable in v1
- stronger host-integrated storage can come later

Without that, the example reads as if key persistence is trivial when it is actually a design choice.

***(comment by Codex) Phase 4: End-to-End Testing

The test scenarios are good and directly relevant.

The key correction is this:

- agent stop/start is reconnect, not QUIC connection migration

The note currently blurs:

- path migration
- reconnect after closure
- session survival across reconnect

Those are not the same thing.
If the agent process stops, existing proxied sessions usually do not survive automatically.
That distinction should be fixed.

***(comment by Codex) Technology Stack Deep Dive

This section is useful, but it sounds too certain in places.

My concern is not that `quiche` is a bad idea.
My concern is that the note reads as if the decision is already settled before the spike proves it.

I would present `quiche` as:

- preferred candidate
- strongest current hypothesis

not as an already-validated implementation choice.

***(comment by Codex) QUIC Library: quiche vs quinn vs s2n-quic

The comparison is helpful.

My main comment is practical:

- if the primary goal is to ship in two months, `quinn` deserves more consideration than this note gives it
- if the primary goal is lower-level control and closer MASQUE-adjacent transport work, `quiche` is the stronger candidate

That tradeoff should be resolved by Phase 0, not purely by architectural preference.

***(comment by Codex) Dependency Changes

Directionally fine, but too implementation-specific too early.

I would avoid committing to exact crate names and exact dependency removal until the spike confirms the architecture.
This section should feel tentative, not final.

***(comment by Codex) mTLS Certificate Architecture

The architecture direction is good.

The problem is that the code is too optimistic and too concrete.
Some of the certificate flow shown here is clearly pseudocode, but it is not labeled that way.

That includes:

- the `rcgen` signing flow
- certificate fingerprint helper calls
- the handshake certificate extraction examples

Keep the section, but explicitly label the code as illustrative pseudocode.

Also, storing certificate fingerprint in the agent record is reasonable, but serial number plus issuing CA context may be a cleaner operational identity anchor.

***(comment by Codex) Common Pitfalls to Avoid

This is a strong addition.
It makes the note much more reviewable because it now anticipates likely implementation mistakes.

I support keeping this section.

***(comment by Codex) Pitfall 1: Attempting to Preserve `VirtualTcpStream`

The warning is correct.

The specific example is too strong.
You should not assume a direct `quiche::stream::Stream` type is immediately usable as a Tokio `AsyncRead + AsyncWrite` stream in the final code.

The safer conclusion is:

- do not preserve the internal mechanics of `VirtualTcpStream`
- prefer a thin QUIC-stream adapter if one is needed

That keeps the architectural lesson without overcommitting on library API shape.

***(comment by Codex) Pitfall 2: Trying to Share UDP Port 443 with Existing TLS/HTTPS

This section needs correction.

TCP 443 and UDP 443 are different transport sockets and can normally coexist on the same host without `SO_REUSEPORT`.
That is not the real problem.

The real deployment questions are:

- does the hosting environment expose UDP 443
- do the current reverse-proxy or platform layers support UDP
- how are TLS certificates managed across the TCP and UDP entrypoints

So this section should be rewritten to focus on deployment and platform exposure, not socket coexistence.

***(comment by Codex) Pitfall 3: Not Handling QUIC Connection Migration

This section also needs correction.

It currently mixes:

- QUIC path migration
- reconnect after closed connection
- session continuity after reconnect

Those are separate concerns.

Also, enabling QUIC datagrams is not the same thing as enabling connection migration.
That specific linkage should be removed.

***(comment by Codex) Pitfall 4: Forgetting About MTU

I agree with the purpose of this section.

I would just phrase the benefits more carefully.
QUIC does not make MTU irrelevant, but it is a much better transport fit for this use case because it handles packetization, loss recovery, and flow control correctly at the tunnel layer.

***(comment by Codex) Final Recommendation

I agree with this section.

It is now consistent with the rest of the document and states the rewrite case cleanly.

***(comment by Codex) Code Size Estimate

I would weaken or remove this section.

The line counts, memory estimates, and some of the performance numbers are too speculative.
They look precise without being grounded enough to defend in review.

That kind of false precision weakens the stronger parts of the note.

If the section stays, it should be explicitly qualitative.

***(comment by Codex) Direct Code Reuse Opportunities

This section is useful, but the percentages are too aggressive.

I would replace terms like:

- 100% reusable

with terms like:

- high semantic reuse
- moderate structural reuse
- low literal code reuse

That would make the document more credible and more accurate.

***(comment by Codex) Migration Checklist

This section is practical and good.

I would add one Phase 0 item:

- prove how the QUIC service is actually hosted in the target deployment environment

That is a major real-world risk and should be surfaced early.

***(comment by Codex) WireGuard vs QUIC Feature Parity Matrix

The matrix is useful as a discussion aid.

A few cells overclaim:

- QUIC does not universally "look like HTTPS" in a way that guarantees firewall success
- QUIC may be faster, but that is not guaranteed
- connection migration should not be conflated with session survival after reconnect

Still, the matrix is helpful if treated as directional rather than contractual.

***(comment by Codex) References and Prior Art

This section is fine, but I would keep external references clearly secondary to repo-grounded arguments.
For this project, the strongest evidence is still the current codebase, not external blog analogies.

***(comment by Codex) Bottom Line

I support the overall direction of this revised note.

Before I would call it review-ready, I would make these concrete fixes:

- mark `quiche` and certificate code blocks as pseudocode
- fix the TCP/UDP 443 coexistence section
- fix the connection-migration versus reconnect section
- remove or soften speculative numeric claims
- correct the enrollment-token example so it matches the current repo
- tone down "100% reusable" wording to "semantically reusable"

With those changes, the note becomes a solid basis for architecture review.
