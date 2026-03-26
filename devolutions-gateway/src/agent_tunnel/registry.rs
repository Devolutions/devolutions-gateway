use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use ipnetwork::Ipv4Network;
use parking_lot::RwLock;
use uuid::Uuid;

/// Duration after which an agent is considered offline if no heartbeat has been received.
pub const AGENT_OFFLINE_TIMEOUT: Duration = Duration::from_secs(90);

/// Tracks route advertisements received from an agent.
///
/// The epoch-based update protocol works as follows:
/// - A higher epoch replaces the entire route set (new process or config reload).
/// - The same epoch only refreshes `updated_at` (periodic re-advertisement).
#[derive(Debug, Clone)]
pub struct RouteAdvertisementState {
    /// Monotonically increasing epoch within an agent process lifetime.
    pub epoch: u64,
    /// IPv4 subnets this agent can reach.
    pub subnets: Vec<Ipv4Network>,
    /// When this route set was first received (used for tie-breaking).
    pub received_at: SystemTime,
    /// Last time this route set was refreshed.
    pub updated_at: SystemTime,
}

/// Represents a QUIC-connected agent peer tracked by the gateway.
#[derive(Debug)]
pub struct AgentPeer {
    /// Unique identifier for this agent.
    pub agent_id: Uuid,
    /// Human-readable name of the agent.
    pub name: String,
    /// SHA-256 fingerprint of the agent's client certificate.
    pub cert_fingerprint: String,
    /// Last heartbeat timestamp in milliseconds since UNIX epoch (updated atomically).
    last_seen: AtomicU64,
    /// Current route advertisement state, if any.
    route_state: RwLock<Option<RouteAdvertisementState>>,
}

impl AgentPeer {
    /// Creates a new agent peer with the current time as last_seen.
    pub fn new(agent_id: Uuid, name: String, cert_fingerprint: String) -> Self {
        let now_ms = current_time_millis();
        Self {
            agent_id,
            name,
            cert_fingerprint,
            last_seen: AtomicU64::new(now_ms),
            route_state: RwLock::new(None),
        }
    }

    /// Updates the last-seen timestamp to the current time.
    pub fn touch(&self) {
        let now_ms = current_time_millis();
        self.last_seen.store(now_ms, Ordering::Release);
    }

    /// Returns the last-seen timestamp as milliseconds since UNIX epoch.
    pub fn last_seen_ms(&self) -> u64 {
        self.last_seen.load(Ordering::Acquire)
    }

    /// Checks whether this agent is considered online.
    ///
    /// An agent is online if the elapsed time since `last_seen` is less than `timeout`.
    pub fn is_online(&self, timeout: Duration) -> bool {
        let last_ms = self.last_seen.load(Ordering::Acquire);
        let now_ms = current_time_millis();
        // Saturating subtraction handles clock skew gracefully.
        let elapsed_ms = now_ms.saturating_sub(last_ms);
        elapsed_ms < timeout.as_millis() as u64
    }

    /// Returns a clone of the current route advertisement state, if any.
    pub fn route_state(&self) -> Option<RouteAdvertisementState> {
        self.route_state.read().clone()
    }

    /// Updates the route advertisement state using epoch-based logic.
    ///
    /// - If `epoch` is greater than the current epoch, the route set is replaced entirely
    ///   and both `received_at` and `updated_at` are set to now.
    /// - If `epoch` equals the current epoch, only `updated_at` is refreshed (re-advertisement).
    /// - If `epoch` is less than the current epoch, the update is ignored (stale).
    pub fn update_routes(&self, epoch: u64, subnets: Vec<Ipv4Network>) {
        let mut state = self.route_state.write();
        let now = SystemTime::now();

        match state.as_ref() {
            Some(current) if epoch < current.epoch => {
                // Stale epoch; ignore.
                debug!(
                    agent_id = %self.agent_id,
                    received_epoch = epoch,
                    current_epoch = current.epoch,
                    "ignoring stale route advertisement"
                );
            }
            Some(current) if epoch == current.epoch => {
                // Same epoch: refresh timestamp only, do not replace subnets.
                debug!(
                    agent_id = %self.agent_id,
                    epoch,
                    subnet_count = subnets.len(),
                    "refreshing route advertisement (same epoch)"
                );
                // We must rebuild because `updated_at` changed, but subnets stay the same.
                *state = Some(RouteAdvertisementState {
                    epoch,
                    subnets: current.subnets.clone(),
                    received_at: current.received_at,
                    updated_at: now,
                });
            }
            _ => {
                // New epoch (or first advertisement): replace everything.
                info!(
                    agent_id = %self.agent_id,
                    epoch,
                    subnet_count = subnets.len(),
                    "accepted new route advertisement"
                );
                *state = Some(RouteAdvertisementState {
                    epoch,
                    subnets,
                    received_at: now,
                    updated_at: now,
                });
            }
        }
    }

    /// Returns `true` if this agent can route traffic to the given IP address.
    pub fn can_reach(&self, target_ip: IpAddr) -> bool {
        self.route_state
            .read()
            .as_ref()
            .map(|route_state| match target_ip {
                IpAddr::V4(ipv4) => route_state.subnets.iter().any(|subnet| subnet.contains(ipv4)),
                IpAddr::V6(_) => false,
            })
            .unwrap_or(false)
    }
}

/// Thread-safe registry of online QUIC-connected agents.
///
/// Agents are indexed by their `Uuid`. The registry supports concurrent reads and writes
/// through `DashMap`, and provides route-based agent lookup for proxy target resolution.
#[derive(Debug, Clone)]
pub struct AgentRegistry {
    agents: Arc<DashMap<Uuid, Arc<AgentPeer>>>,
}

impl AgentRegistry {
    /// Creates a new, empty agent registry.
    pub fn new() -> Self {
        Self {
            agents: Arc::new(DashMap::new()),
        }
    }

    /// Registers a new agent peer. If an agent with the same ID already exists, it is replaced.
    pub fn register(&self, peer: Arc<AgentPeer>) {
        info!(
            agent_id = %peer.agent_id,
            name = %peer.name,
            "agent registered"
        );
        self.agents.insert(peer.agent_id, peer);
    }

    /// Removes an agent from the registry by ID.
    pub fn unregister(&self, agent_id: &Uuid) -> Option<Arc<AgentPeer>> {
        let removed = self.agents.remove(agent_id).map(|(_, peer)| peer);
        if let Some(ref peer) = removed {
            info!(
                agent_id = %peer.agent_id,
                name = %peer.name,
                "agent unregistered"
            );
        }
        removed
    }

    /// Looks up an agent by ID.
    pub fn get(&self, agent_id: &Uuid) -> Option<Arc<AgentPeer>> {
        self.agents.get(agent_id).map(|entry| Arc::clone(entry.value()))
    }

    /// Returns the number of agents currently in the registry (including offline ones).
    pub fn len(&self) -> usize {
        self.agents.len()
    }

    /// Returns the number of agents considered online.
    pub fn online_count(&self) -> usize {
        self.agents
            .iter()
            .filter(|entry| entry.value().is_online(AGENT_OFFLINE_TIMEOUT))
            .count()
    }

    /// Finds all online agents whose advertised subnets include the given target IP.
    ///
    /// Results are sorted by `received_at` in descending order (most recently received first).
    pub fn find_agents_for_target(&self, target_ip: IpAddr) -> Vec<Arc<AgentPeer>> {
        let mut candidates: Vec<(SystemTime, Arc<AgentPeer>)> = self
            .agents
            .iter()
            .filter(|entry| entry.value().is_online(AGENT_OFFLINE_TIMEOUT))
            .filter_map(|entry| {
                let agent = Arc::clone(entry.value());
                let route_state = agent.route_state()?;
                let matches = match target_ip {
                    IpAddr::V4(ipv4) => route_state.subnets.iter().any(|subnet| subnet.contains(ipv4)),
                    IpAddr::V6(_) => false,
                };

                if matches {
                    Some((route_state.received_at, agent))
                } else {
                    None
                }
            })
            .collect();

        // Sort by received_at descending (most recent first).
        candidates.sort_by(|a, b| b.0.cmp(&a.0));

        candidates.into_iter().map(|(_, agent)| agent).collect()
    }

    /// Selects a single online agent that can route to the given target IP.
    ///
    /// When multiple agents match, the one with the most recent `received_at` wins.
    pub fn select_agent_for_target(&self, target_ip: IpAddr) -> Option<Arc<AgentPeer>> {
        self.agents
            .iter()
            .filter(|entry| entry.value().is_online(AGENT_OFFLINE_TIMEOUT))
            .filter_map(|entry| {
                let agent = Arc::clone(entry.value());
                let route_state = agent.route_state()?;
                let matches = match target_ip {
                    IpAddr::V4(ipv4) => route_state.subnets.iter().any(|subnet| subnet.contains(ipv4)),
                    IpAddr::V6(_) => false,
                };

                if matches {
                    Some((route_state.received_at, agent))
                } else {
                    None
                }
            })
            .max_by_key(|(received_at, _)| *received_at)
            .map(|(_, agent)| agent)
    }

    /// Returns information about a single agent by ID.
    pub fn agent_info(&self, agent_id: &Uuid) -> Option<AgentInfo> {
        self.agents.get(agent_id).map(|entry| {
            let agent = entry.value();
            let route_state = agent.route_state();
            AgentInfo {
                agent_id: agent.agent_id,
                name: agent.name.clone(),
                cert_fingerprint: agent.cert_fingerprint.clone(),
                is_online: agent.is_online(AGENT_OFFLINE_TIMEOUT),
                last_seen_ms: agent.last_seen_ms(),
                subnets: route_state
                    .as_ref()
                    .map(|rs| rs.subnets.iter().map(ToString::to_string).collect())
                    .unwrap_or_default(),
                route_epoch: route_state.as_ref().map(|rs| rs.epoch),
            }
        })
    }

    /// Collects information about all registered agents for API responses.
    pub fn agent_infos(&self) -> Vec<AgentInfo> {
        self.agents
            .iter()
            .map(|entry| {
                let agent = entry.value();
                let route_state = agent.route_state();
                AgentInfo {
                    agent_id: agent.agent_id,
                    name: agent.name.clone(),
                    cert_fingerprint: agent.cert_fingerprint.clone(),
                    is_online: agent.is_online(AGENT_OFFLINE_TIMEOUT),
                    last_seen_ms: agent.last_seen_ms(),
                    subnets: route_state
                        .as_ref()
                        .map(|rs| rs.subnets.iter().map(ToString::to_string).collect())
                        .unwrap_or_default(),
                    route_epoch: route_state.as_ref().map(|rs| rs.epoch),
                }
            })
            .collect()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable snapshot of an agent's state, suitable for API responses.
#[derive(Debug, Clone, Serialize)]
pub struct AgentInfo {
    pub agent_id: Uuid,
    pub name: String,
    pub cert_fingerprint: String,
    pub is_online: bool,
    pub last_seen_ms: u64,
    pub subnets: Vec<String>,
    pub route_epoch: Option<u64>,
}

/// Returns the current time as milliseconds since UNIX epoch.
fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(name: &str) -> Arc<AgentPeer> {
        Arc::new(AgentPeer::new(
            Uuid::new_v4(),
            String::from(name),
            String::from("sha256:deadbeef"),
        ))
    }

    #[test]
    fn register_and_lookup() {
        let registry = AgentRegistry::new();
        let peer = make_peer("test-agent");
        let agent_id = peer.agent_id;

        registry.register(Arc::clone(&peer));
        assert_eq!(registry.len(), 1);

        let found = registry.get(&agent_id).expect("agent should be found");
        assert_eq!(found.agent_id, agent_id);
    }

    #[test]
    fn unregister_removes_agent() {
        let registry = AgentRegistry::new();
        let peer = make_peer("test-agent");
        let agent_id = peer.agent_id;

        registry.register(Arc::clone(&peer));
        let removed = registry.unregister(&agent_id);
        assert!(removed.is_some());
        assert_eq!(registry.len(), 0);
        assert!(registry.get(&agent_id).is_none());
    }

    #[test]
    fn is_online_within_timeout() {
        let peer = make_peer("online-agent");
        peer.touch();
        assert!(peer.is_online(AGENT_OFFLINE_TIMEOUT));
    }

    #[test]
    fn is_offline_after_timeout() {
        let peer = AgentPeer::new(
            Uuid::new_v4(),
            String::from("offline-agent"),
            String::from("sha256:deadbeef"),
        );
        // Simulate a very old last_seen timestamp.
        peer.last_seen.store(0, Ordering::Release);
        assert!(!peer.is_online(AGENT_OFFLINE_TIMEOUT));
    }

    #[test]
    fn update_routes_new_epoch_replaces() {
        let peer = make_peer("route-agent");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

        peer.update_routes(1, vec![subnet]);
        let state = peer.route_state().expect("route state should exist");
        assert_eq!(state.epoch, 1);
        assert_eq!(state.subnets.len(), 1);

        let new_subnet: Ipv4Network = "192.168.0.0/16".parse().expect("valid CIDR");
        peer.update_routes(2, vec![new_subnet]);
        let state = peer.route_state().expect("route state should exist");
        assert_eq!(state.epoch, 2);
        assert_eq!(state.subnets.len(), 1);
        assert_eq!(state.subnets[0], new_subnet);
    }

    #[test]
    fn update_routes_same_epoch_refreshes_only() {
        let peer = make_peer("refresh-agent");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

        peer.update_routes(1, vec![subnet]);
        let state_before = peer.route_state().expect("route state should exist");
        let received_at_before = state_before.received_at;

        // Same epoch with different subnets should NOT replace subnets.
        let different_subnet: Ipv4Network = "172.16.0.0/12".parse().expect("valid CIDR");
        peer.update_routes(1, vec![different_subnet]);

        let state_after = peer.route_state().expect("route state should exist");
        assert_eq!(state_after.epoch, 1);
        // Subnets should remain unchanged (original advertisement).
        assert_eq!(state_after.subnets[0], subnet);
        // received_at should remain unchanged.
        assert_eq!(state_after.received_at, received_at_before);
        // updated_at should have been refreshed.
        assert!(state_after.updated_at >= state_before.updated_at);
    }

    #[test]
    fn update_routes_stale_epoch_ignored() {
        let peer = make_peer("stale-agent");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

        peer.update_routes(5, vec![subnet]);
        let old_subnet: Ipv4Network = "172.16.0.0/12".parse().expect("valid CIDR");
        peer.update_routes(3, vec![old_subnet]);

        let state = peer.route_state().expect("route state should exist");
        assert_eq!(state.epoch, 5);
        assert_eq!(state.subnets[0], subnet);
    }

    #[test]
    fn can_reach_matching_subnet() {
        let peer = make_peer("reachable-agent");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        peer.update_routes(1, vec![subnet]);

        assert!(peer.can_reach("10.1.2.3".parse().expect("valid IP")));
        assert!(!peer.can_reach("192.168.1.1".parse().expect("valid IP")));
    }

    #[test]
    fn can_reach_returns_false_for_ipv6() {
        let peer = make_peer("v4-only-agent");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        peer.update_routes(1, vec![subnet]);

        assert!(!peer.can_reach("::1".parse().expect("valid IP")));
    }

    #[test]
    fn select_agent_for_target_picks_most_recent() {
        let registry = AgentRegistry::new();

        let agent_a = make_peer("agent-a");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        agent_a.update_routes(1, vec![subnet]);
        registry.register(Arc::clone(&agent_a));

        // Small delay to ensure different received_at timestamps.
        std::thread::sleep(Duration::from_millis(10));

        let agent_b = make_peer("agent-b");
        agent_b.update_routes(1, vec![subnet]);
        registry.register(Arc::clone(&agent_b));

        let target: IpAddr = "10.5.5.5".parse().expect("valid IP");
        let winner = registry.select_agent_for_target(target).expect("should find an agent");
        // agent_b was registered later, so its received_at is more recent.
        assert_eq!(winner.agent_id, agent_b.agent_id);
    }

    #[test]
    fn find_agents_for_target_returns_sorted() {
        let registry = AgentRegistry::new();

        let agent_a = make_peer("agent-a");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        agent_a.update_routes(1, vec![subnet]);
        registry.register(Arc::clone(&agent_a));

        std::thread::sleep(Duration::from_millis(10));

        let agent_b = make_peer("agent-b");
        agent_b.update_routes(1, vec![subnet]);
        registry.register(Arc::clone(&agent_b));

        let target: IpAddr = "10.5.5.5".parse().expect("valid IP");
        let agents = registry.find_agents_for_target(target);
        assert_eq!(agents.len(), 2);
        // Most recent first.
        assert_eq!(agents[0].agent_id, agent_b.agent_id);
        assert_eq!(agents[1].agent_id, agent_a.agent_id);
    }

    #[test]
    fn find_agents_excludes_offline() {
        let registry = AgentRegistry::new();

        let agent = make_peer("offline-agent");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        agent.update_routes(1, vec![subnet]);
        // Force agent to appear offline.
        agent.last_seen.store(0, Ordering::Release);
        registry.register(agent);

        let target: IpAddr = "10.5.5.5".parse().expect("valid IP");
        let agents = registry.find_agents_for_target(target);
        assert!(agents.is_empty());
    }

    #[test]
    fn agent_infos_snapshot() {
        let registry = AgentRegistry::new();
        let peer = make_peer("info-agent");
        let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        peer.update_routes(1, vec![subnet]);
        registry.register(peer);

        let infos = registry.agent_infos();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "info-agent");
        assert!(infos[0].is_online);
        assert_eq!(infos[0].subnets, vec!["10.0.0.0/8"]);
        assert_eq!(infos[0].route_epoch, Some(1));
    }

    #[test]
    fn online_count_accuracy() {
        let registry = AgentRegistry::new();

        let online_agent = make_peer("online");
        registry.register(Arc::clone(&online_agent));

        let offline_agent = make_peer("offline");
        offline_agent.last_seen.store(0, Ordering::Release);
        registry.register(offline_agent);

        assert_eq!(registry.len(), 2);
        assert_eq!(registry.online_count(), 1);
    }

    #[test]
    fn default_trait_creates_empty_registry() {
        let registry = AgentRegistry::default();
        assert_eq!(registry.len(), 0);
    }
}
