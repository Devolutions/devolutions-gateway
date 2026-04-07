use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use agent_tunnel_proto::DomainAdvertisement;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use parking_lot::RwLock;
use serde::Serialize;
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
    pub subnets: Vec<IpNetwork>,
    /// DNS domains this agent can resolve, with source tracking.
    pub domains: Vec<DomainAdvertisement>,
    /// When this route set was first received (used for tie-breaking).
    pub received_at: SystemTime,
    /// Last time this route set was refreshed.
    pub updated_at: SystemTime,
}

impl RouteAdvertisementState {
    /// Match this route set against a target host (IP or domain name).
    ///
    /// Returns a specificity score if matched, or `None` if no match.
    /// IP subnet matches return `usize::MAX` (always highest priority).
    /// Domain matches return the matched domain length (longer = more specific).
    pub fn matches_target(&self, target_host: &str) -> Option<usize> {
        use std::net::IpAddr;

        if let Ok(ip) = target_host.parse::<IpAddr>() {
            return self
                .subnets
                .iter()
                .any(|subnet| subnet.contains(ip))
                .then_some(usize::MAX);
        }

        self.domains
            .iter()
            .filter(|adv| adv.domain.matches_hostname(target_host))
            .map(|adv| adv.domain.as_str().len())
            .max()
    }
}

impl Default for RouteAdvertisementState {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            epoch: 0,
            subnets: Vec::new(),
            domains: Vec::new(),
            received_at: now,
            updated_at: now,
        }
    }
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
    pub last_seen: AtomicU64,
    /// Current route advertisement state.
    route_state: RwLock<RouteAdvertisementState>,
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
            route_state: RwLock::new(RouteAdvertisementState::default()),
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
        elapsed_ms < u64::try_from(timeout.as_millis()).expect("timeout in milliseconds should fit in u64")
    }

    /// Returns a clone of the current route advertisement state.
    pub fn route_state(&self) -> RouteAdvertisementState {
        self.route_state.read().clone()
    }

    /// Updates the route advertisement state using epoch-based logic.
    ///
    /// - If `epoch` is greater than the current epoch, the route set is replaced entirely
    ///   and both `received_at` and `updated_at` are set to now.
    /// - If `epoch` equals the current epoch, only `updated_at` is refreshed (re-advertisement).
    /// - If `epoch` is less than the current epoch, the update is ignored (stale).
    pub fn update_routes(&self, epoch: u64, subnets: Vec<IpNetwork>, domains: Vec<DomainAdvertisement>) {
        let mut state = self.route_state.write();
        let now = SystemTime::now();

        let current = &*state;

        if epoch < current.epoch {
            debug!(
                agent_id = %self.agent_id,
                received_epoch = epoch,
                current_epoch = current.epoch,
                "Ignoring stale route advertisement"
            );
        } else if epoch == current.epoch {
            // Same epoch: refresh timestamp only, do not replace subnets or domains.
            debug!(
                agent_id = %self.agent_id,
                epoch,
                subnet_count = subnets.len(),
                domain_count = state.domains.len(),
                "Refreshing route advertisement (same epoch)"
            );
            state.updated_at = now;
        } else {
            // New epoch (or first advertisement): replace everything.
            info!(
                agent_id = %self.agent_id,
                epoch,
                subnet_count = subnets.len(),
                domain_count = domains.len(),
                "Accepted new route advertisement"
            );
            *state = RouteAdvertisementState {
                epoch,
                subnets,
                domains,
                received_at: now,
                updated_at: now,
            };
        }
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
            "Agent registered"
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
                "Agent unregistered"
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

    /// Returns `true` when no agent is registered.
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Returns the number of agents considered online.
    pub fn online_count(&self) -> usize {
        self.agents
            .iter()
            .filter(|entry| entry.value().is_online(AGENT_OFFLINE_TIMEOUT))
            .count()
    }

    /// Returns information about a single agent by ID.
    pub fn agent_info(&self, agent_id: &Uuid) -> Option<AgentInfo> {
        self.agents.get(agent_id).map(|entry| AgentInfo::from(entry.value()))
    }

    /// Collects information about all registered agents for API responses.
    pub fn agent_infos(&self) -> Vec<AgentInfo> {
        self.agents.iter().map(|entry| AgentInfo::from(entry.value())).collect()
    }

    /// Find all online agents that can route to the given target host (IP or domain).
    ///
    /// For IP targets: matches against advertised subnets.
    /// For domain targets: uses longest suffix match (more specific domain wins).
    ///
    /// Results with equal specificity are sorted by `received_at` descending (most recent first).
    pub fn find_agents_for(&self, target_host: &str) -> Vec<Arc<AgentPeer>> {
        let mut best_specificity: usize = 0;
        let mut candidates: Vec<(SystemTime, Arc<AgentPeer>)> = Vec::new();

        for entry in self.agents.iter() {
            let agent = entry.value();
            if !agent.is_online(AGENT_OFFLINE_TIMEOUT) {
                continue;
            }

            let route_state = agent.route_state();

            if let Some(specificity) = route_state.matches_target(target_host) {
                if specificity > best_specificity {
                    best_specificity = specificity;
                    candidates.clear();
                    candidates.push((route_state.received_at, Arc::clone(agent)));
                } else if specificity == best_specificity {
                    candidates.push((route_state.received_at, Arc::clone(agent)));
                }
            }
        }

        candidates.sort_by(|a, b| b.0.cmp(&a.0));
        candidates.into_iter().map(|(_, agent)| agent).collect()
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
    pub domains: Vec<DomainAdvertisement>,
    pub route_epoch: u64,
}

impl From<&Arc<AgentPeer>> for AgentInfo {
    fn from(agent: &Arc<AgentPeer>) -> Self {
        let route_state = agent.route_state();
        Self {
            agent_id: agent.agent_id,
            name: agent.name.clone(),
            cert_fingerprint: agent.cert_fingerprint.clone(),
            is_online: agent.is_online(AGENT_OFFLINE_TIMEOUT),
            last_seen_ms: agent.last_seen_ms(),
            subnets: route_state.subnets.iter().map(ToString::to_string).collect(),
            domains: route_state.domains.clone(),
            route_epoch: route_state.epoch,
        }
    }
}

use agent_tunnel_proto::current_time_millis;
