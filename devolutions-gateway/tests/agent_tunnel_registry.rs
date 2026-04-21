#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use agent_tunnel::registry::{AGENT_OFFLINE_TIMEOUT, AgentPeer, AgentRegistry};
use agent_tunnel_proto::{DomainAdvertisement, DomainName};
use ipnetwork::Ipv4Network;
use uuid::Uuid;

fn make_peer(name: &str) -> Arc<AgentPeer> {
    Arc::new(AgentPeer::new(
        Uuid::new_v4(),
        String::from(name),
        String::from("sha256:deadbeef"),
    ))
}

fn domain(name: &str, auto_detected: bool) -> DomainAdvertisement {
    DomainAdvertisement {
        domain: DomainName::new(name),
        auto_detected,
    }
}

#[tokio::test]
async fn register_and_lookup() {
    let registry = AgentRegistry::new();
    let peer = make_peer("test-agent");
    let agent_id = peer.agent_id;

    registry.register(Arc::clone(&peer)).await;
    assert_eq!(registry.len().await, 1);

    let found = registry.get(&agent_id).await.expect("agent should be found");
    assert_eq!(found.agent_id, agent_id);
}

#[tokio::test]
async fn unregister_removes_agent() {
    let registry = AgentRegistry::new();
    let peer = make_peer("test-agent");
    let agent_id = peer.agent_id;

    registry.register(Arc::clone(&peer)).await;
    let removed = registry.unregister(&agent_id).await;
    assert!(removed.is_some());
    assert_eq!(registry.len().await, 0);
    assert!(registry.get(&agent_id).await.is_none());
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
    peer.set_last_seen_for_test(0);
    assert!(!peer.is_online(AGENT_OFFLINE_TIMEOUT));
}

#[test]
fn update_routes_new_epoch_replaces() {
    let peer = make_peer("route-agent");
    let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

    peer.update_routes(1, vec![subnet], vec![]);
    let state = peer.route_state();
    assert_eq!(state.epoch, 1);
    assert_eq!(state.subnets.len(), 1);

    let new_subnet: Ipv4Network = "192.168.0.0/16".parse().expect("valid CIDR");
    peer.update_routes(2, vec![new_subnet], vec![]);
    let state = peer.route_state();
    assert_eq!(state.epoch, 2);
    assert_eq!(state.subnets.len(), 1);
    assert_eq!(state.subnets[0], new_subnet);
}

#[test]
fn update_routes_same_epoch_refreshes_only() {
    let peer = make_peer("refresh-agent");
    let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

    peer.update_routes(1, vec![subnet], vec![]);
    let state_before = peer.route_state();
    let received_at_before = state_before.received_at;

    let different_subnet: Ipv4Network = "172.16.0.0/12".parse().expect("valid CIDR");
    peer.update_routes(1, vec![different_subnet], vec![]);

    let state_after = peer.route_state();
    assert_eq!(state_after.epoch, 1);
    assert_eq!(state_after.subnets[0], subnet);
    assert_eq!(state_after.received_at, received_at_before);
    assert!(state_after.updated_at >= state_before.updated_at);
}

#[test]
fn update_routes_stale_epoch_ignored() {
    let peer = make_peer("stale-agent");
    let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

    peer.update_routes(5, vec![subnet], vec![]);
    let old_subnet: Ipv4Network = "172.16.0.0/12".parse().expect("valid CIDR");
    peer.update_routes(3, vec![old_subnet], vec![]);

    let state = peer.route_state();
    assert_eq!(state.epoch, 5);
    assert_eq!(state.subnets[0], subnet);
}

#[tokio::test]
async fn agent_infos_snapshot() {
    let registry = AgentRegistry::new();
    let peer = make_peer("info-agent");
    let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
    peer.update_routes(1, vec![subnet], vec![]);
    registry.register(peer).await;

    let infos = registry.agent_infos().await;
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].name, "info-agent");
    assert!(infos[0].is_online);
    assert_eq!(infos[0].subnets, vec!["10.0.0.0/8"]);
    assert_eq!(infos[0].route_epoch, 1);
}

#[tokio::test]
async fn online_count_accuracy() {
    let registry = AgentRegistry::new();

    let online_agent = make_peer("online");
    registry.register(Arc::clone(&online_agent)).await;

    let offline_agent = make_peer("offline");
    offline_agent.set_last_seen_for_test(0);
    registry.register(offline_agent).await;

    assert_eq!(registry.len().await, 2);
    assert_eq!(registry.online_count().await, 1);
}

#[tokio::test]
async fn default_trait_creates_empty_registry() {
    let registry = AgentRegistry::default();
    assert_eq!(registry.len().await, 0);
}

#[test]
fn update_routes_stores_domains_with_source() {
    let peer = make_peer("domain-agent");
    let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

    peer.update_routes(1, vec![subnet], vec![domain("contoso.local", false)]);
    let state = peer.route_state();
    assert_eq!(state.domains.len(), 1);
    assert_eq!(state.domains[0].domain.as_str(), "contoso.local");
    assert!(!state.domains[0].auto_detected);
}

#[test]
fn update_routes_new_epoch_replaces_domains() {
    let peer = make_peer("domain-agent");
    let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

    peer.update_routes(1, vec![subnet], vec![domain("old.local", false)]);
    peer.update_routes(2, vec![subnet], vec![domain("new.local", true)]);

    let state = peer.route_state();
    assert_eq!(state.epoch, 2);
    assert_eq!(state.domains[0].domain.as_str(), "new.local");
    assert!(state.domains[0].auto_detected);
}

#[test]
fn update_routes_same_epoch_preserves_domains() {
    let peer = make_peer("domain-agent");
    let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");

    peer.update_routes(1, vec![subnet], vec![domain("contoso.local", false)]);
    peer.update_routes(1, vec![subnet], vec![domain("different.local", true)]);

    let state = peer.route_state();
    assert_eq!(state.domains[0].domain.as_str(), "contoso.local");
    assert!(!state.domains[0].auto_detected);
}
