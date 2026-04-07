#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use agent_tunnel_proto::{DomainAdvertisement, DomainName};
use devolutions_gateway::agent_tunnel::registry::{AgentPeer, AgentRegistry};
use devolutions_gateway::agent_tunnel::routing::{RoutingDecision, resolve_route};
use ipnetwork::IpNetwork;
use uuid::Uuid;

fn make_peer(name: &str) -> Arc<AgentPeer> {
    Arc::new(AgentPeer::new(
        Uuid::new_v4(),
        name.to_owned(),
        "sha256:test".to_owned(),
    ))
}

fn domain(name: &str) -> DomainAdvertisement {
    DomainAdvertisement {
        domain: DomainName::new(name),
        auto_detected: false,
    }
}

#[test]
fn route_explicit_agent_id() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let agent_id = peer.agent_id;
    registry.register(Arc::clone(&peer));

    match resolve_route(&registry, Some(agent_id), "anything") {
        RoutingDecision::ViaAgent(agents) => {
            assert_eq!(agents.len(), 1);
            assert_eq!(agents[0].agent_id, agent_id);
        }
        other => panic!("expected ViaAgent, got {other:?}"),
    }
}

#[test]
fn route_explicit_agent_id_not_found() {
    let registry = AgentRegistry::new();
    let bogus_id = Uuid::new_v4();

    match resolve_route(&registry, Some(bogus_id), "anything") {
        RoutingDecision::ExplicitAgentNotFound(id) => {
            assert_eq!(id, bogus_id);
        }
        other => panic!("expected ExplicitAgentNotFound, got {other:?}"),
    }
}

#[test]
fn route_ip_target_via_subnet() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let agent_id = peer.agent_id;
    let subnet: IpNetwork = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![]);
    registry.register(peer);

    match resolve_route(&registry, None, "10.1.5.50") {
        RoutingDecision::ViaAgent(agents) => {
            assert_eq!(agents[0].agent_id, agent_id);
        }
        other => panic!("expected ViaAgent, got {other:?}"),
    }
}

#[test]
fn route_hostname_via_domain() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let agent_id = peer.agent_id;
    let subnet: IpNetwork = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![domain("contoso.local")]);
    registry.register(peer);

    match resolve_route(&registry, None, "dc01.contoso.local") {
        RoutingDecision::ViaAgent(agents) => {
            assert_eq!(agents[0].agent_id, agent_id);
        }
        other => panic!("expected ViaAgent, got {other:?}"),
    }
}

#[test]
fn route_no_match_returns_direct() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let subnet: IpNetwork = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![domain("contoso.local")]);
    registry.register(peer);

    assert!(matches!(
        resolve_route(&registry, None, "external.example.com"),
        RoutingDecision::Direct
    ));
}

#[test]
fn route_ip_no_match_returns_direct() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let subnet: IpNetwork = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![]);
    registry.register(peer);

    assert!(matches!(
        resolve_route(&registry, None, "192.168.1.1"),
        RoutingDecision::Direct
    ));
}

#[test]
fn route_skips_offline_agents() {
    let registry = AgentRegistry::new();
    let peer = make_peer("offline-agent");
    let subnet: IpNetwork = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![domain("contoso.local")]);
    peer.last_seen.store(0, Ordering::Release);
    registry.register(peer);

    assert!(matches!(
        resolve_route(&registry, None, "dc01.contoso.local"),
        RoutingDecision::Direct
    ));
}

#[test]
fn route_domain_match_returns_multiple_agents_ordered() {
    let registry = AgentRegistry::new();

    let peer_a = make_peer("agent-a");
    let subnet_a: IpNetwork = "10.1.0.0/16".parse().expect("valid test subnet");
    peer_a.update_routes(1, vec![subnet_a], vec![domain("contoso.local")]);
    registry.register(Arc::clone(&peer_a));

    std::thread::sleep(std::time::Duration::from_millis(10));

    let peer_b = make_peer("agent-b");
    let id_b = peer_b.agent_id;
    let subnet_b: IpNetwork = "10.2.0.0/16".parse().expect("valid test subnet");
    peer_b.update_routes(1, vec![subnet_b], vec![domain("contoso.local")]);
    registry.register(Arc::clone(&peer_b));

    match resolve_route(&registry, None, "dc01.contoso.local") {
        RoutingDecision::ViaAgent(agents) => {
            assert_eq!(agents.len(), 2);
            assert_eq!(agents[0].agent_id, id_b, "most recent first");
        }
        other => panic!("expected ViaAgent, got {other:?}"),
    }
}
