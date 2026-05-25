use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use agent_tunnel::registry::{AgentPeer, AgentRegistry};
use agent_tunnel::routing::{RouteTarget, RoutingDecision, resolve_route, route_and_connect, try_route};
use agent_tunnel_proto::{DomainAdvertisement, DomainName};
use ipnetwork::Ipv4Network;
use uuid::Uuid;

use super::common::bind_test_listener;

fn ip(s: &str) -> RouteTarget {
    RouteTarget::Ip(IpAddr::V4(s.parse::<Ipv4Addr>().expect("valid test ipv4")))
}

fn host(s: &str) -> RouteTarget {
    RouteTarget::hostname(s)
}

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

#[tokio::test]
async fn route_explicit_agent_id() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let agent_id = peer.agent_id;
    registry.register(Arc::clone(&peer)).await;

    match resolve_route(&registry, Some(agent_id), &host("anything")).await {
        RoutingDecision::ViaAgent(agents) => {
            assert_eq!(agents.len(), 1);
            assert_eq!(agents[0].agent_id, agent_id);
        }
        other => panic!("expected ViaAgent, got {other:?}"),
    }
}

#[tokio::test]
async fn route_explicit_agent_id_not_found() {
    let registry = AgentRegistry::new();
    let bogus_id = Uuid::new_v4();

    match resolve_route(&registry, Some(bogus_id), &host("anything")).await {
        RoutingDecision::ExplicitAgentNotFound(id) => {
            assert_eq!(id, bogus_id);
        }
        other => panic!("expected ExplicitAgentNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn route_ip_target_via_subnet() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let agent_id = peer.agent_id;
    let subnet: Ipv4Network = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![]);
    registry.register(peer).await;

    match resolve_route(&registry, None, &ip("10.1.5.50")).await {
        RoutingDecision::ViaAgent(agents) => {
            assert_eq!(agents[0].agent_id, agent_id);
        }
        other => panic!("expected ViaAgent, got {other:?}"),
    }
}

#[tokio::test]
async fn route_hostname_via_domain() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let agent_id = peer.agent_id;
    let subnet: Ipv4Network = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![domain("contoso.local")]);
    registry.register(peer).await;

    match resolve_route(&registry, None, &host("dc01.contoso.local")).await {
        RoutingDecision::ViaAgent(agents) => {
            assert_eq!(agents[0].agent_id, agent_id);
        }
        other => panic!("expected ViaAgent, got {other:?}"),
    }
}

#[tokio::test]
async fn route_no_match_returns_direct() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let subnet: Ipv4Network = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![domain("contoso.local")]);
    registry.register(peer).await;

    assert!(matches!(
        resolve_route(&registry, None, &host("external.example.com")).await,
        RoutingDecision::Direct
    ));
}

#[tokio::test]
async fn route_ip_no_match_returns_direct() {
    let registry = AgentRegistry::new();
    let peer = make_peer("agent-a");
    let subnet: Ipv4Network = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![]);
    registry.register(peer).await;

    assert!(matches!(
        resolve_route(&registry, None, &ip("192.168.1.1")).await,
        RoutingDecision::Direct
    ));
}

#[tokio::test]
async fn route_skips_offline_agents() {
    let registry = AgentRegistry::new();
    let peer = make_peer("offline-agent");
    let subnet: Ipv4Network = "10.1.0.0/16".parse().expect("valid test subnet");
    peer.update_routes(1, vec![subnet], vec![domain("contoso.local")]);
    peer.set_last_seen_for_test(0);
    registry.register(peer).await;

    assert!(matches!(
        resolve_route(&registry, None, &host("dc01.contoso.local")).await,
        RoutingDecision::Direct
    ));
}

#[tokio::test]
async fn route_domain_match_returns_multiple_agents_ordered() {
    let registry = AgentRegistry::new();

    let peer_a = make_peer("agent-a");
    let subnet_a: Ipv4Network = "10.1.0.0/16".parse().expect("valid test subnet");
    peer_a.update_routes(1, vec![subnet_a], vec![domain("contoso.local")]);
    // Pin `received_at` explicitly — do NOT rely on thread::sleep to advance
    // SystemTime, since Windows timer resolution is ~16 ms and makes the
    // ordering assertion below flaky.
    peer_a.set_received_at_for_test(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1));
    registry.register(Arc::clone(&peer_a)).await;

    let peer_b = make_peer("agent-b");
    let id_b = peer_b.agent_id;
    let subnet_b: Ipv4Network = "10.2.0.0/16".parse().expect("valid test subnet");
    peer_b.update_routes(1, vec![subnet_b], vec![domain("contoso.local")]);
    peer_b.set_received_at_for_test(std::time::UNIX_EPOCH + std::time::Duration::from_secs(2));
    registry.register(Arc::clone(&peer_b)).await;

    match resolve_route(&registry, None, &host("dc01.contoso.local")).await {
        RoutingDecision::ViaAgent(agents) => {
            assert_eq!(agents.len(), 2);
            assert_eq!(agents[0].agent_id, id_b, "most recent first");
        }
        other => panic!("expected ViaAgent, got {other:?}"),
    }
}

// A token that names a specific `jet_agent_id` must NOT silently fall back to a
// direct connect when the gateway has no agent-tunnel configured — doing so
// would bypass the intended network boundary.
#[tokio::test]
async fn try_route_rejects_explicit_agent_when_handle_missing() {
    let result = try_route(
        None,
        Some(Uuid::new_v4()),
        &host("host.example.com"),
        Uuid::new_v4(),
        "host.example.com:443",
    )
    .await;

    assert!(result.is_err(), "expected Err for explicit agent with no handle");
}

// Without an explicit `jet_agent_id`, a missing handle just means "no tunneling
// available" — falling back to a direct connect is correct.
#[tokio::test]
async fn try_route_without_explicit_agent_falls_through_when_handle_missing() {
    let result = try_route(
        None,
        None,
        &host("host.example.com"),
        Uuid::new_v4(),
        "host.example.com:443",
    )
    .await;

    match result {
        Ok(None) => {}
        Ok(Some(_)) => panic!("expected Ok(None), got Ok(Some(_))"),
        Err(e) => panic!("expected Ok(None), got Err: {e:#}"),
    }
}

#[tokio::test]
async fn route_and_connect_with_empty_candidates_errors() {
    let listener = bind_test_listener().await;

    let err = match route_and_connect(&listener.handle, &[], Uuid::new_v4(), "10.1.1.1:22").await {
        Ok(_) => panic!("expected Err for empty candidate list"),
        Err(e) => e,
    };

    let msg = format!("{err:#}");
    assert!(
        msg.contains("empty candidates"),
        "error should mention empty candidates, got: {msg}"
    );

    listener.shutdown().await;
}

// With a real handle but a target that no registered agent can reach,
// `try_route` must return `Ok(None)` so the caller falls through to a
// direct connection — without ever attempting QUIC traffic.
#[tokio::test]
async fn try_route_falls_through_when_no_agent_matches() {
    let listener = bind_test_listener().await;

    let peer = make_peer("agent-a");
    let subnet: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
    peer.update_routes(1, vec![subnet], vec![domain("contoso.local")]);
    listener.handle.registry().register(peer).await;

    let result = try_route(
        Some(&listener.handle),
        None,
        &host("external.example.com"),
        Uuid::new_v4(),
        "external.example.com:443",
    )
    .await;

    match result {
        Ok(None) => {}
        Ok(Some(_)) => panic!("expected Ok(None), got Ok(Some(_))"),
        Err(e) => panic!("expected Ok(None), got Err: {e:#}"),
    }

    listener.shutdown().await;
}

// With a real handle but an explicit `jet_agent_id` that no agent in the
// registry can satisfy, `try_route` must error rather than silently fall
// back to a direct connection — the explicit claim is a security boundary.
#[tokio::test]
async fn try_route_errors_on_explicit_agent_not_found() {
    let listener = bind_test_listener().await;

    let bogus_id = Uuid::new_v4();
    let err = match try_route(
        Some(&listener.handle),
        Some(bogus_id),
        &host("anywhere.example.com"),
        Uuid::new_v4(),
        "anywhere.example.com:443",
    )
    .await
    {
        Ok(_) => panic!("expected Err for explicit agent_id not in registry"),
        Err(e) => e,
    };

    let msg = format!("{err:#}");
    assert!(
        msg.contains("not found in registry"),
        "error should mention the missing agent, got: {msg}"
    );

    listener.shutdown().await;
}
