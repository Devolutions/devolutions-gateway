//! Shared routing pipeline for agent tunnel.
//!
//! Used by both connection forwarding (`fwd.rs`) and KDC proxy (`kdc_proxy.rs`)
//! to ensure consistent routing behavior and error messages.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use uuid::Uuid;

use super::listener::AgentTunnelHandle;
use super::registry::{AgentPeer, AgentRegistry};
use super::stream::TunnelStream;

/// Result of the routing pipeline.
///
/// Each variant carries enough context for the caller to produce an actionable error message.
#[derive(Debug)]
pub enum RoutingDecision {
    /// Route through these agent candidates (try in order, first success wins).
    ViaAgent(Vec<Arc<AgentPeer>>),
    /// Explicit agent_id was specified but not found in registry.
    ExplicitAgentNotFound(Uuid),
    /// No agent matched — caller should attempt direct connection.
    Direct,
}

/// Determines how to route a connection to the given target.
///
/// Pipeline (in order of priority):
/// 1. Explicit agent_id (from JWT) → route to that agent
/// 2. Target match (IP subnet or domain suffix) → best match wins
/// 3. No match → direct connection
pub fn resolve_route(registry: &AgentRegistry, explicit_agent_id: Option<Uuid>, target_host: &str) -> RoutingDecision {
    // Step 1: Explicit agent ID (from JWT)
    match explicit_agent_id
        .map(|id| registry.get(&id).ok_or(RoutingDecision::ExplicitAgentNotFound(id)))
        .transpose()
    {
        Ok(Some(agent)) => return RoutingDecision::ViaAgent(vec![agent]),
        Err(decision) => return decision,
        _ => {}
    }

    // Step 2: Match target against all agents (IP subnet or domain suffix)
    let agents = registry.find_agents_for(target_host);

    match agents.is_empty() {
        false => RoutingDecision::ViaAgent(agents),
        true => RoutingDecision::Direct,
    }
}

/// Attempt to route a connection via the agent tunnel.
///
/// Returns `Ok(Some(stream))` if routed through an agent, `Ok(None)` if the caller
/// should fall through to direct connect, or `Err` if an explicit agent was specified
/// but not found (or all candidates failed).
pub async fn try_route(
    handle: Option<&AgentTunnelHandle>,
    explicit_agent_id: Option<Uuid>,
    target_host: &str,
    session_id: Uuid,
    target_addr: &str,
) -> Result<Option<(TunnelStream, Arc<AgentPeer>)>> {
    let Some(handle) = handle else {
        return Ok(None);
    };

    match resolve_route(handle.registry(), explicit_agent_id, target_host) {
        RoutingDecision::ExplicitAgentNotFound(id) => {
            Err(anyhow!("agent {id} specified in token not found in registry"))
        }
        RoutingDecision::Direct => Ok(None),
        RoutingDecision::ViaAgent(candidates) => {
            let result = route_and_connect(handle, &candidates, session_id, target_addr).await?;
            Ok(Some(result))
        }
    }
}

/// Try connecting to target through agent candidates (try-fail-retry).
///
/// Returns the connected `TunnelStream` and the agent that succeeded.
///
/// Callers must handle `RoutingDecision::ExplicitAgentNotFound` and
/// `RoutingDecision::Direct` before calling this function.
pub async fn route_and_connect(
    handle: &AgentTunnelHandle,
    candidates: &[Arc<AgentPeer>],
    session_id: Uuid,
    target: &str,
) -> Result<(TunnelStream, Arc<AgentPeer>)> {
    assert!(!candidates.is_empty(), "route_and_connect called with empty candidates");

    let mut last_error = None;

    for agent in candidates {
        info!(
            agent_id = %agent.agent_id,
            agent_name = %agent.name,
            %target,
            "Routing via agent tunnel"
        );

        match handle.connect_via_agent(agent.agent_id, session_id, target).await {
            Ok(stream) => {
                info!(
                    agent_id = %agent.agent_id,
                    agent_name = %agent.name,
                    %target,
                    "Agent tunnel connection established"
                );
                return Ok((stream, Arc::clone(agent)));
            }
            Err(error) => {
                warn!(
                    agent_id = %agent.agent_id,
                    agent_name = %agent.name,
                    %target,
                    error = format!("{error:#}"),
                    "Agent tunnel connection failed, trying next candidate"
                );
                last_error = Some(error);
            }
        }
    }

    let agent_names: Vec<&str> = candidates.iter().map(|a| a.name.as_str()).collect();
    let last_err_msg = last_error.as_ref().map(|e| format!("{e:#}")).unwrap_or_default();

    error!(
        agent_count = candidates.len(),
        %target,
        agents = ?agent_names,
        last_error = %last_err_msg,
        "All agent tunnel candidates failed"
    );

    Err(last_error.unwrap_or_else(|| {
        anyhow!(
            "All {} agents matching target '{}' failed to connect. Agents tried: [{}]",
            candidates.len(),
            target,
            agent_names.join(", "),
        )
    }))
}
