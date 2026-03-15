use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::DiagnosticsReadScope;
use crate::http::{HttpError, HttpErrorBuilder};
use crate::wireguard::AgentInfo;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/", get(list_agents))
        .route("/{agent_id}", get(get_agent))
        .route("/resolve-target", post(resolve_target))
        .with_state(state)
}

/// Agent list response
#[derive(serde::Serialize)]
struct AgentsResponse {
    agents: Vec<AgentInfo>,
}

/// Resolve target request
#[derive(serde::Deserialize)]
struct ResolveTargetRequest {
    target: String,
}

/// Resolve target response
#[derive(serde::Serialize)]
struct ResolveTargetResponse {
    target: String,
    target_ip: Option<IpAddr>,
    reachable_agents: Vec<AgentInfo>,
    target_reachable: bool,
}

/// List all WireGuard agents
async fn list_agents(
    State(DgwState { wireguard_listener, .. }): State<DgwState>,
    _scope: DiagnosticsReadScope,
) -> Result<Json<AgentsResponse>, HttpError> {
    let wg = wireguard_listener
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("WireGuard not enabled"))?;

    let agents = wg.list_agents();
    Ok(Json(AgentsResponse { agents }))
}

/// Get information for a specific agent
async fn get_agent(
    State(DgwState { wireguard_listener, .. }): State<DgwState>,
    Path(agent_id): Path<Uuid>,
    _scope: DiagnosticsReadScope,
) -> Result<Json<AgentInfo>, HttpError> {
    let wg = wireguard_listener
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("WireGuard not enabled"))?;

    let agent = wg
        .get_agent(&agent_id)
        .ok_or_else(|| HttpError::not_found().build(format!("Agent {} not found", agent_id)))?;

    Ok(Json(agent))
}

/// Find agents that can reach a target
async fn resolve_target(
    State(DgwState { wireguard_listener, .. }): State<DgwState>,
    _scope: DiagnosticsReadScope,
    Json(request): Json<ResolveTargetRequest>,
) -> Result<Json<ResolveTargetResponse>, HttpError> {
    let wg = wireguard_listener
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("WireGuard not enabled"))?;

    // Parse target to extract IP
    let target_ip = parse_target_ip(&request.target);

    let reachable_agents = if let Some(ip) = target_ip {
        wg.find_agents_for_target(ip)
    } else {
        Vec::new()
    };

    let target_reachable = !reachable_agents.is_empty();

    Ok(Json(ResolveTargetResponse {
        target: request.target,
        target_ip,
        reachable_agents,
        target_reachable,
    }))
}

/// Parse target string to extract IP address
fn parse_target_ip(target: &str) -> Option<IpAddr> {
    // Remove protocol prefix if present
    let target = target
        .strip_prefix("tcp://")
        .or_else(|| target.strip_prefix("http://"))
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);

    // Split host:port
    let host = target.split(':').next()?;

    // Try to parse as IP address
    host.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_ip() {
        assert_eq!(
            parse_target_ip("192.168.1.100"),
            Some("192.168.1.100".parse().expect("valid IPv4"))
        );
        assert_eq!(
            parse_target_ip("192.168.1.100:3389"),
            Some("192.168.1.100".parse().expect("valid IPv4"))
        );
        assert_eq!(
            parse_target_ip("tcp://192.168.1.100:3389"),
            Some("192.168.1.100".parse().expect("valid IPv4"))
        );
        assert_eq!(parse_target_ip("example.com"), None);
        assert_eq!(parse_target_ip("example.com:8080"), None);
    }
}
