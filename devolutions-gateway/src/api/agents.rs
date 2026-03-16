use std::net::IpAddr;

use anyhow::Context as _;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{AgentManagementReadAccess, AgentManagementWriteAccess};
use crate::http::{HttpError, HttpErrorBuilder};
use crate::wireguard::AgentInfo;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/", get(list_agents))
        .route("/enroll", post(enroll_agent))
        .route("/{agent_id}", get(get_agent).delete(delete_agent))
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentEnrollRequest {
    enrollment_token: String,
    public_key: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentEnrollResponse {
    agent_id: Uuid,
    name: String,
    gateway_public_key: String,
    assigned_ip: String,
    gateway_ip: String,
}

/// List all WireGuard agents
async fn list_agents(
    State(DgwState { wireguard_listener, .. }): State<DgwState>,
    _access: AgentManagementReadAccess,
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
    _access: AgentManagementReadAccess,
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
    _access: AgentManagementReadAccess,
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

async fn enroll_agent(
    State(DgwState {
        conf_handle,
        agent_store,
        enrollment_store,
        wireguard_listener,
        ..
    }): State<DgwState>,
    Json(request): Json<AgentEnrollRequest>,
) -> Result<Json<AgentEnrollResponse>, HttpError> {
    let enrollment_store = enrollment_store
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("Enrollment not enabled"))?;
    let agent_store = agent_store
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("Agent store not enabled"))?;
    let wg_handle = wireguard_listener
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("WireGuard not enabled"))?;

    let token_claims = enrollment_store
        .validate_and_consume_token(&request.enrollment_token)
        .map_err(HttpError::unauthorized().with_msg("invalid enrollment token").err())?;

    let conf = conf_handle.get_conf();
    let wireguard_conf = conf
        .wireguard
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("WireGuard not enabled"))?;

    let public_key = parse_wireguard_public_key(&request.public_key)
        .map_err(HttpError::bad_request().with_msg("invalid wireguard public key").err())?;

    let agent_id = Uuid::new_v4();
    let name = request
        .name
        .or(token_claims.requested_name)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| format!("agent-{agent_id}"));
    let peer_config = agent_store
        .allocate_and_upsert_enrolled_peer(agent_id, name.clone(), public_key, wireguard_conf)
        .map_err(HttpError::internal().with_msg("persist enrolled agent").err())?;
    let assigned_ip = peer_config.assigned_ip;

    if let Err(error) = wg_handle.add_peer(peer_config) {
        let _ = agent_store.remove(&agent_id);
        let _ = enrollment_store.restore_token(token_claims.token_id);
        return Err(HttpError::internal()
            .with_msg("register runtime wireguard peer")
            .build(error));
    }

    let gateway_public_key = base64::engine::general_purpose::STANDARD
        .encode(wireguard_tunnel::PublicKey::from(&wireguard_conf.private_key).as_bytes());

    info!(
        %agent_id,
        %name,
        %assigned_ip,
        "Enrolled WireGuard agent"
    );

    Ok(Json(AgentEnrollResponse {
        agent_id,
        name,
        gateway_public_key,
        assigned_ip: assigned_ip.to_string(),
        gateway_ip: wireguard_conf.gateway_ip.to_string(),
    }))
}

async fn delete_agent(
    State(DgwState {
        agent_store,
        wireguard_listener,
        ..
    }): State<DgwState>,
    Path(agent_id): Path<Uuid>,
    _access: AgentManagementWriteAccess,
) -> Result<StatusCode, HttpError> {
    let agent_store = agent_store
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("Agent store not enabled"))?;
    let wg_handle = wireguard_listener
        .as_ref()
        .ok_or_else(|| HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE).msg("WireGuard not enabled"))?;

    let removed = agent_store
        .remove(&agent_id)
        .map_err(HttpError::internal().with_msg("remove enrolled agent").err())?;

    let Some(removed) = removed else {
        return Err(HttpError::not_found().build(format!("Agent {} not found", agent_id)));
    };

    wg_handle.remove_peer(&agent_id);
    info!(
        %agent_id,
        name = %removed.name,
        assigned_ip = %removed.assigned_ip,
        "Removed enrolled WireGuard agent"
    );

    Ok(StatusCode::NO_CONTENT)
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

fn parse_wireguard_public_key(public_key: &str) -> anyhow::Result<wireguard_tunnel::PublicKey> {
    use base64::Engine as _;

    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key)
        .context("failed to decode base64 wireguard public key")?;

    anyhow::ensure!(public_key_bytes.len() == 32, "wireguard public key must be 32 bytes");

    let mut public_key_array = [0u8; 32];
    public_key_array.copy_from_slice(&public_key_bytes);

    Ok(wireguard_tunnel::PublicKey::from(public_key_array))
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

    #[test]
    fn parse_wireguard_public_key_rejects_invalid_length() {
        assert!(parse_wireguard_public_key("AAAA").is_err());
    }
}
