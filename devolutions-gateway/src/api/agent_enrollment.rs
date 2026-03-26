use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::{Json, Router};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{AgentManagementReadAccess, AgentManagementWriteAccess};
use crate::http::HttpError;

#[derive(Deserialize)]
pub struct EnrollRequest {
    /// Friendly name for the agent.
    pub agent_name: String,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    /// Assigned agent ID.
    pub agent_id: Uuid,
    /// Agent name.
    pub agent_name: String,
    /// PEM-encoded client certificate (signed by the gateway CA).
    pub client_cert_pem: String,
    /// PEM-encoded client private key.
    pub client_key_pem: String,
    /// PEM-encoded gateway CA certificate (for server verification).
    pub gateway_ca_cert_pem: String,
    /// QUIC endpoint to connect to (`host:port`).
    pub quic_endpoint: String,
}

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/enroll", axum::routing::post(enroll_agent))
        .route("/agents", axum::routing::get(list_agents))
        .route("/agents/{agent_id}", axum::routing::get(get_agent).delete(delete_agent))
        .route("/agents/resolve-target", axum::routing::post(resolve_target))
        .with_state(state)
}

/// Enroll a new agent.
///
/// Requires a Bearer token matching the configured enrollment secret
/// or a valid one-time enrollment token from the store.
async fn enroll_agent(
    State(DgwState {
        conf_handle,
        agent_tunnel_handle,
        ..
    }): State<DgwState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, HttpError> {
    let conf = conf_handle.get_conf();

    // Extract the Bearer token.
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| HttpError::unauthorized().msg("missing Authorization header"))?;

    let provided_token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| HttpError::unauthorized().msg("expected Bearer token"))?;

    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::internal().msg("agent tunnel not initialized"))?;

    // Try one-time enrollment token from the store first.
    let token_valid = handle.enrollment_token_store().consume(provided_token);

    if !token_valid {
        // Fall back to the static enrollment secret.
        let enrollment_secret = conf
            .agent_tunnel
            .enrollment_secret
            .as_deref()
            .ok_or_else(|| HttpError::not_found().msg("agent enrollment is not configured"))?;

        if provided_token != enrollment_secret {
            return Err(HttpError::forbidden().msg("invalid enrollment token"));
        }
    }

    let agent_id = Uuid::new_v4();

    let cert_bundle = handle
        .ca_manager()
        .issue_agent_certificate(agent_id, &req.agent_name)
        .map_err(HttpError::internal().with_msg("issue agent certificate").err())?;

    let quic_endpoint = format!("{}:{}", conf.hostname, conf.agent_tunnel.listen_port);

    info!(
        %agent_id,
        agent_name = %req.agent_name,
        "Agent enrolled successfully",
    );

    Ok(Json(EnrollResponse {
        agent_id,
        agent_name: req.agent_name,
        client_cert_pem: cert_bundle.client_cert_pem,
        client_key_pem: cert_bundle.client_key_pem,
        gateway_ca_cert_pem: cert_bundle.ca_cert_pem,
        quic_endpoint,
    }))
}

/// List connected agents and their status.
async fn list_agents(
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    _access: AgentManagementReadAccess,
) -> Result<Json<Vec<crate::agent_tunnel::registry::AgentInfo>>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let agents = handle.registry().agent_infos();

    Ok(Json(agents))
}

/// Get a single agent by ID.
async fn get_agent(
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    _access: AgentManagementReadAccess,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<crate::agent_tunnel::registry::AgentInfo>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let info = handle
        .registry()
        .agent_info(&agent_id)
        .ok_or_else(|| HttpError::not_found().msg("agent not found"))?;

    Ok(Json(info))
}

/// Delete (unregister) an agent by ID.
async fn delete_agent(
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    _access: AgentManagementWriteAccess,
    Path(agent_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    handle
        .registry()
        .unregister(&agent_id)
        .ok_or_else(|| HttpError::not_found().msg("agent not found"))?;

    info!(%agent_id, "Agent deleted via API");

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ResolveTargetRequest {
    target: String,
}

#[derive(Serialize)]
struct ResolveTargetResponse {
    target: String,
    target_ip: Option<IpAddr>,
    reachable_agents: Vec<crate::agent_tunnel::registry::AgentInfo>,
    target_reachable: bool,
}

/// Resolve a target string to find which agents can reach it.
async fn resolve_target(
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    _access: AgentManagementReadAccess,
    Json(req): Json<ResolveTargetRequest>,
) -> Result<Json<ResolveTargetResponse>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let target_ip = parse_target_ip(&req.target);

    let reachable_agents = if let Some(ip) = target_ip {
        handle
            .registry()
            .find_agents_for_target(ip)
            .into_iter()
            .map(|peer| {
                let route_state = peer.route_state();
                crate::agent_tunnel::registry::AgentInfo {
                    agent_id: peer.agent_id,
                    name: peer.name.clone(),
                    cert_fingerprint: peer.cert_fingerprint.clone(),
                    is_online: peer.is_online(crate::agent_tunnel::registry::AGENT_OFFLINE_TIMEOUT),
                    last_seen_ms: peer.last_seen_ms(),
                    subnets: route_state
                        .as_ref()
                        .map(|rs| rs.subnets.iter().map(ToString::to_string).collect())
                        .unwrap_or_default(),
                    route_epoch: route_state.as_ref().map(|rs| rs.epoch),
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let target_reachable = !reachable_agents.is_empty();

    Ok(Json(ResolveTargetResponse {
        target: req.target,
        target_ip,
        reachable_agents,
        target_reachable,
    }))
}

/// Parse a target string to extract an IP address.
///
/// Supports formats like:
/// - `tcp://host:port`
/// - `http://host:port`
/// - `https://host:port`
/// - `host:port`
/// - bare IP address
fn parse_target_ip(target: &str) -> Option<IpAddr> {
    // Strip known scheme prefixes.
    let host_port = target
        .strip_prefix("tcp://")
        .or_else(|| target.strip_prefix("http://"))
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);

    // Split off port if present.
    let host = if let Some((h, _port)) = host_port.rsplit_once(':') {
        h
    } else {
        host_port
    };

    // Strip brackets for IPv6 literals like [::1].
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);

    host.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_ip_bare_ipv4() {
        assert_eq!(parse_target_ip("10.0.0.1"), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_target_ip_with_port() {
        assert_eq!(parse_target_ip("10.0.0.1:3389"), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_target_ip_tcp_scheme() {
        assert_eq!(
            parse_target_ip("tcp://192.168.1.1:22"),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn parse_target_ip_hostname_returns_none() {
        assert_eq!(parse_target_ip("myserver.local:3389"), None);
    }

    #[test]
    fn parse_target_ip_bare_hostname_returns_none() {
        assert_eq!(parse_target_ip("myserver"), None);
    }
}
