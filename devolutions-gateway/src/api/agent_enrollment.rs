use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::{Json, Router};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{AgentManagementReadAccess, AgentManagementWriteAccess};
use crate::http::HttpError;

/// Timing-safe byte comparison to prevent side-channel attacks on secret comparison.
///
/// Both inputs are hashed with SHA-256 first, producing fixed 32-byte digests.
/// The digest comparison runs in constant time (fixed-length XOR fold).
/// SHA-256 itself runs in time proportional to input length, but this only
/// reveals the length of the attacker's guess — not the secret's length or content.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let da = Sha256::digest(a);
    let db = Sha256::digest(b);
    da.iter().zip(db.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    /// Friendly name for the agent.
    pub agent_name: String,
    /// PEM-encoded Certificate Signing Request from the agent.
    pub csr_pem: String,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    /// Assigned agent ID.
    pub agent_id: Uuid,
    /// Agent name.
    pub agent_name: String,
    /// PEM-encoded client certificate (signed by the gateway CA).
    pub client_cert_pem: String,
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
///
/// The agent generates its own key pair and sends a CSR. The gateway signs it
/// and returns the certificate. The private key never leaves the agent.
async fn enroll_agent(
    State(DgwState {
        conf_handle,
        agent_tunnel_handle,
        ..
    }): State<DgwState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, HttpError> {
    // Validate agent name: 1-255 printable ASCII characters.
    if req.agent_name.is_empty()
        || 255 < req.agent_name.len()
        || req.agent_name.bytes().any(|b| !(0x20..=0x7E).contains(&b))
    {
        return Err(HttpError::bad_request().msg("agent name must be 1-255 printable ASCII characters"));
    }

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
        .ok_or_else(|| HttpError::not_found().msg("agent enrollment is not configured"))?;

    // Try one-time enrollment token from the store first.
    let token_valid = handle.enrollment_token_store().consume(provided_token);

    if !token_valid {
        // Fall back to the static enrollment secret.
        let enrollment_secret = conf
            .agent_tunnel
            .enrollment_secret
            .as_deref()
            .ok_or_else(|| HttpError::not_found().msg("agent enrollment is not configured"))?;

        if !constant_time_eq(provided_token.as_bytes(), enrollment_secret.as_bytes()) {
            return Err(HttpError::forbidden().msg("invalid enrollment token"));
        }
    }

    let agent_id = Uuid::new_v4();

    let signed = handle
        .ca_manager()
        .sign_agent_csr(agent_id, &req.agent_name, &req.csr_pem)
        .map_err(HttpError::bad_request().with_msg("invalid CSR").err())?;

    let quic_endpoint = format!("{}:{}", conf.hostname, conf.agent_tunnel.listen_port);

    info!(
        %agent_id,
        agent_name = %req.agent_name,
        "Agent enrolled successfully",
    );

    Ok(Json(EnrollResponse {
        agent_id,
        agent_name: req.agent_name,
        client_cert_pem: signed.client_cert_pem,
        gateway_ca_cert_pem: signed.ca_cert_pem,
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

    // Use the same routing logic as fwd.rs: IP → subnet match, hostname → domain suffix match
    let matching_peers = if let Some(ip) = target_ip {
        handle.registry().find_agents_for_target(ip)
    } else {
        let hostname = strip_scheme_and_port(&req.target);
        handle.registry().select_agents_for_domain(hostname)
    };

    let reachable_agents: Vec<_> = matching_peers
        .iter()
        .map(crate::agent_tunnel::registry::AgentInfo::from)
        .collect();

    let target_reachable = !reachable_agents.is_empty();

    Ok(Json(ResolveTargetResponse {
        target: req.target,
        target_ip,
        reachable_agents,
        target_reachable,
    }))
}

/// Strip scheme prefix and port from a target string, returning the bare host.
///
/// Handles `tcp://host:port`, `http://host:port`, `host:port`, and bare hostnames.
fn strip_scheme_and_port(target: &str) -> &str {
    let host_port = target
        .strip_prefix("tcp://")
        .or_else(|| target.strip_prefix("http://"))
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);

    let host = if let Some((h, _port)) = host_port.rsplit_once(':') {
        h
    } else {
        host_port
    };

    // Strip brackets for IPv6 literals like [::1].
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

fn parse_target_ip(target: &str) -> Option<IpAddr> {
    strip_scheme_and_port(target).parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_ip_bare_ipv4() {
        assert_eq!(parse_target_ip("10.0.0.1"), Some("10.0.0.1".parse().expect("test")));
    }

    #[test]
    fn parse_target_ip_with_port() {
        assert_eq!(
            parse_target_ip("10.0.0.1:3389"),
            Some("10.0.0.1".parse().expect("test"))
        );
    }

    #[test]
    fn parse_target_ip_tcp_scheme() {
        assert_eq!(
            parse_target_ip("tcp://192.168.1.1:22"),
            Some("192.168.1.1".parse().expect("test"))
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
