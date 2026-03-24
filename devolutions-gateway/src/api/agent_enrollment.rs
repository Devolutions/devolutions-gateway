use axum::extract::State;
use axum::http::HeaderMap;
use axum::{Json, Router};
use uuid::Uuid;

use crate::DgwState;
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
        .with_state(state)
}

/// Enroll a new agent.
///
/// Requires a Bearer token matching the configured enrollment secret.
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

    // Validate that agent tunnel is enabled and has an enrollment secret.
    let enrollment_secret = conf
        .agent_tunnel
        .enrollment_secret
        .as_deref()
        .ok_or_else(|| HttpError::not_found().msg("agent enrollment is not configured"))?;

    // Extract and validate the Bearer token.
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| HttpError::unauthorized().msg("missing Authorization header"))?;

    let provided_token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| HttpError::unauthorized().msg("expected Bearer token"))?;

    if provided_token != enrollment_secret {
        return Err(HttpError::forbidden().msg("invalid enrollment token"));
    }

    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::internal().msg("agent tunnel not initialized"))?;

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
) -> Result<Json<Vec<crate::agent_tunnel::registry::AgentInfo>>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let agents = handle.registry().agent_infos();

    Ok(Json(agents))
}
