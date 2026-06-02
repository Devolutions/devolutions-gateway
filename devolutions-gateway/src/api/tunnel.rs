use axum::extract::{Path, State};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{AgentManagementReadAccess, AgentManagementWriteAccess};
use crate::http::HttpError;

#[derive(Deserialize)]
pub struct EnrollRequest {
    /// Agent-generated UUID (the agent owns its identity).
    pub agent_id: Uuid,
    /// PEM-encoded Certificate Signing Request from the agent.
    pub csr_pem: String,
    /// Optional hostname of the agent machine (added as DNS SAN in the issued certificate).
    #[serde(default)]
    pub agent_hostname: Option<String>,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    /// Assigned agent ID.
    pub agent_id: Uuid,
    /// PEM-encoded client certificate (signed by the gateway CA).
    pub client_cert_pem: String,
    /// PEM-encoded gateway CA certificate (for server verification).
    pub gateway_ca_cert_pem: String,
    /// QUIC endpoint to connect to (`host:port`).
    pub quic_endpoint: String,
    /// SHA-256 hash of the server certificate's SPKI (hex-encoded).
    /// Used by the agent to pin the server's public key.
    pub server_spki_sha256: String,
}

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/enroll", axum::routing::post(enroll_agent))
        .route("/agents", axum::routing::get(list_agents))
        .route("/agents/{agent_id}", axum::routing::get(get_agent).delete(delete_agent))
        .with_state(state)
}

/// Enroll a new agent.
///
/// Requires a Bearer token: an `ENROLLMENT` JWT signed by the configured provisioner key
/// (e.g. any compatible provisioner).
///
/// The agent generates its own key pair and sends a CSR. The gateway signs it
/// and returns the certificate. The private key never leaves the agent.
async fn enroll_agent(
    crate::extract::EnrollmentToken(token_claims): crate::extract::EnrollmentToken,
    State(DgwState {
        conf_handle,
        agent_tunnel_handle,
        ..
    }): State<DgwState>,
    Json(EnrollRequest {
        agent_id,
        csr_pem,
        agent_hostname,
    }): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, HttpError> {
    let agent_name = token_claims.jet_agent_name;

    // Validate agent name: 1-255 printable ASCII characters.
    if agent_name.is_empty() || 255 < agent_name.len() || agent_name.bytes().any(|b| !(0x20..=0x7E).contains(&b)) {
        return Err(HttpError::bad_request().msg("agent name must be 1-255 printable ASCII characters"));
    }

    let conf = conf_handle.get_conf();

    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent enrollment is not configured"))?;

    // Reject duplicate agent IDs to prevent identity shadowing.
    if handle.registry().get(&agent_id).await.is_some() {
        return Err(
            crate::http::HttpErrorBuilder::new(axum::http::StatusCode::CONFLICT).msg("agent ID already registered")
        );
    }

    let signed = handle
        .ca_manager()
        .sign_agent_csr(agent_id, &agent_name, &csr_pem, agent_hostname.as_deref())
        .map_err(HttpError::bad_request().with_msg("invalid CSR").err())?;

    let quic_endpoint = format!("{}:{}", conf.hostname, conf.agent_tunnel.listen_port);

    let server_spki_sha256 = handle
        .ca_manager()
        .server_spki_sha256(&conf.hostname)
        .map_err(HttpError::internal().with_msg("compute server SPKI").err())?;

    info!(
        %agent_id,
        agent_name = %agent_name,
        "Agent enrolled successfully",
    );

    Ok(Json(EnrollResponse {
        agent_id,
        client_cert_pem: signed.client_cert_pem,
        gateway_ca_cert_pem: signed.ca_cert_pem,
        quic_endpoint,
        server_spki_sha256,
    }))
}

/// List connected agents and their status.
async fn list_agents(
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    _access: AgentManagementReadAccess,
) -> Result<Json<Vec<agent_tunnel::registry::AgentInfo>>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let agents = handle.registry().agent_infos().await;

    Ok(Json(agents))
}

/// Get a single agent by ID.
async fn get_agent(
    _access: AgentManagementReadAccess,
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<agent_tunnel::registry::AgentInfo>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let info = handle
        .registry()
        .agent_info(&agent_id)
        .await
        .ok_or_else(|| HttpError::not_found().msg("agent not found"))?;

    Ok(Json(info))
}

/// Delete (unregister) an agent by ID.
async fn delete_agent(
    _access: AgentManagementWriteAccess,
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    Path(agent_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    handle
        .registry()
        .unregister(&agent_id)
        .await
        .ok_or_else(|| HttpError::not_found().msg("agent not found"))?;

    info!(%agent_id, "Agent deleted via API");

    Ok(axum::http::StatusCode::NO_CONTENT)
}
