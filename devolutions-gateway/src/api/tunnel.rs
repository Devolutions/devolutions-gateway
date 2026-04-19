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
/// Note: the hashing step itself runs in time proportional to input length.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let da = Sha256::digest(a);
    let db = Sha256::digest(b);
    da.iter().zip(db.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    /// Agent-generated UUID (the agent owns its identity).
    pub agent_id: Uuid,
    /// Friendly name for the agent.
    pub agent_name: String,
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
    let token_valid = handle.enrollment_token_store().redeem(provided_token).await;

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

    let agent_id = req.agent_id;

    // Reject duplicate agent IDs to prevent identity shadowing.
    if handle.registry().get(&agent_id).await.is_some() {
        return Err(
            crate::http::HttpErrorBuilder::new(axum::http::StatusCode::CONFLICT).msg("agent ID already registered")
        );
    }

    let signed = handle
        .ca_manager()
        .sign_agent_csr(agent_id, &req.agent_name, &req.csr_pem, req.agent_hostname.as_deref())
        .map_err(HttpError::bad_request().with_msg("invalid CSR").err())?;

    let quic_endpoint = format!("{}:{}", conf.hostname, conf.agent_tunnel.listen_port);

    let server_spki_sha256 = handle
        .ca_manager()
        .server_spki_sha256(&conf.hostname)
        .map_err(HttpError::internal().with_msg("compute server SPKI").err())?;

    info!(
        %agent_id,
        agent_name = %req.agent_name,
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
) -> Result<Json<Vec<crate::agent_tunnel::registry::AgentInfo>>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let agents = handle.registry().agent_infos().await;

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
        .await
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
        .await
        .ok_or_else(|| HttpError::not_found().msg("agent not found"))?;

    info!(%agent_id, "Agent deleted via API");

    Ok(axum::http::StatusCode::NO_CONTENT)
}
