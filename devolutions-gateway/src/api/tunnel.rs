use axum::extract::{Path, State};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{AgentManagementDeleteAccess, AgentManagementReadAccess};
use crate::http::HttpError;
use crate::token::EnrollmentTokenClaims;

#[derive(Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentDomainAdvertisement {
    /// Domain route advertised by the Agent.
    pub domain: String,
    /// Whether the Agent discovered the domain automatically.
    pub auto_detected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// No tunnel connection exists for the Agent.
    Offline,
    /// The Agent has a tunnel connection and a recent heartbeat.
    Online,
    /// The Agent has a tunnel connection, but its heartbeat has expired.
    Unresponsive,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentInfo {
    /// Stable Agent identity.
    pub agent_id: Uuid,
    /// Unique management name assigned during enrollment.
    pub name: String,
    /// Current tunnel connection status.
    pub status: AgentStatus,
    /// Time of the Agent's last heartbeat.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_seen: Option<OffsetDateTime>,
    /// Subnet routes currently advertised by the Agent.
    pub subnets: Option<Vec<String>>,
    /// Domain routes currently advertised by the Agent.
    pub domains: Option<Vec<AgentDomainAdvertisement>>,
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
/// (e.g. DVLS, Hub, PAM service, or any other compatible provisioner).
///
/// The agent generates its own key pair and sends a CSR. The gateway signs it
/// and returns the certificate. The private key never leaves the agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "EnrollAgent",
    tag = "Agent",
    path = "/jet/tunnel/enroll",
    request_body(content = EnrollRequest, description = "Agent identity and certificate signing request", content_type = "application/json"),
    responses(
        (status = 200, description = "Agent enrolled", body = EnrollResponse),
        (status = 400, description = "Invalid agent name, request body, or certificate signing request"),
        (status = 401, description = "Invalid or missing enrollment token"),
        (status = 409, description = "Agent ID or name already registered, agent key previously deleted, or enrollment token already used"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("enrollment_token" = [])),
))]
pub(crate) async fn enroll_agent(
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
    let EnrollmentTokenClaims {
        exp,
        jti,
        jet_agent_name: agent_name,
        ..
    } = token_claims;

    // Validate agent name: 1-255 printable ASCII characters.
    if agent_name.is_empty()
        || 255 < agent_name.len()
        || agent_name.trim() != agent_name
        || agent_name.bytes().any(|b| !(0x20..=0x7E).contains(&b))
    {
        return Err(
            HttpError::bad_request().msg("agent name must be 1-255 printable ASCII characters without outer spaces")
        );
    }

    let conf = conf_handle.get_conf();

    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent enrollment is not configured"))?;

    let signed = handle
        .ca_manager()
        .sign_agent_csr(agent_id, &agent_name, &csr_pem, agent_hostname.as_deref())
        .map_err(HttpError::bad_request().with_msg("invalid CSR").err())?;
    let client_spki_sha256 = agent_tunnel::cert::spki_sha256_digest_from_pem(&signed.client_cert_pem)
        .map_err(HttpError::internal().with_msg("compute client SPKI").err())?;
    let request_sha256 = enrollment_request_sha256(
        jti,
        agent_id,
        &agent_name,
        client_spki_sha256,
        agent_hostname.as_deref(),
    );

    let quic_endpoint = format!("{}:{}", conf.hostname, conf.agent_tunnel.listen_port);

    // Computed before enrollment so the durable authorization write is the last
    // fallible step; failing after it would leave a ghost enrollment behind.
    let server_spki_sha256 = handle
        .ca_manager()
        .server_spki_sha256(&conf.hostname)
        .map_err(HttpError::internal().with_msg("compute server SPKI").err())?;

    let outcome = handle
        .enroll(agent_tunnel::authorization::EnrollmentAttempt {
            token_id: jti,
            token_expires_at: exp,
            agent_id,
            name: agent_name.clone(),
            client_spki_sha256,
            request_sha256,
        })
        .await
        .map_err(HttpError::internal().with_msg("persist Agent enrollment").err())?;

    if let agent_tunnel::authorization::EnrollmentOutcome::Conflict(conflict) = outcome {
        let message = match conflict {
            agent_tunnel::authorization::EnrollmentConflict::AgentId => "agent ID already registered",
            agent_tunnel::authorization::EnrollmentConflict::AgentName => "agent name already registered",
            agent_tunnel::authorization::EnrollmentConflict::DeletedKey => "agent key was previously deleted",
            agent_tunnel::authorization::EnrollmentConflict::TokenReplay => {
                "enrollment token was already used for another request"
            }
        };
        return Err(crate::http::HttpErrorBuilder::new(axum::http::StatusCode::CONFLICT).msg(message));
    }

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

fn enrollment_request_sha256(
    token_id: Uuid,
    agent_id: Uuid,
    agent_name: &str,
    client_spki_sha256: [u8; 32],
    agent_hostname: Option<&str>,
) -> [u8; 32] {
    fn update_field(hasher: &mut Sha256, value: &[u8]) {
        let len = u64::try_from(value.len()).expect("enrollment field length fits in u64");
        hasher.update(len.to_be_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    update_field(&mut hasher, token_id.as_bytes());
    update_field(&mut hasher, agent_id.as_bytes());
    update_field(&mut hasher, agent_name.as_bytes());
    update_field(&mut hasher, &client_spki_sha256);
    update_field(&mut hasher, agent_hostname.unwrap_or_default().as_bytes());
    hasher.finalize().into()
}

/// Converts a heartbeat timestamp expressed in milliseconds since the Unix epoch into an
/// [`OffsetDateTime`], returning `None` if the value cannot be represented (e.g. it overflows
/// the range supported by [`OffsetDateTime`]) rather than panicking.
fn last_seen_ms_to_datetime(last_seen_ms: u64) -> Option<OffsetDateTime> {
    let nanos = i128::from(last_seen_ms).checked_mul(1_000_000)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()
}

fn agent_info(
    accepted: agent_tunnel::authorization::AcceptedAgent,
    runtime: Option<agent_tunnel::registry::AgentInfo>,
) -> AgentInfo {
    let Some(runtime) = runtime else {
        return AgentInfo {
            agent_id: accepted.agent_id,
            name: accepted.name,
            status: AgentStatus::Offline,
            last_seen: None,
            subnets: None,
            domains: None,
        };
    };

    AgentInfo {
        agent_id: accepted.agent_id,
        name: accepted.name,
        status: if runtime.is_online {
            AgentStatus::Online
        } else {
            AgentStatus::Unresponsive
        },
        last_seen: last_seen_ms_to_datetime(runtime.last_seen_ms),
        subnets: Some(runtime.subnets),
        domains: Some(
            runtime
                .domains
                .into_iter()
                .map(|domain| AgentDomainAdvertisement {
                    domain: domain.domain.to_string(),
                    auto_detected: domain.auto_detected,
                })
                .collect(),
        ),
    }
}

/// List accepted agents and their current status.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "ListAgents",
    tag = "Agent",
    path = "/jet/tunnel/agents",
    responses(
        (status = 200, description = "Accepted agents and their current status", body = [AgentInfo]),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.agent.read"])),
))]
pub(crate) async fn list_agents(
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    _access: AgentManagementReadAccess,
) -> Result<Json<Vec<AgentInfo>>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let accepted_agents = handle
        .accepted_agents()
        .await
        .map_err(HttpError::internal().with_msg("query accepted Agents").err())?;
    let mut agents = Vec::with_capacity(accepted_agents.len());
    for accepted in accepted_agents {
        let runtime = handle.registry().agent_info(&accepted.agent_id).await;
        agents.push(agent_info(accepted, runtime));
    }

    Ok(Json(agents))
}

/// Get a single agent by ID.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    operation_id = "GetAgent",
    tag = "Agent",
    path = "/jet/tunnel/agents/{agent_id}",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent status", body = AgentInfo),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.agent.read"])),
))]
pub(crate) async fn get_agent(
    _access: AgentManagementReadAccess,
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<AgentInfo>, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    let accepted = handle
        .accepted_agent(agent_id)
        .await
        .map_err(HttpError::internal().with_msg("query accepted Agent").err())?
        .ok_or_else(|| HttpError::not_found().msg("agent not found"))?;
    let runtime = handle.registry().agent_info(&agent_id).await;

    Ok(Json(agent_info(accepted, runtime)))
}

/// Delete an accepted agent by ID.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    operation_id = "DeleteAgent",
    tag = "Agent",
    path = "/jet/tunnel/agents/{agent_id}",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    responses(
        (status = 204, description = "Agent deleted"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Agent not found"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.agent.delete"])),
))]
pub(crate) async fn delete_agent(
    _access: AgentManagementDeleteAccess,
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    Path(agent_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    handle
        .delete_agent(agent_id)
        .await
        .map_err(HttpError::internal().with_msg("delete accepted Agent").err())?
        .ok_or_else(|| HttpError::not_found().msg("agent not found"))?;

    info!(%agent_id, "Agent deleted via API");

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted_agent(agent_id: Uuid) -> agent_tunnel::authorization::AcceptedAgent {
        agent_tunnel::authorization::AcceptedAgent {
            agent_id,
            name: String::from("montreal-office"),
            client_spki_sha256: [0x11; 32],
        }
    }

    #[test]
    fn connected_agent_without_recent_heartbeat_is_unresponsive() {
        let agent_id = Uuid::new_v4();
        let runtime = agent_tunnel::registry::AgentInfo {
            agent_id,
            name: String::from("montreal-office"),
            cert_fingerprint: String::from("fingerprint"),
            is_online: false,
            last_seen_ms: 1234,
            subnets: Vec::new(),
            domains: Vec::new(),
            route_epoch: 1,
        };

        let info = agent_info(accepted_agent(agent_id), Some(runtime));

        assert_eq!(info.status, AgentStatus::Unresponsive);
        assert_eq!(
            info.last_seen,
            Some(OffsetDateTime::from_unix_timestamp_nanos(1234 * 1_000_000).expect("valid timestamp"))
        );
        assert_eq!(info.subnets, Some(Vec::new()));
        assert!(info.domains.is_some_and(|domains| domains.is_empty()));
    }

    #[test]
    fn agent_never_seen_has_no_last_seen() {
        let agent_id = Uuid::new_v4();

        let info = agent_info(accepted_agent(agent_id), None);

        assert_eq!(info.status, AgentStatus::Offline);
        assert_eq!(info.last_seen, None);
    }

    #[test]
    fn last_seen_ms_to_datetime_converts_zero_to_unix_epoch() {
        assert_eq!(last_seen_ms_to_datetime(0), Some(OffsetDateTime::UNIX_EPOCH));
    }

    #[test]
    fn last_seen_ms_to_datetime_does_not_panic_on_out_of_range_value() {
        assert_eq!(last_seen_ms_to_datetime(u64::MAX), None);
    }
}
