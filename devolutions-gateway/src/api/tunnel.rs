use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{AgentManagementReadAccess, AgentManagementWriteAccess};
use crate::http::HttpError;

/// Validate the enrollment JWT and return its decoded claims on success.
///
/// Same validation rules as [`validate_enrollment_jwt`]; on failure returns
/// `None`. The caller does not need to distinguish between failure modes —
/// the unauthenticated request is rejected at the HTTP layer with a generic
/// "invalid enrollment token" message regardless.
fn validate_enrollment_jwt_claims(
    token: &str,
    provisioner_key: &picky::key::PublicKey,
) -> Option<crate::token::EnrollmentTokenClaims> {
    use picky::jose::jws::RawJws;
    use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator};

    use crate::token::{AccessScope, EnrollmentTokenClaims};

    let raw_jws = RawJws::decode(token).ok()?;
    let jwt = raw_jws.verify(provisioner_key).map(JwtSig::from).ok()?;

    let now = JwtDate::new_with_leeway(time::OffsetDateTime::now_utc().unix_timestamp(), 60);
    let validator = JwtValidator::strict(now);

    let validated = jwt.validate::<EnrollmentTokenClaims>(&validator).ok()?;

    if !matches!(
        validated.state.claims.scope,
        AccessScope::AgentEnroll | AccessScope::Wildcard
    ) {
        return None;
    }

    Some(validated.state.claims)
}

/// Canonicalize the host portion of `jet_gw_url` for comparison against
/// `AgentTunnel.AdvertisedNames`.
///
/// - IP literals (IPv4 or IPv6) are parsed via `std::net::IpAddr` so
///   alternate textual forms collapse to the canonical one.
/// - IPv6 brackets (e.g. `[fd00::7]`) are stripped before parsing — `url::Url`
///   surfaces IPv6 hosts with brackets already included.
/// - DNS names are lower-cased (DNS is case-insensitive).
fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    // Strip surrounding brackets for IPv6 literals before parsing.
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

/// Parse `jet_gw_url` and return the normalized host portion.
///
/// Returns `None` when the URL is unparseable or has no host component.
fn enrollment_host(jet_gw_url: &str) -> Option<String> {
    let url = url::Url::parse(jet_gw_url).ok()?;
    let host = url.host_str()?;
    Some(normalize_host(host))
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
    ///
    /// Computed from the enrollment URL host (the host the agent actually used)
    /// plus the agent tunnel listen port. Kept for backward compatibility with
    /// older agents; new agents should prefer `quic_port` plus the host they
    /// already enrolled through.
    pub quic_endpoint: String,
    /// UDP port the agent tunnel QUIC listener is bound to.
    ///
    /// New field (compat bridge in the enrollment response). New agents should
    /// dial `(enrollment URL host, quic_port)` rather than parsing `quic_endpoint`.
    pub quic_port: u16,
    /// SHA-256 hash of the server certificate's SPKI (hex-encoded).
    /// Used by the agent to pin the server's public key.
    pub server_spki_sha256: String,
}

/// Structured 400 body returned when the enrollment URL host is not in
/// `AgentTunnel.AdvertisedNames`.
///
/// The agent CLI propagates this verbatim to stderr so the installer dialog
/// and Windows event log can surface the operator-facing help text.
#[derive(Serialize)]
struct EnrollmentRejection {
    /// Stable identifier for this error class. Always
    /// `"enrollment_host_not_advertised"` for this rejection.
    error: &'static str,
    /// One-sentence description of what is wrong.
    message: String,
    /// One paragraph telling the operator how to recover.
    help: String,
}

impl EnrollmentRejection {
    fn host_not_advertised(jwt_host: &str, allowed: &[String]) -> Self {
        let allowed_repr = serde_json::to_string(allowed).unwrap_or_else(|_| "[]".to_owned());
        Self {
            error: "enrollment_host_not_advertised",
            message: format!(
                "The Gateway is not advertised as '{jwt_host}'. Allowed advertised names: {allowed_repr}.",
            ),
            help: format!(
                "Either (a) regenerate the enrollment string in DVLS using one of the names listed above, \
                 or (b) ask the Gateway operator to add '{jwt_host}' to AgentTunnel.AdvertisedNames in \
                 gateway.json and restart the Gateway."
            ),
        }
    }

    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
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
/// Requires a Bearer token: a JWT signed by the configured provisioner key
/// (e.g. DVLS, Hub, or any PEM service) with `AgentEnroll` or `Wildcard` scope.
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
    Json(EnrollRequest {
        agent_id,
        agent_name,
        csr_pem,
        agent_hostname,
    }): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, Response> {
    // Validate agent name: 1-255 printable ASCII characters.
    if agent_name.is_empty() || 255 < agent_name.len() || agent_name.bytes().any(|b| !(0x20..=0x7E).contains(&b)) {
        return Err(http_err(HttpError::bad_request().msg("agent name must be 1-255 printable ASCII characters")));
    }

    let conf = conf_handle.get_conf();

    // Extract the Bearer token.
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| http_err(HttpError::unauthorized().msg("missing Authorization header")))?;

    let provided_token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| http_err(HttpError::unauthorized().msg("expected Bearer token")))?;

    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| http_err(HttpError::not_found().msg("agent enrollment is not configured")))?;

    let claims = validate_enrollment_jwt_claims(provided_token, &conf.provisioner_public_key)
        .ok_or_else(|| http_err(HttpError::forbidden().msg("invalid enrollment token")))?;

    // Parse the URL the agent enrolled through. The agent will dial QUIC at
    // this host:listen_port pair, so the gateway must (a) have a server cert
    // SAN matching this host and (b) explicitly advertise it as a valid name.
    let jwt_host = enrollment_host(&claims.jet_gw_url).ok_or_else(|| {
        http_err(HttpError::bad_request().msg("enrollment JWT jet_gw_url is missing or has no host component"))
    })?;

    // Build the canonical normalized list of advertised names.
    let advertised: Vec<String> = conf
        .agent_tunnel
        .advertised_names
        .iter()
        .map(|n| normalize_host(n.name()))
        .collect();

    if !advertised.iter().any(|name| name == &jwt_host) {
        warn!(
            jwt_host = %jwt_host,
            ?advertised,
            %agent_id,
            "Rejecting enrollment: jet_gw_url host is not in AgentTunnel.AdvertisedNames",
        );
        return Err(EnrollmentRejection::host_not_advertised(&jwt_host, &advertised).into_response());
    }

    // Reject duplicate agent IDs to prevent identity shadowing.
    if handle.registry().get(&agent_id).await.is_some() {
        return Err(http_err(
            crate::http::HttpErrorBuilder::new(StatusCode::CONFLICT).msg("agent ID already registered"),
        ));
    }

    let signed = handle
        .ca_manager()
        .sign_agent_csr(agent_id, &agent_name, &csr_pem, agent_hostname.as_deref())
        .map_err(|e| http_err(HttpError::bad_request().with_msg("invalid CSR").build(e)))?;

    // Compute `quic_endpoint` from the host the agent already used to reach the
    // gateway, NOT from `conf.hostname` — that was the old footgun.
    let listen_port = conf.agent_tunnel.listen_port;
    let quic_endpoint = format_endpoint(&jwt_host, listen_port);

    let advertised_names: Vec<&str> = conf
        .agent_tunnel
        .advertised_names
        .iter()
        .map(|n| n.name())
        .collect();

    let server_spki_sha256 = handle
        .ca_manager()
        .server_spki_sha256(&advertised_names)
        .map_err(|e| http_err(HttpError::internal().with_msg("compute server SPKI").build(e)))?;

    info!(
        %agent_id,
        agent_name = %agent_name,
        %jwt_host,
        quic_port = listen_port,
        "Agent enrolled successfully",
    );

    Ok(Json(EnrollResponse {
        agent_id,
        client_cert_pem: signed.client_cert_pem,
        gateway_ca_cert_pem: signed.ca_cert_pem,
        quic_endpoint,
        quic_port: listen_port,
        server_spki_sha256,
    }))
}

/// Wrap an `HttpError` as an Axum `Response` so the enrollment handler can
/// also return structured 400 bodies for host validation failures.
fn http_err(error: HttpError) -> Response {
    error.into_response()
}

/// Format a `host:port` endpoint with proper bracketing for IPv6 literals.
///
/// Kept here for the gateway's `quic_endpoint` compatibility field. The agent
/// uses an equivalent helper on its side.
fn format_endpoint(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
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
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    _access: AgentManagementReadAccess,
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
    State(DgwState {
        agent_tunnel_handle, ..
    }): State<DgwState>,
    _access: AgentManagementWriteAccess,
    Path(agent_id): Path<Uuid>,
) -> Result<StatusCode, HttpError> {
    let handle = agent_tunnel_handle
        .as_ref()
        .ok_or_else(|| HttpError::not_found().msg("agent tunnel not configured"))?;

    handle
        .registry()
        .unregister(&agent_id)
        .await
        .ok_or_else(|| HttpError::not_found().msg("agent not found"))?;

    info!(%agent_id, "Agent deleted via API");

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use picky::jose::jws::JwsAlg;
    use picky::jose::jwt::CheckedJwtSig;
    use picky::key::{PrivateKey, PublicKey};
    use serde_json::json;
    use uuid::Uuid;

    use super::validate_enrollment_jwt_claims;

    /// Thin wrapper preserving the old assertion ergonomics.
    fn validate_enrollment_jwt(token: &str, key: &PublicKey) -> bool {
        validate_enrollment_jwt_claims(token, key).is_some()
    }

    fn keypair() -> (PrivateKey, PublicKey) {
        let private_key = PrivateKey::generate_rsa(2048).expect("generate RSA private key");
        let public_key = private_key.to_public_key().expect("derive public key");
        (private_key, public_key)
    }

    /// `strict` validation requires both `nbf` and `exp`.
    fn now_ts() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    fn sign(claims: serde_json::Value, key: &PrivateKey) -> String {
        CheckedJwtSig::new(JwsAlg::RS256, claims).encode(key).expect("sign JWT")
    }

    #[test]
    fn accepts_well_formed_enrollment_jwt() {
        let (priv_key, pub_key) = keypair();
        let token = sign(
            json!({
                "scope": "gateway.agent.enroll",
                "nbf": now_ts() - 60,
                "exp": now_ts() + 3600,
                "jti": Uuid::new_v4(),
                "jet_gw_url": "https://gw.example.com:7171",
                "jet_agent_name": "site-a-agent",
            }),
            &priv_key,
        );

        assert!(validate_enrollment_jwt(&token, &pub_key));
    }

    #[test]
    fn accepts_wildcard_scope() {
        let (priv_key, pub_key) = keypair();
        let token = sign(
            json!({
                "scope": "*",
                "nbf": now_ts() - 60,
                "exp": now_ts() + 3600,
                "jti": Uuid::new_v4(),
                "jet_gw_url": "https://gw.example.com",
            }),
            &priv_key,
        );

        assert!(validate_enrollment_jwt(&token, &pub_key));
    }

    #[test]
    fn rejects_wrong_scope() {
        let (priv_key, pub_key) = keypair();
        let token = sign(
            json!({
                "scope": "gateway.sessions.read",
                "nbf": now_ts() - 60,
                "exp": now_ts() + 3600,
                "jti": Uuid::new_v4(),
                "jet_gw_url": "https://gw.example.com",
            }),
            &priv_key,
        );

        assert!(!validate_enrollment_jwt(&token, &pub_key));
    }

    #[test]
    fn rejects_expired_token() {
        let (priv_key, pub_key) = keypair();
        let token = sign(
            json!({
                "scope": "gateway.agent.enroll",
                "nbf": now_ts() - 7200,
                "exp": now_ts() - 3600,
                "jti": Uuid::new_v4(),
                "jet_gw_url": "https://gw.example.com",
            }),
            &priv_key,
        );

        assert!(!validate_enrollment_jwt(&token, &pub_key));
    }

    #[test]
    fn rejects_signature_from_different_key() {
        let (attacker_priv, _) = keypair();
        let (_, gateway_pub) = keypair();
        let token = sign(
            json!({
                "scope": "gateway.agent.enroll",
                "nbf": now_ts() - 60,
                "exp": now_ts() + 3600,
                "jti": Uuid::new_v4(),
                "jet_gw_url": "https://gw.example.com",
            }),
            &attacker_priv,
        );

        assert!(!validate_enrollment_jwt(&token, &gateway_pub));
    }

    #[test]
    fn rejects_missing_jet_gw_url() {
        let (priv_key, pub_key) = keypair();
        let token = sign(
            json!({
                "scope": "gateway.agent.enroll",
                "nbf": now_ts() - 60,
                "exp": now_ts() + 3600,
                "jti": Uuid::new_v4(),
                // jet_gw_url missing
            }),
            &priv_key,
        );

        assert!(!validate_enrollment_jwt(&token, &pub_key));
    }

    #[test]
    fn rejects_non_jwt_strings() {
        let (_, pub_key) = keypair();
        assert!(!validate_enrollment_jwt("not-a-jwt", &pub_key));
        assert!(!validate_enrollment_jwt("", &pub_key));
        assert!(!validate_enrollment_jwt("only.two", &pub_key));
    }

    // ---- Host normalization & enrollment URL parsing -------------------------

    #[test]
    fn normalize_host_lowercases_dns() {
        assert_eq!(super::normalize_host("Gateway.Example.COM"), "gateway.example.com");
        assert_eq!(super::normalize_host("  HOST  "), "host");
    }

    #[test]
    fn normalize_host_canonicalizes_ipv4() {
        // Different textual forms of 10.10.0.7 collapse onto canonical form via IpAddr::parse.
        assert_eq!(super::normalize_host("10.10.0.7"), "10.10.0.7");
    }

    #[test]
    fn normalize_host_canonicalizes_ipv6() {
        // Verbose IPv6 collapses to the canonical compressed form.
        assert_eq!(super::normalize_host("fd00:0000:0000:0000:0000:0000:0000:0007"), "fd00::7");
        assert_eq!(super::normalize_host("FD00::7"), "fd00::7");
    }

    #[test]
    fn enrollment_host_extracts_normalized_host() {
        assert_eq!(
            super::enrollment_host("https://Gateway.Example.COM:7171").as_deref(),
            Some("gateway.example.com"),
        );
        assert_eq!(super::enrollment_host("http://10.10.0.7:7777").as_deref(), Some("10.10.0.7"));
        // url::Url surfaces IPv6 hosts without brackets.
        assert_eq!(super::enrollment_host("https://[fd00::7]:7171").as_deref(), Some("fd00::7"));
    }

    #[test]
    fn enrollment_host_rejects_no_host() {
        // No scheme means url::Url cannot parse this as an absolute URL.
        assert!(super::enrollment_host("not-a-url").is_none());
    }

    // ---- format_endpoint with IPv6 bracketing --------------------------------

    #[test]
    fn format_endpoint_dns() {
        assert_eq!(super::format_endpoint("gateway.example.com", 4433), "gateway.example.com:4433");
    }

    #[test]
    fn format_endpoint_ipv4() {
        assert_eq!(super::format_endpoint("10.10.0.7", 4433), "10.10.0.7:4433");
    }

    #[test]
    fn format_endpoint_ipv6_is_bracketed() {
        assert_eq!(super::format_endpoint("fd00::7", 4433), "[fd00::7]:4433");
    }

    // ---- AdvertisedName serde ------------------------------------------------

    #[test]
    fn advertised_name_deserializes_bare_string() {
        let value: crate::config::dto::AdvertisedName =
            serde_json::from_str("\"gateway.corp.example.com\"").expect("parse bare");
        assert_eq!(value.name(), "gateway.corp.example.com");
        assert_eq!(value.label(), None);
    }

    #[test]
    fn advertised_name_deserializes_labeled_object() {
        let value: crate::config::dto::AdvertisedName =
            serde_json::from_str(r#"{ "Name": "10.10.0.7", "Label": "Customer LAN" }"#).expect("parse labeled");
        assert_eq!(value.name(), "10.10.0.7");
        assert_eq!(value.label(), Some("Customer LAN"));
    }

    #[test]
    fn advertised_name_accepts_lowercase_keys_too() {
        let value: crate::config::dto::AdvertisedName =
            serde_json::from_str(r#"{ "name": "host", "label": "lab" }"#).expect("parse lowercase keys");
        assert_eq!(value.name(), "host");
        assert_eq!(value.label(), Some("lab"));
    }

    #[test]
    fn advertised_name_roundtrips_bare_form_when_no_label() {
        let value = crate::config::dto::AdvertisedName::Bare("gateway.corp.example.com".to_owned());
        let json = serde_json::to_string(&value).expect("serialize bare");
        assert_eq!(json, "\"gateway.corp.example.com\"");
    }

    // ---- EnrollmentRejection JSON body shape --------------------------------

    #[test]
    fn enrollment_rejection_body_carries_error_message_help_triple() {
        let rejection = super::EnrollmentRejection::host_not_advertised(
            "evil.example.com",
            &["gateway.corp.example.com".to_owned(), "10.10.0.7".to_owned()],
        );
        let json = serde_json::to_value(&rejection).expect("serialize rejection");
        assert_eq!(json["error"], serde_json::json!("enrollment_host_not_advertised"));
        let message = json["message"].as_str().expect("message string");
        assert!(message.contains("evil.example.com"), "{message}");
        assert!(message.contains("gateway.corp.example.com"), "{message}");
        assert!(message.contains("10.10.0.7"), "{message}");
        let help = json["help"].as_str().expect("help string");
        assert!(help.contains("AdvertisedNames"), "{help}");
        assert!(help.contains("regenerate the enrollment string"), "{help}");
    }

    // ---- AdvertisedName serde, continued ------------------------------------

    #[test]
    fn advertised_name_serializes_labeled_as_object() {
        let value = crate::config::dto::AdvertisedName::Labeled {
            name: "10.10.0.7".to_owned(),
            label: Some("Customer LAN".to_owned()),
        };
        let json = serde_json::to_string(&value).expect("serialize labeled");
        // Object with both Name + Label.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["Name"], serde_json::json!("10.10.0.7"));
        assert_eq!(parsed["Label"], serde_json::json!("Customer LAN"));
    }
}
