//! Agent enrollment logic for QUIC tunnel.
//!
//! This module handles the enrollment process where an agent registers with
//! the Gateway and receives its client certificate and configuration.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config;

/// Subset of the enrollment JWT claims needed by the agent.
///
/// The agent does *not* verify the signature — it trusts whoever handed over
/// the JWT (the operator). The Gateway verifies the signature when the JWT is
/// presented as the Bearer token on `/jet/tunnel/enroll`.
///
/// Additional standard claims (`exp`, `jti`, `scope`, ...) are ignored here.
#[derive(Debug, serde::Deserialize)]
pub struct EnrollmentJwtClaims {
    /// Gateway URL to connect to for enrollment.
    pub jet_gw_url: String,
    /// Suggested agent display name (optional hint).
    #[serde(default)]
    pub jet_agent_name: Option<String>,
    /// QUIC endpoint (`host:port`) the agent should connect to for the tunnel.
    ///
    /// # Why the operator must supply this
    ///
    /// A running gateway has no way to discover the address its clients actually
    /// route to: that is a view from outside the host, not from inside. The moment
    /// there is any translation layer between the gateway and the agent, a
    /// self-reported `conf.hostname:listen_port` will differ from what the agent
    /// needs. Common cases:
    ///
    /// 1. **Docker / Kubernetes**: `conf.hostname` defaults to the container ID or
    ///    pod name, which is not resolvable outside the bridge/cluster network.
    /// 2. **Split-horizon DNS / NAT**: the gateway knows itself by an internal
    ///    name that does not resolve (or resolves to a different IP) from the
    ///    agent's network.
    /// 3. **HA behind a load balancer**: individual gateway nodes have per-node
    ///    hostnames, but agents must connect to the LB VIP or a stable DNS name.
    ///
    /// Rather than silently shipping a wrong self-report and hoping the operator
    /// notices when tunnels fail, the gateway deliberately does NOT return a QUIC
    /// endpoint from its enroll API. The operator — who designed the network —
    /// supplies the correct address here when minting the enrollment JWT.
    ///
    /// Optional at the JWT level only because the `--quic-endpoint` CLI flag can
    /// provide it instead. The agent refuses to start if neither is given.
    #[serde(default)]
    pub jet_quic_endpoint: Option<String>,
}

/// Decode an enrollment JWT to extract agent-side configuration claims.
///
/// The JWT format is `<header>.<payload>.<signature>`, each part base64url-encoded.
/// This parser reads the payload only; signature verification is the Gateway's job
/// once the JWT is presented as a Bearer token.
///
/// We keep the split/decode inline instead of pulling in `picky` just for
/// unverified payload decoding — the dependency cost isn't worth saving a
/// dozen lines of straightforward parsing, and agent binary size matters.
pub fn parse_enrollment_jwt(jwt: &str) -> Result<EnrollmentJwtClaims> {
    let mut parts = jwt.split('.');
    let _header = parts.next().context("enrollment JWT missing header")?;
    let payload = parts
        .next()
        .filter(|s| !s.is_empty())
        .context("enrollment JWT missing payload")?;
    let _signature = parts.next().context("enrollment JWT missing signature")?;

    if parts.next().is_some() {
        bail!("enrollment JWT has too many segments");
    }

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("enrollment JWT payload is not valid base64url")?;

    serde_json::from_slice(&decoded).context("enrollment JWT payload is not valid JSON or missing required claims")
}

/// Request body for enrollment API
#[derive(Serialize)]
struct EnrollRequest {
    /// Agent-generated UUID (the agent owns its identity)
    agent_id: Uuid,
    /// Friendly name for the agent
    agent_name: String,
    /// PEM-encoded Certificate Signing Request
    csr_pem: String,
    /// Optional hostname of the agent machine (added as DNS SAN in the issued certificate)
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_hostname: Option<String>,
}

/// Response from enrollment API
#[derive(Deserialize)]
struct EnrollResponse {
    agent_id: Uuid,
    client_cert_pem: String,
    gateway_ca_cert_pem: String,
    server_spki_sha256: String,
}

#[derive(Debug, Clone)]
pub struct PersistedEnrollment {
    pub agent_id: Uuid,
    pub agent_name: String,
    pub client_cert_path: Utf8PathBuf,
    pub client_key_path: Utf8PathBuf,
    pub gateway_ca_path: Utf8PathBuf,
    pub quic_endpoint: String,
}

/// Enroll an agent with the Gateway and save the configuration.
///
/// # Arguments
/// * `gateway_url` - Base Gateway URL (e.g., "https://gateway.example.com:7171")
/// * `enrollment_token` - JWT token for enrollment
/// * `agent_name` - Friendly name for this agent
/// * `advertise_subnets` - List of subnets to advertise (e.g., ["10.0.0.0/8"])
/// * `quic_endpoint` - QUIC endpoint (`host:port`) the agent should connect to for the
///   tunnel. The gateway does not report this: a running process cannot know the address
///   its clients actually route to (Docker/K8s, NAT, split-horizon DNS, LB VIP). The
///   operator supplies it via the `jet_quic_endpoint` JWT claim or the `--quic-endpoint`
///   CLI flag. See [`EnrollmentJwtClaims::jet_quic_endpoint`] for the full rationale.
pub async fn enroll_agent(
    gateway_url: &str,
    enrollment_token: &str,
    agent_name: &str,
    advertise_subnets: Vec<String>,
    quic_endpoint: String,
) -> Result<PersistedEnrollment> {
    // Generate key pair and CSR locally — the private key never leaves this machine.
    let (key_pem, csr_pem) = generate_key_and_csr(agent_name)?;

    let enroll_response = request_enrollment(gateway_url, enrollment_token, agent_name, &csr_pem).await?;

    persist_enrollment_response(agent_name, advertise_subnets, enroll_response, quic_endpoint, &key_pem)
}

/// Generate an ECDSA P-256 key pair and a CSR containing the agent name as CN.
///
/// Returns `(key_pem, csr_pem)`. The private key stays on the agent; only the
/// CSR is sent to the gateway.
fn generate_key_and_csr(agent_name: &str) -> Result<(String, String)> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate agent key pair")?;
    let key_pem = key_pair.serialize_pem();

    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, agent_name);

    let csr = params.serialize_request(&key_pair).context("generate CSR")?;
    let csr_pem = csr.pem().context("encode CSR to PEM")?;

    Ok((key_pem, csr_pem))
}

async fn request_enrollment(
    gateway_url: &str,
    enrollment_token: &str,
    agent_name: &str,
    csr_pem: &str,
) -> Result<EnrollResponse> {
    let client = reqwest::Client::new();
    let enroll_url = format!("{}/jet/tunnel/enroll", gateway_url.trim_end_matches('/'));

    let response = client
        .post(&enroll_url)
        .bearer_auth(enrollment_token)
        .json(&EnrollRequest {
            agent_id: Uuid::new_v4(),
            agent_name: agent_name.to_owned(),
            csr_pem: csr_pem.to_owned(),
            agent_hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .filter(|h| !h.is_empty()),
        })
        .send()
        .await
        .context("failed to send enrollment request")?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        bail!("enrollment failed with status {}: {}", status, error_text);
    }

    response.json().await.context("failed to parse enrollment response")
}

fn persist_enrollment_response(
    agent_name: &str,
    advertise_subnets: Vec<String>,
    EnrollResponse {
        agent_id,
        client_cert_pem,
        gateway_ca_cert_pem,
        server_spki_sha256,
    }: EnrollResponse,
    quic_endpoint: String,
    key_pem: &str,
) -> Result<PersistedEnrollment> {
    let config_path = config::get_conf_file_path();
    let config_dir = config_path
        .parent()
        .filter(|path| !path.as_str().is_empty())
        .map(Utf8Path::to_owned)
        .unwrap_or_else(|| Utf8PathBuf::from("."));
    let cert_dir = config_dir.join("certs");

    std::fs::create_dir_all(&cert_dir)
        .with_context(|| format!("failed to create certificate directory: {}", cert_dir))?;

    let client_cert_path = cert_dir.join(format!("{agent_id}-cert.pem"));
    let client_key_path = cert_dir.join(format!("{agent_id}-key.pem"));
    let gateway_ca_path = cert_dir.join("gateway-ca.pem");

    // Write the locally-generated private key first (before cert/CA from the network).
    std::fs::write(&client_key_path, key_pem)
        .with_context(|| format!("failed to write client private key: {client_key_path}"))?;

    std::fs::write(&client_cert_path, &client_cert_pem)
        .with_context(|| format!("failed to write client certificate: {client_cert_path}"))?;

    std::fs::write(&gateway_ca_path, &gateway_ca_cert_pem)
        .with_context(|| format!("failed to write gateway CA certificate: {gateway_ca_path}"))?;

    // Restrict permissions on cert/key files (owner-only on Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let restricted = std::fs::Permissions::from_mode(0o600);
        for path in [&client_cert_path, &client_key_path, &gateway_ca_path] {
            std::fs::set_permissions(path, restricted.clone())
                .with_context(|| format!("failed to set permissions on {path}"))?;
        }
    }

    // Load existing config and update only the Tunnel section.
    // This preserves other settings (Updater, Session, PEDM, etc.) that may have been
    // configured by the MSI installer or admin.
    let mut conf_file = config::load_conf_file_or_generate_new().context("failed to load existing configuration")?;

    // Preserve existing domain config from previous enrollment/manual configuration.
    let existing_tunnel = conf_file.tunnel.as_ref();

    let tunnel_conf = config::dto::TunnelConf {
        enabled: true,
        gateway_endpoint: quic_endpoint.clone(),
        client_cert_path: Some(client_cert_path.clone()),
        client_key_path: Some(client_key_path.clone()),
        gateway_ca_cert_path: Some(gateway_ca_path.clone()),
        advertise_subnets,
        advertise_domains: existing_tunnel.map(|t| t.advertise_domains.clone()).unwrap_or_default(),
        auto_detect_domain: existing_tunnel.map(|t| t.auto_detect_domain).unwrap_or(true),
        heartbeat_interval_secs: Some(60),
        route_advertise_interval_secs: Some(30),
        server_spki_sha256: Some(server_spki_sha256),
    };

    conf_file.tunnel = Some(tunnel_conf);

    config::save_config(&conf_file)?;

    Ok(PersistedEnrollment {
        agent_id,
        agent_name: agent_name.to_owned(),
        client_cert_path,
        client_key_path,
        gateway_ca_path,
        quic_endpoint,
    })
}

// ---------------------------------------------------------------------------
// Certificate renewal helpers
// ---------------------------------------------------------------------------

/// Check if a PEM certificate expires within `threshold_days`.
pub fn is_cert_expiring(cert_path: &Utf8Path, threshold_days: u32) -> Result<bool> {
    use std::io::BufReader;

    let pem_str = std::fs::read_to_string(cert_path).with_context(|| format!("read certificate from {cert_path}"))?;
    let der = rustls_pemfile::certs(&mut BufReader::new(pem_str.as_bytes()))
        .next()
        .context("empty PEM input")?
        .context("parse certificate PEM")?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow::anyhow!("parse X.509 certificate: {e}"))?;

    let not_after = cert.validity().not_after.to_datetime();

    let threshold_secs = i64::from(threshold_days) * 86400;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_secs();
    let now_epoch = i64::try_from(now_secs).context("unix timestamp exceeds i64::MAX")?;
    let not_after_epoch = not_after.unix_timestamp();

    Ok(not_after_epoch - now_epoch <= threshold_secs)
}

/// Read the CommonName from an existing PEM certificate.
///
/// Used by the renewal path: the agent must reuse its own name across renewals
/// because the gateway looks it up in the registry, and the most authoritative
/// source for that name is the cert the gateway itself issued last time.
pub fn read_agent_name_from_cert(cert_path: &Utf8Path) -> Result<String> {
    use std::io::BufReader;

    let pem_str = std::fs::read_to_string(cert_path).with_context(|| format!("read certificate from {cert_path}"))?;
    let der = rustls_pemfile::certs(&mut BufReader::new(pem_str.as_bytes()))
        .next()
        .context("empty PEM input")?
        .context("parse certificate PEM")?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow::anyhow!("parse X.509 certificate: {e}"))?;

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .context("certificate subject has no Common Name")?
        .as_str()
        .context("certificate Common Name is not valid UTF-8")?;

    Ok(cn.to_owned())
}

/// Generate a CSR using an existing private key (for renewal — key never changes).
pub fn generate_csr_from_existing_key(key_path: &Utf8Path, agent_name: &str) -> Result<String> {
    let key_pem = std::fs::read_to_string(key_path).with_context(|| format!("read private key from {key_path}"))?;
    let key_pair = rcgen::KeyPair::from_pem(&key_pem).context("parse private key PEM")?;

    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, agent_name);

    let csr = params.serialize_request(&key_pair).context("serialize renewal CSR")?;

    csr.pem().context("encode CSR to PEM")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a JWT with arbitrary header/signature placeholders. The parser never
    /// verifies the signature, so the content of those two segments is irrelevant.
    fn make_jwt(payload: serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            b64.encode(header.to_string()),
            b64.encode(payload.to_string()),
            b64.encode("signature-placeholder"),
        )
    }

    #[test]
    fn parse_enrollment_jwt_rejects_malformed() {
        assert!(parse_enrollment_jwt("not-a-jwt").is_err());
        assert!(parse_enrollment_jwt("only.two").is_err());
        assert!(parse_enrollment_jwt("four.parts.here.bad").is_err());
    }

    #[test]
    fn parse_enrollment_jwt_requires_gw_url() {
        let jwt = make_jwt(serde_json::json!({
            "scope": "gateway.agent.enroll",
            "jet_agent_name": "agent-a",
        }));
        assert!(parse_enrollment_jwt(&jwt).is_err());
    }
}
