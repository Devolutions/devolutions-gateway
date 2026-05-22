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
///
/// The compat bridge (per the identity refactor design) means both
/// `quic_endpoint` and `quic_port` may be present:
///
/// - `quic_port` is the canonical new field. Agents should pair it with the
///   host they already enrolled through (parsed from the JWT's `jet_gw_url`).
/// - `quic_endpoint` is kept for one release so older gateways still work.
///
/// Both fields are `#[serde(default)]` so the deserializer accepts either or
/// both. After enroll, the agent picks `quic_port` when available, otherwise
/// it parses the port off `quic_endpoint`.
#[derive(Deserialize)]
struct EnrollResponse {
    agent_id: Uuid,
    client_cert_pem: String,
    gateway_ca_cert_pem: String,
    #[serde(default)]
    quic_endpoint: Option<String>,
    #[serde(default)]
    quic_port: Option<u16>,
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
pub async fn enroll_agent(
    gateway_url: &str,
    enrollment_token: &str,
    agent_name: &str,
    advertise_subnets: Vec<String>,
) -> Result<PersistedEnrollment> {
    // Generate key pair and CSR locally — the private key never leaves this machine.
    let (key_pem, csr_pem) = generate_key_and_csr(agent_name)?;

    let enroll_response = request_enrollment(gateway_url, enrollment_token, agent_name, &csr_pem).await?;

    // The agent dials the QUIC tunnel at whichever host the operator already
    // proved is reachable from this agent's network — that's `gateway_url`'s
    // host. The Gateway tells the agent which *port* to dial (via `quic_port`),
    // not which host. For older Gateways the host is parsed off the legacy
    // `quic_endpoint` field.
    let enrollment_host = url::Url::parse(gateway_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned));

    persist_enrollment_response(
        agent_name,
        advertise_subnets,
        enroll_response,
        enrollment_host.as_deref(),
        &key_pem,
    )
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
        quic_endpoint,
        quic_port,
        server_spki_sha256,
    }: EnrollResponse,
    enrollment_host: Option<&str>,
    key_pem: &str,
) -> Result<PersistedEnrollment> {
    // Pick the QUIC port: prefer the new `quic_port` field, otherwise parse
    // the port off the legacy `quic_endpoint` (compat with older gateways).
    let quic_port_resolved = if let Some(port) = quic_port {
        port
    } else {
        let endpoint = quic_endpoint
            .as_deref()
            .context("enrollment response carries neither `quic_port` nor `quic_endpoint`")?;
        parse_endpoint_port(endpoint).with_context(|| format!("parse legacy quic_endpoint {endpoint:?}"))?
    };

    // Compose the gateway endpoint from `(enrollment_host, quic_port)` when we
    // know the enrollment host (new agents talking to new gateways and to old
    // gateways alike). If the caller did not pass it — only possible when
    // running against the unit tests or a malformed URL — fall back to the
    // legacy `quic_endpoint` verbatim.
    let resolved_endpoint = match enrollment_host {
        Some(host) => format_endpoint(host, quic_port_resolved),
        None => quic_endpoint
            .clone()
            .context("enrollment URL has no host and response did not include a usable quic_endpoint")?,
    };
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
        gateway_endpoint: resolved_endpoint.clone(),
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
        quic_endpoint: resolved_endpoint,
    })
}

/// Format a `host:port` endpoint string, bracketing IPv6 literals so the
/// resulting string is parseable as a `SocketAddr` and unambiguous to humans.
///
/// | host kind | output |
/// |---|---|
/// | DNS | `gateway.example.com:4433` |
/// | IPv4 | `10.10.0.7:4433` |
/// | IPv6 | `[fd00::7]:4433` |
///
/// The IPv6 case strips any pre-existing surrounding brackets first, so both
/// `fd00::7` and `[fd00::7]` produce the same canonical bracketed form.
pub fn format_endpoint(host: &str, port: u16) -> String {
    let trimmed = host.trim();
    // url::Url surfaces IPv6 hosts already bracketed; strip them here so we
    // can detect "it's an IPv6 literal" by trying to parse as Ipv6Addr.
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    if unbracketed.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{unbracketed}]:{port}")
    } else {
        format!("{trimmed}:{port}")
    }
}

/// Parse the port off a legacy `quic_endpoint` string of the form
/// `<host>:<port>` (DNS / IPv4) or `[<ipv6>]:<port>`.
fn parse_endpoint_port(endpoint: &str) -> Result<u16> {
    let trimmed = endpoint.trim();
    let port_str = if let Some(rest) = trimmed.rsplit_once(']') {
        // IPv6: "[host]:port" — `rest.0` is "[host", `rest.1` is ":port".
        rest.1
            .strip_prefix(':')
            .context("missing ':' before port in bracketed endpoint")?
    } else {
        // DNS / IPv4: "host:port" — split on the last ':' since DNS / IPv4 have no colons in the host.
        trimmed
            .rsplit_once(':')
            .map(|(_, p)| p)
            .context("missing ':' between host and port in endpoint")?
    };
    port_str.parse::<u16>().context("endpoint port is not a valid u16")
}

// ---------------------------------------------------------------------------
// Certificate renewal helpers
// ---------------------------------------------------------------------------

/// Check whether the PEM-encoded certificate at `cert_path` expires within
/// `threshold_days`. The agent uses this on every reconnect to decide whether
/// to ask the gateway for a new certificate before opening real traffic.
pub fn is_cert_expiring(cert_path: &Utf8Path, threshold_days: u32) -> Result<bool> {
    use std::io::BufReader;

    let pem_str = std::fs::read_to_string(cert_path).with_context(|| format!("read certificate from {cert_path}"))?;
    let der = rustls_pemfile::certs(&mut BufReader::new(pem_str.as_bytes()))
        .next()
        .context("empty PEM input")?
        .context("parse certificate PEM")?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow::anyhow!("parse X.509 certificate: {e}"))?;

    let not_after_epoch = cert.validity().not_after.timestamp();
    let now_epoch = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before UNIX epoch")?
            .as_secs(),
    )
    .context("unix timestamp exceeds i64::MAX")?;

    let threshold_secs = i64::from(threshold_days) * 86_400;
    Ok(not_after_epoch - now_epoch <= threshold_secs)
}

/// Extract the `CommonName` from an existing PEM certificate. The renewal CSR
/// must reuse the agent's name across renewals — the gateway looks the agent
/// up in its registry by that name, and the most authoritative source for it
/// is the cert the gateway itself signed last time.
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

/// Build a renewal CSR using the agent's existing private key. Reusing the key
/// across renewals matches the design that says the private key never leaves
/// the agent — the gateway only ever sees CSRs.
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
            "scope": "gateway.tunnel.enroll",
            "jet_agent_name": "agent-a",
        }));
        assert!(parse_enrollment_jwt(&jwt).is_err());
    }

    // ---- format_endpoint -----------------------------------------------------

    #[test]
    fn format_endpoint_dns() {
        assert_eq!(format_endpoint("gateway.example.com", 4433), "gateway.example.com:4433");
    }

    #[test]
    fn format_endpoint_ipv4() {
        assert_eq!(format_endpoint("10.10.0.7", 4433), "10.10.0.7:4433");
    }

    #[test]
    fn format_endpoint_ipv6_bracketed() {
        assert_eq!(format_endpoint("fd00::7", 4433), "[fd00::7]:4433");
    }

    #[test]
    fn format_endpoint_ipv6_already_bracketed_input() {
        // Defensive: if the caller already pre-bracketed (as `url::Url::host_str`
        // does for IPv6), the helper still produces the canonical form once.
        assert_eq!(format_endpoint("[fd00::7]", 4433), "[fd00::7]:4433");
    }

    // ---- parse_endpoint_port -------------------------------------------------

    #[test]
    fn parse_endpoint_port_dns() {
        assert_eq!(parse_endpoint_port("gateway.example.com:4433").unwrap(), 4433);
    }

    #[test]
    fn parse_endpoint_port_ipv4() {
        assert_eq!(parse_endpoint_port("10.10.0.7:4433").unwrap(), 4433);
    }

    #[test]
    fn parse_endpoint_port_ipv6_bracketed() {
        assert_eq!(parse_endpoint_port("[fd00::7]:4433").unwrap(), 4433);
    }

    #[test]
    fn parse_endpoint_port_rejects_no_colon() {
        assert!(parse_endpoint_port("gateway.example.com").is_err());
    }

    // ---- EnrollResponse deserialization --------------------------------------

    /// New gateway: both `quic_endpoint` and `quic_port` present. Agent prefers
    /// `quic_port`.
    #[test]
    fn enroll_response_accepts_new_compat_bridge_payload() {
        let body = serde_json::json!({
            "agent_id": "00000000-0000-0000-0000-000000000001",
            "client_cert_pem": "stub",
            "gateway_ca_cert_pem": "stub",
            "quic_endpoint": "10.10.0.7:4433",
            "quic_port": 4433,
            "server_spki_sha256": "deadbeef",
        });
        let parsed: EnrollResponse = serde_json::from_value(body).expect("parse new payload");
        assert_eq!(parsed.quic_port, Some(4433));
        assert_eq!(parsed.quic_endpoint.as_deref(), Some("10.10.0.7:4433"));
    }

    /// Legacy gateway: only `quic_endpoint`. Agent must fall back to parsing it.
    #[test]
    fn enroll_response_accepts_legacy_payload_without_quic_port() {
        let body = serde_json::json!({
            "agent_id": "00000000-0000-0000-0000-000000000001",
            "client_cert_pem": "stub",
            "gateway_ca_cert_pem": "stub",
            "quic_endpoint": "10.10.0.7:4433",
            "server_spki_sha256": "deadbeef",
        });
        let parsed: EnrollResponse = serde_json::from_value(body).expect("parse legacy payload");
        assert_eq!(parsed.quic_port, None);
        assert_eq!(parsed.quic_endpoint.as_deref(), Some("10.10.0.7:4433"));
    }
}
