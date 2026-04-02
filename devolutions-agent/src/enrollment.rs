//! Agent enrollment logic for QUIC tunnel.
//!
//! This module handles the enrollment process where an agent registers with
//! the Gateway and receives its client certificate and configuration.

use anyhow::Context as _;
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config;

/// Request body for enrollment API
#[derive(Serialize)]
struct EnrollRequest {
    /// Friendly name for the agent
    agent_name: String,
    /// PEM-encoded Certificate Signing Request
    csr_pem: String,
}

/// Response from enrollment API
#[derive(Deserialize)]
struct EnrollResponse {
    agent_id: Uuid,
    agent_name: String,
    client_cert_pem: String,
    gateway_ca_cert_pem: String,
    quic_endpoint: String,
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
) -> anyhow::Result<()> {
    bootstrap_and_persist(gateway_url, enrollment_token, agent_name, advertise_subnets).await?;
    Ok(())
}

pub async fn bootstrap_and_persist(
    gateway_url: &str,
    enrollment_token: &str,
    agent_name: &str,
    advertise_subnets: Vec<String>,
) -> anyhow::Result<PersistedEnrollment> {
    // Generate key pair and CSR locally — the private key never leaves this machine.
    let (key_pem, csr_pem) = generate_key_and_csr(agent_name)?;

    let enroll_response = request_enrollment(gateway_url, enrollment_token, agent_name, &csr_pem).await?;
    persist_enrollment_response(advertise_subnets, enroll_response, &key_pem)
}

/// Generate an ECDSA P-256 key pair and a CSR containing the agent name as CN.
///
/// Returns `(key_pem, csr_pem)`. The private key stays on the agent; only the
/// CSR is sent to the gateway.
fn generate_key_and_csr(agent_name: &str) -> anyhow::Result<(String, String)> {
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
) -> anyhow::Result<EnrollResponse> {
    let client = reqwest::Client::new();
    let enroll_url = format!("{}/jet/agent-tunnel/enroll", gateway_url.trim_end_matches('/'));

    let response = client
        .post(&enroll_url)
        .bearer_auth(enrollment_token)
        .json(&EnrollRequest {
            agent_name: agent_name.to_owned(),
            csr_pem: csr_pem.to_owned(),
        })
        .send()
        .await
        .context("failed to send enrollment request")?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        anyhow::bail!("enrollment failed with status {}: {}", status, error_text);
    }

    response.json().await.context("failed to parse enrollment response")
}

fn persist_enrollment_response(
    advertise_subnets: Vec<String>,
    enroll_response: EnrollResponse,
    key_pem: &str,
) -> anyhow::Result<PersistedEnrollment> {
    let config_path = config::get_conf_file_path();
    let config_dir = config_path
        .parent()
        .filter(|path| !path.as_str().is_empty())
        .map(Utf8Path::to_owned)
        .unwrap_or_else(|| Utf8PathBuf::from("."));
    let cert_dir = config_dir.join("certs");

    std::fs::create_dir_all(&cert_dir)
        .with_context(|| format!("failed to create certificate directory: {}", cert_dir))?;

    let client_cert_path = cert_dir.join(format!("{}-cert.pem", enroll_response.agent_id));
    let client_key_path = cert_dir.join(format!("{}-key.pem", enroll_response.agent_id));
    let gateway_ca_path = cert_dir.join("gateway-ca.pem");

    // Write the locally-generated private key first (before cert/CA from the network).
    std::fs::write(&client_key_path, key_pem)
        .with_context(|| format!("failed to write client private key: {}", client_key_path))?;

    std::fs::write(&client_cert_path, &enroll_response.client_cert_pem)
        .with_context(|| format!("failed to write client certificate: {}", client_cert_path))?;

    std::fs::write(&gateway_ca_path, &enroll_response.gateway_ca_cert_pem)
        .with_context(|| format!("failed to write gateway CA certificate: {}", gateway_ca_path))?;

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
        gateway_endpoint: enroll_response.quic_endpoint.clone(),
        client_cert_path: Some(client_cert_path.clone()),
        client_key_path: Some(client_key_path.clone()),
        gateway_ca_cert_path: Some(gateway_ca_path.clone()),
        advertise_subnets,
        advertise_domains: existing_tunnel.map(|t| t.advertise_domains.clone()).unwrap_or_default(),
        auto_detect_domain: existing_tunnel.map(|t| t.auto_detect_domain).unwrap_or(true),
        heartbeat_interval_secs: Some(60),
        route_advertise_interval_secs: Some(30),
    };

    conf_file.tunnel = Some(tunnel_conf);

    config::save_config(&conf_file)?;

    Ok(PersistedEnrollment {
        agent_id: enroll_response.agent_id,
        agent_name: enroll_response.agent_name,
        client_cert_path,
        client_key_path,
        gateway_ca_path,
        quic_endpoint: enroll_response.quic_endpoint,
    })
}
