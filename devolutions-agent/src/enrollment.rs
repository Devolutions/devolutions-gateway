//! Agent enrollment logic for QUIC tunnel.
//!
//! This module handles the enrollment process where an agent registers with
//! the Gateway and receives its client certificate and configuration.

use anyhow::{Context as _, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config;

/// Request body for enrollment API
#[derive(Serialize)]
struct EnrollRequest {
    /// Friendly name for the agent
    agent_name: String,
}

/// Response from enrollment API
#[derive(Deserialize)]
struct EnrollResponse {
    agent_id: Uuid,
    agent_name: String,
    client_cert_pem: String,
    client_key_pem: String,
    gateway_ca_cert_pem: String,
    quic_endpoint: String,
}

#[derive(Debug, Clone)]
pub struct PersistedEnrollment {
    pub agent_id: Uuid,
    pub agent_name: String,
    pub config_path: Utf8PathBuf,
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
/// * `config_path` - Path where to save the configuration file
/// * `advertise_subnets` - List of subnets to advertise (e.g., ["10.0.0.0/8"])
#[expect(
    clippy::print_stdout,
    reason = "CLI enrollment intentionally prints user-facing progress before the agent logger is running"
)]
pub async fn enroll_agent(
    gateway_url: &str,
    enrollment_token: &str,
    agent_name: &str,
    config_path: &Utf8PathBuf,
    advertise_subnets: Vec<String>,
) -> Result<()> {
    println!("Enrolling agent with Gateway...");
    println!("  Gateway URL: {}", gateway_url);
    println!("  Agent Name: {}", agent_name);
    println!("  Subnets: {:?}", advertise_subnets);

    let persisted = bootstrap_and_persist(
        gateway_url,
        enrollment_token,
        agent_name,
        config_path.as_ref(),
        advertise_subnets,
    )
    .await?;

    println!("✓ Enrollment successful");
    println!("  Agent ID: {}", persisted.agent_id);
    println!("  Agent Name: {}", persisted.agent_name);
    println!("✓ Certificates saved");
    println!("  Client cert: {}", persisted.client_cert_path);
    println!("  Client key: {}", persisted.client_key_path);
    println!("  Gateway CA: {}", persisted.gateway_ca_path);
    println!("✓ Configuration saved: {}", persisted.config_path);
    println!();
    println!("Enrollment complete! You can now run the agent with:");
    println!("  devolutions-agent run --config {}", persisted.config_path);

    Ok(())
}

pub async fn bootstrap_and_persist(
    gateway_url: &str,
    enrollment_token: &str,
    agent_name: &str,
    config_path: &Utf8Path,
    advertise_subnets: Vec<String>,
) -> Result<PersistedEnrollment> {
    let enroll_response = request_enrollment(gateway_url, enrollment_token, agent_name).await?;
    persist_enrollment_response(config_path, advertise_subnets, enroll_response)
}

async fn request_enrollment(gateway_url: &str, enrollment_token: &str, agent_name: &str) -> Result<EnrollResponse> {
    let client = reqwest::Client::new();
    let enroll_url = format!("{}/jet/agent-tunnel/enroll", gateway_url.trim_end_matches('/'));

    let response = client
        .post(&enroll_url)
        .bearer_auth(enrollment_token)
        .json(&EnrollRequest {
            agent_name: agent_name.to_owned(),
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
    config_path: &Utf8Path,
    advertise_subnets: Vec<String>,
    enroll_response: EnrollResponse,
) -> Result<PersistedEnrollment> {
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

    std::fs::write(&client_cert_path, &enroll_response.client_cert_pem)
        .with_context(|| format!("failed to write client certificate: {}", client_cert_path))?;

    std::fs::write(&client_key_path, &enroll_response.client_key_pem)
        .with_context(|| format!("failed to write client private key: {}", client_key_path))?;

    std::fs::write(&gateway_ca_path, &enroll_response.gateway_ca_cert_pem)
        .with_context(|| format!("failed to write gateway CA certificate: {}", gateway_ca_path))?;

    let tunnel_conf = config::dto::TunnelConf {
        enabled: true,
        gateway_endpoint: enroll_response.quic_endpoint.clone(),
        client_cert_path: Some(client_cert_path.clone()),
        client_key_path: Some(client_key_path.clone()),
        gateway_ca_cert_path: Some(gateway_ca_path.clone()),
        advertise_subnets,
        heartbeat_interval_secs: Some(60),
        route_advertise_interval_secs: Some(30),
    };

    let conf_file = config::dto::ConfFile {
        verbosity_profile: Some(config::dto::VerbosityProfile::Debug),
        log_file: None,
        updater: None,
        remote_desktop: None,
        pedm: None,
        session: None,
        tunnel: Some(tunnel_conf),
        proxy: None,
        debug: None,
        rest: serde_json::Map::new(),
    };

    config::save_config_at_path(config_path, &conf_file)?;

    Ok(PersistedEnrollment {
        agent_id: enroll_response.agent_id,
        agent_name: enroll_response.agent_name,
        config_path: config_path.to_owned(),
        client_cert_path,
        client_key_path,
        gateway_ca_path,
        quic_endpoint: enroll_response.quic_endpoint,
    })
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn persist_enrollment_response_writes_state_and_config() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config_path =
            Utf8PathBuf::from_path_buf(temp_dir.path().join("state").join("agent.json")).expect("utf-8 path");
        let agent_id = Uuid::new_v4();

        let persisted = persist_enrollment_response(
            config_path.as_ref(),
            vec!["10.0.0.0/8".to_owned(), "192.168.1.0/24".to_owned()],
            EnrollResponse {
                agent_id,
                agent_name: "site-a-agent".to_owned(),
                client_cert_pem: "client-cert".to_owned(),
                client_key_pem: "client-key".to_owned(),
                gateway_ca_cert_pem: "gateway-ca".to_owned(),
                quic_endpoint: "gateway.example.com:4433".to_owned(),
            },
        )
        .expect("persist enrollment response");

        assert_eq!(persisted.agent_id, agent_id);
        assert_eq!(persisted.config_path, config_path);
        assert_eq!(
            std::fs::read_to_string(&persisted.client_cert_path).expect("read client cert"),
            "client-cert"
        );
        assert_eq!(
            std::fs::read_to_string(&persisted.client_key_path).expect("read client key"),
            "client-key"
        );
        assert_eq!(
            std::fs::read_to_string(&persisted.gateway_ca_path).expect("read gateway ca"),
            "gateway-ca"
        );

        let saved_config = std::fs::read_to_string(&config_path).expect("read config");
        let parsed: config::dto::ConfFile = serde_json::from_str(&saved_config).expect("parse config");
        let tunnel = parsed.tunnel.expect("tunnel config");

        assert!(tunnel.enabled);
        assert_eq!(tunnel.gateway_endpoint, "gateway.example.com:4433");
        assert_eq!(tunnel.advertise_subnets, vec!["10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(tunnel.client_cert_path, Some(persisted.client_cert_path));
        assert_eq!(tunnel.client_key_path, Some(persisted.client_key_path));
        assert_eq!(tunnel.gateway_ca_cert_path, Some(persisted.gateway_ca_path));
    }
}
