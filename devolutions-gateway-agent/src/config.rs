use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context as _, Result};
use base64::Engine as _;
use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wireguard_tunnel::StaticSecret;
use zeroize::Zeroizing;

/// Agent configuration loaded from TOML file
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    /// Agent unique identifier
    pub agent_id: Uuid,

    /// Friendly name for the agent
    pub name: String,

    /// Gateway endpoint (host:port or IP:port)
    pub gateway_endpoint: String,

    /// WireGuard private key (base64)
    pub private_key: String,

    /// Gateway's WireGuard public key (base64)
    pub gateway_public_key: String,

    /// Agent's assigned tunnel IP
    pub assigned_ip: Ipv4Addr,

    /// Gateway's tunnel IP
    pub gateway_ip: Ipv4Addr,

    /// Subnets this agent should advertise to Gateway (CIDR notation)
    #[serde(default)]
    pub advertise_subnets: Vec<String>,

    /// Optional keepalive interval in seconds
    #[serde(default)]
    pub keepalive_interval: Option<u64>,
}

/// Validated runtime configuration
pub struct RuntimeConfig {
    pub agent_id: Uuid,
    pub name: String,
    pub gateway_endpoint: String,
    pub private_key: StaticSecret,
    pub gateway_public_key: wireguard_tunnel::PublicKey,
    pub assigned_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    #[allow(dead_code)]
    pub advertise_subnets: Vec<Ipv4Network>,
    #[allow(dead_code)]
    pub keepalive_interval: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentStringPayload {
    pub version: u8,
    pub api_base_url: String,
    pub wireguard_endpoint: String,
    pub enrollment_token: String,
}

impl AgentConfig {
    /// Load configuration from TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        toml::from_str(&content).context("Failed to parse TOML configuration")
    }

    pub fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize TOML configuration")?;
        std::fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write config file: {}", path.as_ref().display()))
    }

    /// Validate and convert to runtime configuration
    pub fn into_runtime(self) -> Result<RuntimeConfig> {
        // Decode private key
        let private_key_bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&self.private_key)
                .context("Invalid base64 in private_key")?,
        );

        anyhow::ensure!(
            private_key_bytes.len() == 32,
            "Private key must be 32 bytes, got {}",
            private_key_bytes.len()
        );

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&private_key_bytes);
        let private_key = StaticSecret::from(key_array);

        // Decode gateway public key
        let gateway_pub_bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&self.gateway_public_key)
                .context("Invalid base64 in gateway_public_key")?,
        );

        anyhow::ensure!(
            gateway_pub_bytes.len() == 32,
            "Gateway public key must be 32 bytes, got {}",
            gateway_pub_bytes.len()
        );

        let mut pub_array = [0u8; 32];
        pub_array.copy_from_slice(&gateway_pub_bytes);
        let gateway_public_key = wireguard_tunnel::PublicKey::from(pub_array);

        // Parse advertised subnets
        let advertise_subnets: Result<Vec<Ipv4Network>> = self
            .advertise_subnets
            .iter()
            .map(|s| s.parse().with_context(|| format!("Invalid subnet: {}", s)))
            .collect();

        Ok(RuntimeConfig {
            agent_id: self.agent_id,
            name: self.name,
            gateway_endpoint: self.gateway_endpoint,
            private_key,
            gateway_public_key,
            assigned_ip: self.assigned_ip,
            gateway_ip: self.gateway_ip,
            advertise_subnets: advertise_subnets?,
            keepalive_interval: self.keepalive_interval,
        })
    }
}

/// Generate a sample configuration file
pub fn generate_sample_config() -> String {
    let sample = AgentConfig {
        agent_id: Uuid::new_v4(),
        name: "sample-agent".to_owned(),
        gateway_endpoint: "gateway.example.com:51820".to_owned(),
        private_key: "<base64-encoded-32-byte-key>".to_owned(),
        gateway_public_key: "<gateway-base64-public-key>".to_owned(),
        assigned_ip: "10.10.0.2".parse().unwrap(),
        gateway_ip: "10.10.0.1".parse().unwrap(),
        advertise_subnets: vec!["192.168.1.0/24".to_owned(), "10.0.0.0/8".to_owned()],
        keepalive_interval: Some(25),
    };

    toml::to_string_pretty(&sample).unwrap()
}

pub fn parse_enrollment_string(enrollment_string: &str) -> Result<EnrollmentStringPayload> {
    use base64::Engine as _;

    let payload = enrollment_string
        .strip_prefix("dgw-enroll:v1:")
        .context("Invalid enrollment string prefix")?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("Invalid base64 in enrollment string")?;
    let payload: EnrollmentStringPayload =
        serde_json::from_slice(&payload_bytes).context("Invalid JSON payload in enrollment string")?;

    anyhow::ensure!(payload.version == 1, "Unsupported enrollment string version");

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_enrollment_string_roundtrip() {
        use base64::Engine as _;

        let payload = EnrollmentStringPayload {
            version: 1,
            api_base_url: "https://gateway.example.com".to_owned(),
            wireguard_endpoint: "gateway.example.com:51820".to_owned(),
            enrollment_token: "token-value".to_owned(),
        };
        let payload_json = serde_json::to_vec(&payload).expect("payload should serialize");
        let enrollment_string = format!(
            "dgw-enroll:v1:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json)
        );

        let decoded = parse_enrollment_string(&enrollment_string).expect("string should parse");

        assert_eq!(decoded.api_base_url, payload.api_base_url);
        assert_eq!(decoded.wireguard_endpoint, payload.wireguard_endpoint);
        assert_eq!(decoded.enrollment_token, payload.enrollment_token);
    }
}
