//! CA certificate management for the QUIC agent tunnel.
//!
//! Manages a self-signed CA that issues client certificates to agents during enrollment,
//! and a server certificate for the QUIC listener.

use std::time::Duration;

use anyhow::{Context as _, Result};
use camino::{Utf8Path, Utf8PathBuf};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const CA_CERT_FILENAME: &str = "agent-tunnel-ca-cert.pem";
const CA_KEY_FILENAME: &str = "agent-tunnel-ca-key.pem";
const SERVER_CERT_FILENAME: &str = "agent-tunnel-server-cert.pem";
const SERVER_KEY_FILENAME: &str = "agent-tunnel-server-key.pem";
const CA_VALIDITY_DAYS: u32 = 3650; // ~10 years
const SERVER_CERT_VALIDITY_DAYS: u32 = 365; // 1 year
const AGENT_CERT_VALIDITY_DAYS: u32 = 365; // 1 year

const CA_COMMON_NAME: &str = "Devolutions Gateway Agent Tunnel CA";
const CA_ORG_NAME: &str = "Devolutions Inc.";

/// Build the standard CA `CertificateParams` (same DN every time so that
/// reconstructed certificates match the on-disk CA for chain validation).
fn make_ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, CA_COMMON_NAME);
    params.distinguished_name.push(DnType::OrganizationName, CA_ORG_NAME);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + Duration::from_secs(u64::from(CA_VALIDITY_DAYS) * 86400);
    params
}

/// Convert DER-encoded certificate bytes to PEM format.
fn cert_der_to_pem(der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der))
}

/// Manages the CA used to sign agent client certificates and the QUIC server certificate.
pub struct CaManager {
    ca_cert_pem: String,
    ca_key_pair: KeyPair,
    data_dir: Utf8PathBuf,
}

/// Bundle returned to a newly enrolled agent.
pub struct AgentCertBundle {
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_cert_pem: String,
}

impl CaManager {
    /// Load an existing CA from disk, or generate a new one.
    pub fn load_or_generate(data_dir: &Utf8Path) -> Result<Self> {
        let cert_path = data_dir.join(CA_CERT_FILENAME);
        let key_path = data_dir.join(CA_KEY_FILENAME);

        if cert_path.exists() && key_path.exists() {
            info!(%cert_path, "Loading existing agent tunnel CA");
            let ca_cert_pem =
                std::fs::read_to_string(&cert_path).with_context(|| format!("read CA cert from {cert_path}"))?;
            let ca_key_pem =
                std::fs::read_to_string(&key_path).with_context(|| format!("read CA key from {key_path}"))?;
            let ca_key_pair = KeyPair::from_pem(&ca_key_pem).context("parse CA key pair from PEM")?;
            Ok(Self {
                ca_cert_pem,
                ca_key_pair,
                data_dir: data_dir.to_owned(),
            })
        } else {
            info!("Generating new agent tunnel CA certificate");
            let ca_key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate CA key pair")?;

            let ca_params = make_ca_params();
            let ca_cert = ca_params
                .self_signed(&ca_key_pair)
                .context("self-sign CA certificate")?;
            let ca_cert_pem = ca_cert.pem();

            std::fs::create_dir_all(data_dir).with_context(|| format!("create data directory {data_dir}"))?;
            std::fs::write(&cert_path, &ca_cert_pem).with_context(|| format!("write CA cert to {cert_path}"))?;
            std::fs::write(&key_path, ca_key_pair.serialize_pem())
                .with_context(|| format!("write CA key to {key_path}"))?;

            info!(%cert_path, "Agent tunnel CA certificate generated and saved");

            Ok(Self {
                ca_cert_pem,
                ca_key_pair,
                data_dir: data_dir.to_owned(),
            })
        }
    }

    /// Reconstruct a `Certificate` object from the stored key pair.
    ///
    /// The reconstructed cert uses the same DN as the original CA, so the
    /// issuer field in signed certificates will match the on-disk CA cert.
    fn reconstruct_ca_cert(&self) -> Result<rcgen::Certificate> {
        make_ca_params()
            .self_signed(&self.ca_key_pair)
            .context("reconstruct CA certificate for signing")
    }

    /// Issue a new client certificate for an agent.
    pub fn issue_agent_certificate(&self, agent_id: Uuid, agent_name: &str) -> Result<AgentCertBundle> {
        let agent_key_pair =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate agent key pair")?;

        let mut agent_params = CertificateParams::default();
        agent_params.distinguished_name.push(DnType::CommonName, agent_name);
        agent_params
            .distinguished_name
            .push(DnType::OrganizationName, CA_ORG_NAME);
        agent_params.subject_alt_names.push(SanType::Rfc822Name(
            format!("urn:uuid:{agent_id}").try_into().context("SAN URI")?,
        ));
        agent_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        agent_params.not_before = time::OffsetDateTime::now_utc();
        agent_params.not_after =
            time::OffsetDateTime::now_utc() + Duration::from_secs(u64::from(AGENT_CERT_VALIDITY_DAYS) * 86400);

        let ca_cert = self.reconstruct_ca_cert()?;

        let agent_cert = agent_params
            .signed_by(&agent_key_pair, &ca_cert, &self.ca_key_pair)
            .context("sign agent certificate with CA")?;

        info!(%agent_id, %agent_name, "Issued agent client certificate");

        Ok(AgentCertBundle {
            client_cert_pem: agent_cert.pem(),
            client_key_pem: agent_key_pair.serialize_pem(),
            ca_cert_pem: self.ca_cert_pem.clone(),
        })
    }

    /// Ensure a server certificate exists for the QUIC listener (signed by our CA).
    ///
    /// Returns `(cert_path, key_path)` on disk.
    pub fn ensure_server_cert(&self, hostname: &str) -> Result<(Utf8PathBuf, Utf8PathBuf)> {
        let cert_path = self.data_dir.join(SERVER_CERT_FILENAME);
        let key_path = self.data_dir.join(SERVER_KEY_FILENAME);

        if cert_path.exists() && key_path.exists() {
            info!(%cert_path, "Using existing agent tunnel server certificate");
            return Ok((cert_path, key_path));
        }

        info!(%hostname, "Generating agent tunnel server certificate");

        let server_key_pair =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate server key pair")?;

        let mut server_params = CertificateParams::default();
        server_params.distinguished_name.push(DnType::CommonName, hostname);
        server_params
            .distinguished_name
            .push(DnType::OrganizationName, CA_ORG_NAME);
        server_params
            .subject_alt_names
            .push(SanType::DnsName(hostname.try_into().context("DNS SAN")?));
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        server_params.not_before = time::OffsetDateTime::now_utc();
        server_params.not_after =
            time::OffsetDateTime::now_utc() + Duration::from_secs(u64::from(SERVER_CERT_VALIDITY_DAYS) * 86400);

        let ca_cert = self.reconstruct_ca_cert()?;

        let server_cert = server_params
            .signed_by(&server_key_pair, &ca_cert, &self.ca_key_pair)
            .context("sign server certificate with CA")?;

        std::fs::write(&cert_path, server_cert.pem()).with_context(|| format!("write server cert to {cert_path}"))?;
        std::fs::write(&key_path, server_key_pair.serialize_pem())
            .with_context(|| format!("write server key to {key_path}"))?;

        info!(%cert_path, %hostname, "Server certificate generated and saved");

        Ok((cert_path, key_path))
    }

    /// Get the CA certificate in PEM format.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get the CA certificate file path on disk.
    pub fn ca_cert_path(&self) -> Utf8PathBuf {
        self.data_dir.join(CA_CERT_FILENAME)
    }
}

/// Compute SHA-256 fingerprint of a PEM-encoded certificate (hex string).
pub fn cert_fingerprint_from_pem(pem_str: &str) -> Result<String> {
    let pem = pem::parse(pem_str).context("parse PEM for fingerprint")?;
    let digest = Sha256::digest(pem.contents());
    Ok(hex::encode(digest))
}

/// Compute SHA-256 fingerprint of a DER-encoded certificate (hex string).
pub fn cert_fingerprint_from_der(der_bytes: &[u8]) -> String {
    let digest = Sha256::digest(der_bytes);
    hex::encode(digest)
}

/// Extract agent_id from a PEM-encoded certificate's SAN (urn:uuid:{id}).
pub fn extract_agent_id_from_pem(pem_str: &str) -> Result<Uuid> {
    let pem = pem::parse(pem_str).context("parse PEM for agent ID extraction")?;
    extract_agent_id_from_der(pem.contents())
}

/// Extract agent_id from a DER-encoded certificate's SAN (urn:uuid:{id}).
pub fn extract_agent_id_from_der(der_bytes: &[u8]) -> Result<Uuid> {
    let (_, cert) = x509_parser::parse_x509_certificate(der_bytes).context("parse X.509 certificate")?;

    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::RFC822Name(val) = name {
                    if let Some(uuid_str) = val.strip_prefix("urn:uuid:") {
                        return uuid_str.parse().context("parse UUID from SAN");
                    }
                }
            }
        }
    }

    anyhow::bail!("no urn:uuid: SAN found in certificate")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_and_issue_agent_cert() {
        let temp_dir = std::env::temp_dir().join(format!("dgw-cert-test-{}", Uuid::new_v4()));
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("temp path should be UTF-8");

        let ca = CaManager::load_or_generate(&data_dir).expect("CA generation should succeed");
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));

        let agent_id = Uuid::new_v4();
        let bundle = ca
            .issue_agent_certificate(agent_id, "test-agent")
            .expect("agent cert issue should succeed");

        assert!(bundle.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.client_key_pem.contains("BEGIN PRIVATE KEY"));
        assert_eq!(bundle.ca_cert_pem, ca.ca_cert_pem());

        // Reload CA from disk.
        let ca2 = CaManager::load_or_generate(&data_dir).expect("CA reload should succeed");
        assert_eq!(ca2.ca_cert_pem(), ca.ca_cert_pem());

        // Issue a cert from the reloaded CA and verify it works.
        let bundle2 = ca2
            .issue_agent_certificate(Uuid::new_v4(), "test-agent-2")
            .expect("agent cert from reloaded CA should succeed");
        assert!(bundle2.client_cert_pem.contains("BEGIN CERTIFICATE"));

        // Fingerprint.
        let fp = cert_fingerprint_from_pem(&bundle.client_cert_pem).expect("fingerprint should work");
        assert_eq!(fp.len(), 64); // SHA-256 hex = 64 chars

        // Extract agent_id from PEM.
        let extracted_id = extract_agent_id_from_pem(&bundle.client_cert_pem).expect("agent ID extraction should work");
        assert_eq!(extracted_id, agent_id);

        // Server certificate.
        let (server_cert_path, server_key_path) = ca
            .ensure_server_cert("test-gateway.local")
            .expect("server cert should succeed");
        assert!(server_cert_path.exists());
        assert!(server_key_path.exists());

        // Cleanup.
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
