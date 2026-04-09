//! CA certificate management for the QUIC agent tunnel.
//!
//! Manages a self-signed CA that issues client certificates to agents during enrollment,
//! and a server certificate for the QUIC listener.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
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

/// Manages the CA used to sign agent client certificates and the QUIC server certificate.
pub struct CaManager {
    ca_cert_pem: String,
    ca_key_pair: KeyPair,
    data_dir: Utf8PathBuf,
}

/// Bundle returned to a newly enrolled agent (private key never leaves the agent).
pub struct SignedAgentCert {
    pub client_cert_pem: String,
    pub ca_cert_pem: String,
}

impl CaManager {
    /// Load an existing CA from disk, or generate a new one.
    pub fn load_or_generate(data_dir: &Utf8Path) -> anyhow::Result<Arc<Self>> {
        let cert_path = data_dir.join(CA_CERT_FILENAME);
        let key_path = data_dir.join(CA_KEY_FILENAME);

        if cert_path.exists() && key_path.exists() {
            // --- Load existing CA ---

            info!(%cert_path, "Loading existing agent tunnel CA");

            let ca_cert_pem =
                std::fs::read_to_string(&cert_path).with_context(|| format!("read CA cert from {cert_path}"))?;
            let ca_key_pem =
                std::fs::read_to_string(&key_path).with_context(|| format!("read CA key from {key_path}"))?;
            let ca_key_pair = KeyPair::from_pem(&ca_key_pem).context("parse CA key pair from PEM")?;

            Ok(Arc::new(Self {
                ca_cert_pem,
                ca_key_pair,
                data_dir: data_dir.to_owned(),
            }))
        } else {
            // --- Generate new CA ---

            info!("Generating new agent tunnel CA certificate");

            let ca_key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate CA key pair")?;
            let ca_params = make_ca_params();
            let ca_cert = ca_params
                .self_signed(&ca_key_pair)
                .context("self-sign CA certificate")?;
            let ca_cert_pem = ca_cert.pem();

            // Persist to disk.
            std::fs::create_dir_all(data_dir).with_context(|| format!("create data directory {data_dir}"))?;
            std::fs::write(&cert_path, &ca_cert_pem).with_context(|| format!("write CA cert to {cert_path}"))?;
            std::fs::write(&key_path, ca_key_pair.serialize_pem())
                .with_context(|| format!("write CA key to {key_path}"))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("set permissions on {key_path}"))?;
            }

            // TODO: On Windows, set explicit DACL on the CA key file.
            // Currently relying on ProgramData directory ACL (SYSTEM + Admins only).

            info!(%cert_path, "Agent tunnel CA certificate generated and saved");

            Ok(Arc::new(Self {
                ca_cert_pem,
                ca_key_pair,
                data_dir: data_dir.to_owned(),
            }))
        }
    }

    /// Reconstruct a `Certificate` object from the stored key pair.
    ///
    /// The reconstructed cert uses the same DN as the original CA, so the
    /// issuer field in signed certificates will match the on-disk CA cert.
    fn reconstruct_ca_cert(&self) -> anyhow::Result<rcgen::Certificate> {
        make_ca_params()
            .self_signed(&self.ca_key_pair)
            .context("reconstruct CA certificate for signing")
    }

    /// Sign an agent's CSR, producing a client certificate.
    ///
    /// The agent generates its own key pair and sends only the CSR.
    /// The private key never leaves the agent.
    pub fn sign_agent_csr(
        &self,
        agent_id: Uuid,
        agent_name: &str,
        csr_pem: &str,
        agent_hostname: Option<&str>,
    ) -> anyhow::Result<SignedAgentCert> {
        // Parse and verify the CSR (signature check included).
        let csr_params = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| anyhow::anyhow!("invalid CSR: {e}"))?;

        // Build our own cert params (we control CN, SAN, EKU, validity — not the CSR).
        let mut agent_params = CertificateParams::default();
        agent_params.distinguished_name.push(DnType::CommonName, agent_name);
        agent_params
            .distinguished_name
            .push(DnType::OrganizationName, CA_ORG_NAME);
        agent_params.subject_alt_names.push(SanType::Rfc822Name(
            format!("urn:uuid:{agent_id}").try_into().context("SAN URI")?,
        ));
        if let Some(hostname) = agent_hostname {
            agent_params
                .subject_alt_names
                .push(SanType::DnsName(hostname.try_into().context("agent hostname DNS SAN")?));
        }
        agent_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        agent_params.not_before = time::OffsetDateTime::now_utc();
        agent_params.not_after =
            time::OffsetDateTime::now_utc() + Duration::from_secs(u64::from(AGENT_CERT_VALIDITY_DAYS) * 86400);

        // Sign with the CA, embedding the public key from the CSR.
        let ca_cert = self.reconstruct_ca_cert()?;
        let agent_cert = agent_params
            .signed_by(&csr_params.public_key, &ca_cert, &self.ca_key_pair)
            .context("sign agent certificate with CA")?;

        info!(%agent_id, %agent_name, "Signed agent CSR and issued client certificate");

        Ok(SignedAgentCert {
            client_cert_pem: agent_cert.pem(),
            ca_cert_pem: self.ca_cert_pem.clone(),
        })
    }

    /// Ensure a server certificate exists for the QUIC listener (signed by our CA).
    ///
    /// Returns `(cert_path, key_path)` on disk.
    pub fn ensure_server_cert(&self, hostname: &str) -> anyhow::Result<(Utf8PathBuf, Utf8PathBuf)> {
        let cert_path = self.data_dir.join(SERVER_CERT_FILENAME);
        let key_path = self.data_dir.join(SERVER_KEY_FILENAME);

        if cert_path.exists() && key_path.exists() {
            // TODO: check cert expiry and regenerate if near/past expiration (365-day validity).
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

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("set permissions on {key_path}"))?;
        }

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

    /// Build a `rustls::ServerConfig` for the QUIC listener with mTLS client verification.
    ///
    /// The server certificate is signed by our CA; clients must present a certificate
    /// also signed by our CA (mutual TLS).
    pub fn build_server_tls_config(&self, hostname: &str) -> anyhow::Result<rustls::ServerConfig> {
        use std::io::BufReader;

        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        // Ensure rustls crypto provider is installed (ring).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_cert_path, server_key_path) = self.ensure_server_cert(hostname)?;

        // Load server certificate.
        let server_cert_file = std::fs::File::open(server_cert_path.as_std_path())
            .with_context(|| format!("open server cert file {server_cert_path}"))?;

        let mut server_cert_chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut BufReader::new(server_cert_file))
                .collect::<Result<Vec<_>, _>>()
                .context("parse server certificate PEM")?;

        // Load CA certificate.
        let ca_cert_path = self.ca_cert_path();

        let ca_cert_file = std::fs::File::open(ca_cert_path.as_std_path())
            .with_context(|| format!("open CA cert file {ca_cert_path}"))?;

        let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(ca_cert_file))
            .collect::<Result<Vec<_>, _>>()
            .context("parse CA certificate PEM")?;

        // Build cert chain: [server_cert, ca_cert].
        server_cert_chain.extend(ca_certs.clone());

        // Load server private key.
        let server_key_file = std::fs::File::open(server_key_path.as_std_path())
            .with_context(|| format!("open server key file {server_key_path}"))?;

        let server_private_key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut BufReader::new(server_key_file))
                .context("parse server private key PEM")?
                .context("no private key found in PEM file")?;

        // Build root cert store with our CA for client (agent) verification.
        let ca_roots =
            ca_certs
                .into_iter()
                .try_fold(rustls::RootCertStore::empty(), |mut roots, cert| -> anyhow::Result<_> {
                    roots.add(cert).context("add CA cert to root store")?;
                    Ok(roots)
                })?;

        // Require client certificates signed by our CA.
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(ca_roots.into())
            .build()
            .context("build client certificate verifier")?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_cert_chain, server_private_key)
            .context("build rustls ServerConfig")?;

        tls_config.alpn_protocols = vec![b"devolutions-agent-tunnel".to_vec()];

        Ok(tls_config)
    }

    /// Compute the SPKI SHA-256 hash of the server certificate.
    ///
    /// Loads the cert from disk. Only called during enrollment (infrequent).
    pub fn server_spki_sha256(&self, hostname: &str) -> anyhow::Result<String> {
        let (server_cert_path, _) = self.ensure_server_cert(hostname)?;
        let pem_str = std::fs::read_to_string(&server_cert_path)
            .with_context(|| format!("read server cert from {server_cert_path}"))?;
        let parsed = pem::parse(&pem_str).context("parse server cert PEM")?;
        spki_sha256_from_der(parsed.contents())
    }
}

/// SHA-256 hash of a DER certificate's Subject Public Key Info (hex string).
pub fn spki_sha256_from_der(der_bytes: &[u8]) -> anyhow::Result<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der_bytes)
        .map_err(|e| anyhow::anyhow!("parse certificate for SPKI: {e}"))?;
    let digest = Sha256::digest(cert.public_key().raw);
    Ok(hex::encode(digest))
}

/// Compute SHA-256 fingerprint of a PEM-encoded certificate (hex string).
pub fn cert_fingerprint_from_pem(pem_str: &str) -> anyhow::Result<String> {
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
pub fn extract_agent_id_from_pem(pem_str: &str) -> anyhow::Result<Uuid> {
    let pem = pem::parse(pem_str).context("parse PEM for agent ID extraction")?;
    extract_agent_id_from_der(pem.contents())
}

/// Extract the Common Name (CN) from a DER-encoded certificate.
pub fn extract_agent_name_from_der(cert_der: &[u8]) -> anyhow::Result<String> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert_der).map_err(|e| anyhow::anyhow!("parse certificate: {e}"))?;

    for attr in cert.subject().iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            return Ok(cn.to_owned());
        }
    }

    anyhow::bail!("no Common Name found in certificate")
}

/// Extract agent_id from a DER-encoded certificate's SAN (urn:uuid:{id}).
pub fn extract_agent_id_from_der(der_bytes: &[u8]) -> anyhow::Result<Uuid> {
    let (_, cert) = x509_parser::parse_x509_certificate(der_bytes).context("parse X.509 certificate")?;

    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::RFC822Name(val) = name
                    && let Some(uuid_str) = val.strip_prefix("urn:uuid:")
                {
                    return uuid_str.parse().context("parse UUID from SAN");
                }
            }
        }
    }

    anyhow::bail!("no urn:uuid: SAN found in certificate")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate a CSR PEM for testing.
    fn generate_test_csr(cn: &str) -> (KeyPair, String) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key pair");
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        let csr = params.serialize_request(&key_pair).expect("serialize CSR");
        (key_pair, csr.pem().expect("CSR to PEM"))
    }

    #[test]
    fn generate_ca_and_sign_agent_csr() {
        let temp_dir = std::env::temp_dir().join(format!("dgw-cert-test-{}", Uuid::new_v4()));
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("temp path should be UTF-8");

        let ca = CaManager::load_or_generate(&data_dir).expect("CA generation should succeed");
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));

        let agent_id = Uuid::new_v4();
        let (_key_pair, csr_pem) = generate_test_csr("test-agent");
        let signed = ca
            .sign_agent_csr(agent_id, "test-agent", &csr_pem, Some("test-agent.local"))
            .expect("sign CSR should succeed");

        assert!(signed.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(signed.ca_cert_pem, ca.ca_cert_pem());

        // Reload CA from disk.
        let ca2 = CaManager::load_or_generate(&data_dir).expect("CA reload should succeed");
        assert_eq!(ca2.ca_cert_pem(), ca.ca_cert_pem());

        // Sign a CSR from the reloaded CA and verify it works.
        let (_key_pair2, csr_pem2) = generate_test_csr("test-agent-2");
        let signed2 = ca2
            .sign_agent_csr(Uuid::new_v4(), "test-agent-2", &csr_pem2, None)
            .expect("sign CSR from reloaded CA should succeed");
        assert!(signed2.client_cert_pem.contains("BEGIN CERTIFICATE"));

        // Fingerprint.
        let fp = cert_fingerprint_from_pem(&signed.client_cert_pem).expect("fingerprint should work");
        assert_eq!(fp.len(), 64); // SHA-256 hex = 64 chars

        // Extract agent_id from PEM.
        let extracted_id = extract_agent_id_from_pem(&signed.client_cert_pem).expect("agent ID extraction should work");
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

    #[test]
    fn sign_csr_produces_valid_cert() {
        let temp_dir = std::env::temp_dir().join(format!("dgw-cert-test-{}", Uuid::new_v4()));
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("temp path should be UTF-8");
        let ca = CaManager::load_or_generate(&data_dir).expect("CA generation should succeed");

        let agent_id = Uuid::new_v4();
        let (_key_pair, csr_pem) = generate_test_csr("csr-test-agent");

        let signed = ca
            .sign_agent_csr(agent_id, "csr-test-agent", &csr_pem, Some("csr-test.local"))
            .expect("sign CSR should succeed");

        assert!(signed.client_cert_pem.contains("BEGIN CERTIFICATE"));

        // Verify the cert contains the agent UUID in SAN.
        let extracted_id =
            extract_agent_id_from_pem(&signed.client_cert_pem).expect("should extract agent ID from signed cert");
        assert_eq!(extracted_id, agent_id);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn sign_csr_rejects_tampered_csr() {
        let temp_dir = std::env::temp_dir().join(format!("dgw-cert-test-{}", Uuid::new_v4()));
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("temp path should be UTF-8");
        let ca = CaManager::load_or_generate(&data_dir).expect("CA generation should succeed");

        let (_key_pair, csr_pem) = generate_test_csr("tampered-agent");

        // Decode PEM, flip a byte in the DER, re-encode.
        let parsed = pem::parse(&csr_pem).expect("parse CSR PEM");
        let mut der_bytes = parsed.contents().to_vec();
        // Flip a byte near the end (in the signature area).
        let len = der_bytes.len();
        der_bytes[len - 2] ^= 0xFF;
        let tampered_pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", der_bytes));

        let result = ca.sign_agent_csr(Uuid::new_v4(), "tampered-agent", &tampered_pem, None);
        assert!(result.is_err(), "tampered CSR should be rejected");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
