//! CA certificate management for the QUIC agent tunnel.
//!
//! Manages a self-signed CA that issues client certificates to agents during enrollment,
//! and a server certificate for the QUIC listener.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use camino::{Utf8Path, Utf8PathBuf};
use picky::pem::{PemError, parse_pem, read_pem};
use picky::x509::Cert;
use picky_asn1_x509::{ExtensionView, GeneralName};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PEM_LABEL_CERTIFICATE: &str = "CERTIFICATE";
const PEM_LABEL_PRIVATE_KEY_PKCS8: &str = "PRIVATE KEY";
const PEM_LABEL_PRIVATE_KEY_PKCS1: &str = "RSA PRIVATE KEY";
const PEM_LABEL_PRIVATE_KEY_SEC1: &str = "EC PRIVATE KEY";

/// Extract DER bytes from a PEM-encoded certificate string, checking the label.
fn cert_pem_to_der(pem_str: &str) -> anyhow::Result<Vec<u8>> {
    let pem = parse_pem(pem_str).context("parse certificate PEM")?;
    if pem.label() != PEM_LABEL_CERTIFICATE {
        bail!("expected {PEM_LABEL_CERTIFICATE} PEM, got {}", pem.label());
    }
    Ok(pem.data().to_vec())
}

/// Parse one or more PEM-encoded certificates into `rustls` certificate types.
///
/// A PEM file can carry multiple concatenated CERTIFICATE blocks (chain). We
/// use [`read_pem`] in a loop — each call consumes one block; `HeaderNotFound`
/// signals "no more blocks left", which is the termination condition. Each
/// block's label is verified, then the DER bytes are wrapped in
/// [`rustls_pki_types::CertificateDer`] — the type the rustls/quinn TLS
/// builders accept.
fn read_cert_chain(pem_str: &str) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use std::io::BufReader;

    let mut reader = BufReader::new(pem_str.as_bytes());
    let mut chain = Vec::new();

    loop {
        match read_pem(&mut reader) {
            Ok(pem) => {
                if pem.label() != PEM_LABEL_CERTIFICATE {
                    bail!(
                        "expected {PEM_LABEL_CERTIFICATE} PEM at index {}, got {}",
                        chain.len(),
                        pem.label()
                    );
                }
                // `into_data().into_owned()` consumes the `Pem` and avoids the
                // copy that `pem.data().to_vec()` would force.
                chain.push(rustls::pki_types::CertificateDer::from(pem.into_data().into_owned()));
            }
            Err(PemError::HeaderNotFound) => break,
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!("parse PEM block at index {}", chain.len())));
            }
        }
    }

    if chain.is_empty() {
        bail!("no {PEM_LABEL_CERTIFICATE} blocks found in PEM input");
    }
    Ok(chain)
}

/// Parse a PEM-encoded private key into `rustls`'s tagged [`PrivateKeyDer`].
///
/// Supports PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`) and SEC1
/// (`EC PRIVATE KEY`) — same label set as `rustls_pemfile::private_key`.
/// rcgen produces PKCS#8 by default; we accept the others for flexibility.
fn read_private_key(pem_str: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    let pem = parse_pem(pem_str).context("parse private key PEM")?;
    let data = pem.data().to_vec();
    match pem.label() {
        PEM_LABEL_PRIVATE_KEY_PKCS8 => Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(data))),
        PEM_LABEL_PRIVATE_KEY_PKCS1 => Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(data))),
        PEM_LABEL_PRIVATE_KEY_SEC1 => Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(data))),
        other => bail!("unexpected PEM label for private key: {other}"),
    }
}

const CA_CERT_FILENAME: &str = "agent-tunnel-ca-cert.pem";
const CA_KEY_FILENAME: &str = "agent-tunnel-ca-key.pem";
const SERVER_CERT_FILENAME: &str = "agent-tunnel-server-cert.pem";
const SERVER_KEY_FILENAME: &str = "agent-tunnel-server-key.pem";
const CA_VALIDITY_DAYS: u32 = 3650; // ~10 years
const SERVER_CERT_VALIDITY_DAYS: u32 = 365; // 1 year
const AGENT_CERT_VALIDITY_DAYS: u32 = 365; // 1 year

const SECS_PER_DAY: u64 = 86_400;
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
    params.not_after =
        time::OffsetDateTime::now_utc() + Duration::from_secs(u64::from(CA_VALIDITY_DAYS) * SECS_PER_DAY);
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
        agent_params.subject_alt_names.push(SanType::URI(
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
            time::OffsetDateTime::now_utc() + Duration::from_secs(u64::from(AGENT_CERT_VALIDITY_DAYS) * SECS_PER_DAY);

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
    /// `advertised_names` is the authoritative list of names/IPs the agent tunnel
    /// is reachable as. Each entry is added to the cert SAN — DNS literals are
    /// inserted as `SanType::DnsName`, IP literals (parseable by [`std::net::IpAddr`])
    /// as `SanType::IpAddress`. When the on-disk cert's SAN set differs from the
    /// expected SAN set, the cert is regenerated reusing the existing keypair so
    /// the SPKI pin captured at enrollment stays stable.
    ///
    /// Returns `(cert_path, key_path)` on disk.
    pub fn ensure_server_cert(&self, advertised_names: &[&str]) -> anyhow::Result<(Utf8PathBuf, Utf8PathBuf)> {
        let cert_path = self.data_dir.join(SERVER_CERT_FILENAME);
        let key_path = self.data_dir.join(SERVER_KEY_FILENAME);

        if advertised_names.is_empty() {
            anyhow::bail!("at least one advertised name is required to generate the agent tunnel server certificate");
        }

        // Compute the expected SAN set (canonical, deduped).
        let expected_sans = build_san_set(advertised_names)?;

        let status = check_server_cert(&cert_path, &key_path, &expected_sans);

        // Pick the primary name for cert CN / log messages: the first advertised
        // name. Stable across regenerations so log lines remain greppable.
        let primary_name = advertised_names[0];

        // The keypair is preserved across SAN regenerations to keep the SPKI pin
        // stable for already-enrolled agents. Only the cert document changes.
        // Generate a fresh key only if the existing key is missing/unreadable.
        let server_key_pair = match (status, std::fs::read_to_string(&key_path)) {
            (ServerCertStatus::Valid, _) => {
                info!(%cert_path, ?expected_sans, "Using existing agent tunnel server certificate");
                return Ok((cert_path, key_path));
            }
            (ServerCertStatus::SanMismatch { on_disk_sans }, Ok(key_pem)) => {
                info!(
                    %cert_path,
                    ?on_disk_sans,
                    new_sans = ?expected_sans,
                    "Agent tunnel server cert SAN set changed; regenerating with the existing keypair",
                );
                KeyPair::from_pem(&key_pem).context("parse existing server key pair from PEM")?
            }
            (other_status, _) => {
                info!(%cert_path, ?other_status, "Generating new server certificate keypair");
                KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate server key pair")?
            }
        };

        let mut server_params = CertificateParams::default();
        server_params.distinguished_name.push(DnType::CommonName, primary_name);
        server_params
            .distinguished_name
            .push(DnType::OrganizationName, CA_ORG_NAME);
        for san in &expected_sans {
            server_params.subject_alt_names.push(san_entry(san)?);
        }
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        server_params.not_before = time::OffsetDateTime::now_utc();
        server_params.not_after =
            time::OffsetDateTime::now_utc() + Duration::from_secs(u64::from(SERVER_CERT_VALIDITY_DAYS) * SECS_PER_DAY);

        let ca_cert = self.reconstruct_ca_cert()?;

        let server_cert = server_params
            .signed_by(&server_key_pair, &ca_cert, &self.ca_key_pair)
            .context("sign server certificate with CA")?;

        let server_cert_pem = server_cert.pem();
        let fingerprint = cert_fingerprint_from_pem(&server_cert_pem).unwrap_or_else(|_| "<unknown>".to_owned());

        std::fs::write(&cert_path, &server_cert_pem).with_context(|| format!("write server cert to {cert_path}"))?;
        // Only write the key when generating a new one. Reusing the existing key
        // means we already validated the file is readable above.
        if !key_path.exists() {
            std::fs::write(&key_path, server_key_pair.serialize_pem())
                .with_context(|| format!("write server key to {key_path}"))?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("set permissions on {key_path}"))?;
        }

        info!(
            %cert_path,
            primary_name,
            sans = ?expected_sans,
            %fingerprint,
            "Agent tunnel server certificate generated and saved",
        );

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
    pub fn build_server_tls_config(&self, advertised_names: &[&str]) -> anyhow::Result<rustls::ServerConfig> {
        use rustls::pki_types::PrivateKeyDer;

        // Ensure rustls crypto provider is installed (ring).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_cert_path, server_key_path) = self.ensure_server_cert(advertised_names)?;

        // Load server certificate.
        let server_cert_pem =
            std::fs::read_to_string(&server_cert_path).with_context(|| format!("read {server_cert_path}"))?;
        let mut server_cert_chain = read_cert_chain(&server_cert_pem).context("parse server certificate PEM")?;

        // Load CA certificate.
        let ca_cert_path = self.ca_cert_path();
        let ca_cert_pem = std::fs::read_to_string(&ca_cert_path).with_context(|| format!("read {ca_cert_path}"))?;
        let ca_certs = read_cert_chain(&ca_cert_pem).context("parse CA certificate PEM")?;

        // Build cert chain: [server_cert, ca_cert].
        server_cert_chain.extend(ca_certs.clone());

        // Load server private key.
        let server_key_pem =
            std::fs::read_to_string(&server_key_path).with_context(|| format!("read {server_key_path}"))?;
        let server_private_key: PrivateKeyDer<'static> =
            read_private_key(&server_key_pem).context("parse server private key PEM")?;

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

        tls_config.alpn_protocols = vec![agent_tunnel_proto::ALPN_PROTOCOL.to_vec()];

        Ok(tls_config)
    }

    /// Compute the SPKI SHA-256 hash of the server certificate.
    ///
    /// Loads the cert from disk. Only called during enrollment (infrequent).
    pub fn server_spki_sha256(&self, advertised_names: &[&str]) -> anyhow::Result<String> {
        let (server_cert_path, _) = self.ensure_server_cert(advertised_names)?;
        let pem_str = std::fs::read_to_string(&server_cert_path)
            .with_context(|| format!("read server cert from {server_cert_path}"))?;
        let der = cert_pem_to_der(&pem_str).context("parse server cert PEM")?;
        spki_sha256_from_der(&der)
    }
}

/// Canonical SAN identifier kept inside the manager.
///
/// `Dns` names are lower-cased; `Ip` values are normalized via [`std::net::IpAddr`]
/// so `10.10.0.7` and `10.10.000.7` collapse to the same identifier and IPv6
/// literals compare in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum SanIdent {
    Dns(String),
    Ip(std::net::IpAddr),
}

impl std::fmt::Display for SanIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SanIdent::Dns(name) => f.write_str(name),
            SanIdent::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Build a deduped, canonical SAN set from the raw advertised names.
///
/// Strings that parse as `IpAddr` become `SanIdent::Ip` (with canonical formatting);
/// everything else becomes `SanIdent::Dns` lower-cased.
pub(crate) fn build_san_set(advertised_names: &[&str]) -> anyhow::Result<Vec<SanIdent>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for raw in advertised_names {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("advertised name cannot be empty");
        }
        let ident = if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
            SanIdent::Ip(ip)
        } else {
            SanIdent::Dns(trimmed.to_ascii_lowercase())
        };
        if seen.insert(ident.clone()) {
            out.push(ident);
        }
    }
    Ok(out)
}

/// Build the rcgen `SanType` for a canonical SAN identifier.
fn san_entry(san: &SanIdent) -> anyhow::Result<SanType> {
    match san {
        SanIdent::Dns(name) => Ok(SanType::DnsName(name.clone().try_into().context("DNS SAN")?)),
        SanIdent::Ip(ip) => Ok(SanType::IpAddress(*ip)),
    }
}

/// Extract the SAN set from a parsed certificate as a canonical `Vec<SanIdent>`.
fn extract_san_set(cert: &Cert) -> Vec<SanIdent> {
    let mut sans = Vec::new();
    for ext in cert.extensions() {
        if let ExtensionView::SubjectAltName(names) = ext.extn_value() {
            for name in &names.0 {
                match name {
                    GeneralName::DnsName(dns) => sans.push(SanIdent::Dns(dns.as_utf8().to_ascii_lowercase())),
                    GeneralName::IpAddress(bytes) => {
                        // X.509 IP SAN encodes IPv4 as 4 bytes, IPv6 as 16 bytes.
                        if let Some(ip) = ip_from_san_bytes(bytes) {
                            sans.push(SanIdent::Ip(ip));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    sans
}

fn ip_from_san_bytes(bytes: &[u8]) -> Option<std::net::IpAddr> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// SHA-256 hash of a DER certificate's Subject Public Key Info (hex string).
pub fn spki_sha256_from_der(der_bytes: &[u8]) -> anyhow::Result<String> {
    let cert = Cert::from_der(der_bytes).context("parse certificate for SPKI")?;
    let spki_der = cert.public_key().to_der().context("encode SPKI for hashing")?;
    let digest = Sha256::digest(&spki_der);
    Ok(hex::encode(digest))
}

/// Compute SHA-256 fingerprint of a PEM-encoded certificate (hex string).
pub fn cert_fingerprint_from_pem(pem_str: &str) -> anyhow::Result<String> {
    let der = cert_pem_to_der(pem_str).context("parse PEM for fingerprint")?;
    let digest = Sha256::digest(&der);
    Ok(hex::encode(digest))
}

/// Compute SHA-256 fingerprint of a DER-encoded certificate (hex string).
pub fn cert_fingerprint_from_der(der_bytes: &[u8]) -> String {
    let digest = Sha256::digest(der_bytes);
    hex::encode(digest)
}

/// Extract agent_id from a PEM-encoded certificate's SAN (urn:uuid:{id}).
pub fn extract_agent_id_from_pem(pem_str: &str) -> anyhow::Result<Uuid> {
    let der = cert_pem_to_der(pem_str).context("parse PEM for agent ID extraction")?;
    extract_agent_id_from_der(&der)
}

/// Extract the Common Name (CN) from a DER-encoded certificate.
pub fn extract_agent_name_from_der(cert_der: &[u8]) -> anyhow::Result<String> {
    let cert = Cert::from_der(cert_der).context("parse certificate")?;
    let subject = cert.subject_name();
    let cn = subject
        .find_common_name()
        .context("no Common Name found in certificate")?;
    Ok(cn.to_string())
}

/// Extract agent_id from a DER-encoded certificate's SAN (urn:uuid:{id}).
pub fn extract_agent_id_from_der(der_bytes: &[u8]) -> anyhow::Result<Uuid> {
    let cert = Cert::from_der(der_bytes).context("parse X.509 certificate")?;

    for ext in cert.extensions() {
        if let ExtensionView::SubjectAltName(names) = ext.extn_value() {
            for name in &names.0 {
                if let GeneralName::Uri(uri) = name
                    && let Some(uuid_str) = uri.as_utf8().strip_prefix("urn:uuid:")
                {
                    return uuid_str.parse().context("parse UUID from SAN");
                }
            }
        }
    }

    bail!("no urn:uuid: SAN found in certificate")
}

// ---------------------------------------------------------------------------
// Server certificate validation
// ---------------------------------------------------------------------------

/// Why an existing server certificate cannot be reused.
#[derive(Debug, Clone)]
enum ServerCertStatus {
    /// Certificate is valid and the SAN set matches the configured advertised names.
    Valid,
    /// Certificate or key file does not exist yet.
    NotFound,
    /// Certificate expires within 7 days.
    ExpiringSoon,
    /// Certificate's SAN set does not match the configured advertised names.
    /// The existing keypair can be reused; only the cert document is regenerated.
    SanMismatch { on_disk_sans: Vec<SanIdent> },
    /// Certificate file is corrupt or unparseable.
    Unreadable,
}

fn check_server_cert(cert_path: &Utf8Path, key_path: &Utf8Path, expected_sans: &[SanIdent]) -> ServerCertStatus {
    if !cert_path.exists() || !key_path.exists() {
        return ServerCertStatus::NotFound;
    }

    let Ok(pem_str) = std::fs::read_to_string(cert_path) else {
        return ServerCertStatus::Unreadable;
    };
    let Ok(der) = cert_pem_to_der(&pem_str) else {
        return ServerCertStatus::Unreadable;
    };
    let Ok(cert) = Cert::from_der(&der) else {
        return ServerCertStatus::Unreadable;
    };

    // Expiry: reject if < 7 days remaining.
    let Ok(not_after) = time::OffsetDateTime::try_from(cert.valid_not_after()) else {
        return ServerCertStatus::Unreadable;
    };
    let threshold = time::OffsetDateTime::now_utc() + Duration::from_secs(7 * SECS_PER_DAY);
    if not_after <= threshold {
        return ServerCertStatus::ExpiringSoon;
    }

    // SAN set match: order-insensitive, canonical comparison.
    let mut on_disk_sans = extract_san_set(&cert);
    let mut on_disk_sorted = on_disk_sans.clone();
    on_disk_sorted.sort();
    let mut expected_sorted = expected_sans.to_vec();
    expected_sorted.sort();
    if on_disk_sorted != expected_sorted {
        on_disk_sans.sort();
        return ServerCertStatus::SanMismatch { on_disk_sans };
    }

    ServerCertStatus::Valid
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

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
            .ensure_server_cert(&["test-gateway.local"])
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
        let csr_b64: String = csr_pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let mut der_bytes = base64::engine::general_purpose::STANDARD
            .decode(&csr_b64)
            .expect("decode CSR base64");
        // Flip a byte near the end (in the signature area).
        let len = der_bytes.len();
        der_bytes[len - 2] ^= 0xFF;
        let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(&der_bytes);
        let tampered_pem =
            format!("-----BEGIN CERTIFICATE REQUEST-----\n{tampered_b64}\n-----END CERTIFICATE REQUEST-----\n");

        let result = ca.sign_agent_csr(Uuid::new_v4(), "tampered-agent", &tampered_pem, None);
        assert!(result.is_err(), "tampered CSR should be rejected");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // ---------------------------------------------------------------------
    // read_cert_chain — regression coverage for PEM whitespace / multi-block
    // ---------------------------------------------------------------------

    /// Mint a real CA + signed end-entity cert and return (ca_pem, leaf_pem).
    /// Uses `CaManager::load_or_generate` so we don't reimplement PEM emission
    /// in the test — whatever rcgen produces here is what the runtime sees.
    fn make_cert_pair() -> (String, String) {
        let temp_dir = std::env::temp_dir().join(format!("dgw-cert-chain-test-{}", Uuid::new_v4()));
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("temp path UTF-8");
        let ca = CaManager::load_or_generate(&data_dir).expect("CA generation");
        let (_key_pair, csr_pem) = generate_test_csr("chain-test-agent");
        let signed = ca
            .sign_agent_csr(Uuid::new_v4(), "chain-test-agent", &csr_pem, None)
            .expect("sign CSR");
        let ca_pem = ca.ca_cert_pem().to_owned();
        let _ = std::fs::remove_dir_all(&temp_dir);
        (ca_pem, signed.client_cert_pem)
    }

    #[test]
    fn read_cert_chain_single_block() {
        let (ca_pem, _) = make_cert_pair();
        let chain = read_cert_chain(&ca_pem).expect("parse single-block chain");
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn read_cert_chain_multi_block() {
        let (ca_pem, leaf_pem) = make_cert_pair();
        let combined = format!("{leaf_pem}{ca_pem}");
        let chain = read_cert_chain(&combined).expect("parse multi-block chain");
        assert_eq!(chain.len(), 2, "leaf + CA should both be parsed");
    }

    #[test]
    fn read_cert_chain_handles_crlf_line_endings() {
        let (ca_pem, _) = make_cert_pair();
        let crlf = ca_pem.replace('\n', "\r\n");
        let chain = read_cert_chain(&crlf).expect("parse CRLF chain");
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn read_cert_chain_handles_trailing_whitespace_between_blocks() {
        let (ca_pem, leaf_pem) = make_cert_pair();
        // Insert blank lines and trailing spaces between concatenated blocks —
        // the kind of noise hand-edited or shell-concatenated PEM files end up
        // with. The original hand-rolled scanner choked on this; `read_pem`
        // handles it.
        let combined = format!("{leaf_pem}\n   \n\t\n{ca_pem}\n\n");
        let chain = read_cert_chain(&combined).expect("parse whitespace-padded chain");
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn read_cert_chain_rejects_empty_input() {
        let err = read_cert_chain("").expect_err("empty input should fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("no CERTIFICATE blocks"), "got: {msg}");
    }

    // ---------------------------------------------------------------------
    // SAN regen idempotence — same SAN set must not rotate the keypair, a
    // different SAN set must regenerate the cert but keep the keypair so the
    // SPKI pin held by already-enrolled agents stays stable.
    // ---------------------------------------------------------------------

    #[test]
    fn ensure_server_cert_is_idempotent_when_san_set_matches() {
        let temp_dir = std::env::temp_dir().join(format!("dgw-san-idem-{}", Uuid::new_v4()));
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("temp path UTF-8");
        let ca = CaManager::load_or_generate(&data_dir).expect("CA");

        let names = ["gateway.corp.example.com", "10.10.0.7"];
        let (_cert_path, key_path) = ca.ensure_server_cert(&names).expect("first issue");

        let key_pem_before = std::fs::read_to_string(&key_path).expect("read key after first issue");

        // Re-running with the same set must be a no-op (same key, same cert content).
        let (cert_path_2, key_path_2) = ca.ensure_server_cert(&names).expect("second issue");
        assert_eq!(cert_path_2, _cert_path);
        assert_eq!(key_path_2, key_path);

        let key_pem_after = std::fs::read_to_string(&key_path_2).expect("read key after second issue");
        assert_eq!(key_pem_before, key_pem_after, "keypair must not rotate when SAN set unchanged");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn ensure_server_cert_regenerates_on_san_change_keeping_keypair() {
        let temp_dir = std::env::temp_dir().join(format!("dgw-san-change-{}", Uuid::new_v4()));
        let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("temp path UTF-8");
        let ca = CaManager::load_or_generate(&data_dir).expect("CA");

        let names_before = ["gateway.corp.example.com"];
        let (cert_path, key_path) = ca.ensure_server_cert(&names_before).expect("first issue");
        let key_pem_before = std::fs::read_to_string(&key_path).expect("read key");
        let cert_pem_before = std::fs::read_to_string(&cert_path).expect("read cert");

        // Now configure a different SAN set: add an IP literal and a public DNS name.
        let names_after = ["gateway.corp.example.com", "10.10.0.7", "agw.public.example.com"];
        ca.ensure_server_cert(&names_after).expect("regen with new SAN set");

        let key_pem_after = std::fs::read_to_string(&key_path).expect("read key after regen");
        let cert_pem_after = std::fs::read_to_string(&cert_path).expect("read cert after regen");

        assert_eq!(
            key_pem_before, key_pem_after,
            "keypair must be reused when only the SAN set changes — SPKI pin stays stable"
        );
        assert_ne!(
            cert_pem_before, cert_pem_after,
            "cert document must be reissued when the SAN set changes"
        );

        // Confirm the new cert actually contains the new SANs in canonical form.
        let der = cert_pem_to_der(&cert_pem_after).expect("parse new cert PEM");
        let cert = Cert::from_der(&der).expect("parse new cert DER");
        let mut sans = extract_san_set(&cert);
        sans.sort();
        let mut expected = build_san_set(&names_after).expect("build expected SAN set");
        expected.sort();
        assert_eq!(sans, expected);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn build_san_set_normalizes_and_dedups() {
        // Mixed case DNS, alternate IP formatting, duplicate entries.
        let names = [
            "Gateway.Corp.Example.com",
            "gateway.corp.example.com",
            "10.10.0.7",
            "fd00::7",
            "fd00::0007", // same IPv6 in alternate form
        ];
        let sans = build_san_set(&names).expect("build SAN set");

        // Expected canonical: lowered DNS, canonical IP strings, deduped.
        let expected: Vec<SanIdent> = vec![
            SanIdent::Dns("gateway.corp.example.com".to_owned()),
            SanIdent::Ip("10.10.0.7".parse().unwrap()),
            SanIdent::Ip("fd00::7".parse().unwrap()),
        ];
        assert_eq!(sans, expected);
    }

    #[test]
    fn build_san_set_rejects_empty_entry() {
        let err = build_san_set(&["   "]).expect_err("empty advertised name should fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("empty"), "got: {msg}");
    }

    #[test]
    fn read_cert_chain_rejects_wrong_label() {
        let (_, leaf_pem) = make_cert_pair();
        // Build a 2-block input where the second block has the wrong label.
        let private_key_block = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";
        let combined = format!("{leaf_pem}{private_key_block}");
        let err = read_cert_chain(&combined).expect_err("wrong label should fail");
        let msg = format!("{err:#}");
        // The error context must point at the failing block index, not just say "parse PEM".
        assert!(msg.contains("index 1"), "error should locate the bad block: {msg}");
    }
}
