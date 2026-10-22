use std::fs::{File, OpenOptions};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use camino::Utf8PathBuf;
use devolutions_agent_shared::{create_restricted_directory, get_data_dir, write_restricted_file_atomic};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tonic::Request;
use tonic::transport::Channel;
use uuid::Uuid;

use super::protocol::agent_enrollment_client::AgentEnrollmentClient;
use super::protocol::{
    EnrollRequest, EnrollResponse, EnrollmentStatus, RenewRequest, TrustAnchorRequest, TrustAnchorResponse,
};
use crate::config::PsuConf;

const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const RENEW_BEFORE: i64 = 7 * 24 * 60 * 60;
const ASSERTION_LIFETIME: i64 = 60;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    server_url: String,
    root_thumbprint: String,
    hardware_id: String,
    key_pkcs8: String,
    enrollment_started: bool,
    device_id: Option<Uuid>,
    certificate: Option<String>,
    chain: Vec<String>,
    root: Option<String>,
    not_after: Option<i64>,
    pending: bool,
}

pub struct DeviceIdentity {
    path: Utf8PathBuf,
    state: State,
    _lock: File,
}

impl DeviceIdentity {
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "StatePath": self.path,
            "DeviceId": self.state.device_id,
            "NotAfter": self.state.not_after,
            "PendingApprovalAtIssuance": self.state.pending,
            "EnrollmentOutcomeUnknown": self.state.enrollment_started && self.state.device_id.is_none(),
        })
    }

    pub fn open(conf: &PsuConf) -> anyhow::Result<Self> {
        let device = conf
            .device_enrollment
            .as_ref()
            .context("PSU device mode is not configured")?;
        let server_url = conf.server_url.as_str().to_owned();
        let namespace = hex::encode(Sha256::digest(server_url.as_bytes()));
        let directory = device
            .state_directory
            .clone()
            .unwrap_or_else(|| get_data_dir().join("psu-device"))
            .join(namespace);
        create_restricted_directory(&directory)?;
        let lock_path = directory.join("identity.lock");
        reject_symlink(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .context("open PSU identity lock")?;
        lock.try_lock()
            .context("another process owns this PSU device identity")?;
        let path = directory.join("identity.json");
        reject_symlink(&path)?;
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<State>(&bytes).context("invalid PSU device state")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key =
                    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate PSU device key")?;
                State {
                    version: 1,
                    server_url: server_url.clone(),
                    root_thumbprint: device.root_thumbprint.to_ascii_uppercase(),
                    hardware_id: device.hardware_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string()),
                    key_pkcs8: STANDARD.encode(key.serialize_der()),
                    enrollment_started: false,
                    device_id: None,
                    certificate: None,
                    chain: Vec::new(),
                    root: None,
                    not_after: None,
                    pending: false,
                }
            }
            Err(error) => return Err(error).context("read PSU device state"),
        };
        ensure!(state.version == 1, "unsupported PSU device state version");
        ensure!(
            state.server_url == server_url,
            "PSU device state belongs to a different server"
        );
        ensure!(
            state.root_thumbprint == device.root_thumbprint.to_ascii_uppercase(),
            "PSU device state root pin changed; explicit operator recovery is required"
        );
        ensure!(
            !state.hardware_id.is_empty() && state.hardware_id.len() <= 256,
            "invalid persisted PSU hardware identifier"
        );
        if let Some(hardware_id) = &device.hardware_id {
            ensure!(
                hardware_id == &state.hardware_id,
                "PSU hardware ID changed; explicit operator recovery is required"
            );
        }
        let identity = Self {
            path,
            state,
            _lock: lock,
        };
        identity.key()?;
        if identity.state.device_id.is_some() {
            identity.validate_saved_certificate()?;
        } else {
            ensure!(
                identity.state.certificate.is_none()
                    && identity.state.root.is_none()
                    && identity.state.not_after.is_none()
                    && identity.state.chain.is_empty(),
                "incomplete PSU device state"
            );
        }
        identity.save()?;
        Ok(identity)
    }

    fn save(&self) -> anyhow::Result<()> {
        let json = serde_json::to_string(&self.state).context("serialize PSU device state")?;
        write_restricted_file_atomic(&self.path, &json).context("save PSU device state")
    }

    fn key(&self) -> anyhow::Result<EcdsaKeyPair> {
        let bytes = STANDARD
            .decode(&self.state.key_pkcs8)
            .context("decode PSU device private key")?;
        EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &bytes,
            &SystemRandom::new(),
        )
        .map_err(|_| anyhow::anyhow!("invalid PSU device P-256 private key"))
    }

    pub fn device_id(&self) -> anyhow::Result<String> {
        self.state
            .device_id
            .map(|id| id.to_string())
            .context("PSU device is not enrolled")
    }

    fn csr(&self, name: &str) -> anyhow::Result<Vec<u8>> {
        let bytes = STANDARD
            .decode(&self.state.key_pkcs8)
            .context("decode PSU device private key")?;
        let key = rcgen::KeyPair::try_from(bytes).context("load PSU device key for CSR")?;
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(rcgen::DnType::CommonName, name);
        Ok(params
            .serialize_request(&key)
            .context("create PSU device CSR")?
            .der()
            .to_vec())
    }

    pub async fn prepare(&mut self, channel: Channel, conf: &PsuConf, machine_name: &str) -> anyhow::Result<()> {
        let mut client = AgentEnrollmentClient::new(channel);
        if self.state.device_id.is_none() {
            ensure!(
                !self.state.enrollment_started,
                "PSU enrollment outcome is unknown; recover the existing identity with the operator, do not enroll again"
            );
            let nonce = Uuid::new_v4().to_string();
            let mut request = Request::new(TrustAnchorRequest { nonce: nonce.clone() });
            request.set_timeout(RPC_TIMEOUT);
            let response = client
                .get_trust_anchor(request)
                .await
                .context("get PSU trust anchor")?
                .into_inner();
            validate_trust_anchor(&response, &self.state.root_thumbprint, &nonce, unix_now()?)?;
            let root = response.root_certificate;

            let token = conf
                .device_enrollment
                .as_ref()
                .and_then(|device| device.enrollment_token.as_deref())
                .context("PSU first enrollment requires DeviceEnrollment.EnrollmentToken")?;
            let mut request = Request::new(EnrollRequest {
                csr: self.csr(machine_name)?,
                machine_name: machine_name.to_owned(),
                os: std::env::consts::OS.to_owned(),
                architecture: std::env::consts::ARCH.to_owned(),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                requested_display_name: conf.display_name.clone().unwrap_or_else(|| machine_name.to_owned()),
                hardware_id: self.state.hardware_id.clone(),
            });
            request.metadata_mut().insert(
                "authorization",
                format!("Bearer {token}")
                    .parse()
                    .context("invalid PSU enrollment token metadata")?,
            );
            request.set_timeout(RPC_TIMEOUT);
            // Persist before sending: an ambiguous response must never automatically spend the token again.
            self.state.enrollment_started = true;
            self.save()?;
            let response = client.enroll(request).await.context("enroll PSU device")?.into_inner();
            self.replace_certificate(response, root)?;
            return Ok(());
        }
        self.renew_if_needed(&mut client, false).await
    }

    async fn renew_if_needed(
        &mut self,
        client: &mut AgentEnrollmentClient<Channel>,
        force: bool,
    ) -> anyhow::Result<()> {
        let now = unix_now()?;
        if !force && now < self.renewal_at()? {
            return Ok(());
        }
        let id = self.device_id()?;
        let mut request = Request::new(RenewRequest { csr: self.csr(&id)? });
        request.metadata_mut().insert(
            "authorization",
            self.authorization()?.parse().context("invalid device metadata")?,
        );
        request.set_timeout(RPC_TIMEOUT);
        let response = client
            .renew(request)
            .await
            .context("renew PSU device certificate")?
            .into_inner();
        ensure!(response.device_id == id, "PSU renewal changed device identity");
        let root = STANDARD
            .decode(self.state.root.as_ref().context("missing PSU device root")?)
            .context("decode PSU device root")?;
        let device_id = self.state.device_id.context("missing PSU device ID")?;
        self.replace_certificate(response, root)?;
        info!(%device_id, "Renewed PSU device certificate");
        Ok(())
    }

    fn replace_certificate(&mut self, response: EnrollResponse, root: Vec<u8>) -> anyhow::Result<()> {
        let device_id = Uuid::parse_str(&response.device_id).context("invalid PSU device ID")?;
        if let Some(existing) = self.state.device_id {
            ensure!(existing == device_id, "PSU renewal changed device identity");
        }
        let pending = match EnrollmentStatus::try_from(response.status) {
            Ok(EnrollmentStatus::Approved) => false,
            Ok(EnrollmentStatus::PendingApproval) => true,
            _ => bail!("invalid PSU certificate approval status"),
        };
        validate_device_certificate(
            &response.certificate,
            &response.chain,
            &root,
            &self.state.root_thumbprint,
            self.key()?.public_key().as_ref(),
            &device_id.to_string(),
            unix_now()?,
        )?;
        ensure!(
            fingerprint(&response.certificate) == response.certificate_thumbprint,
            "PSU device certificate thumbprint mismatch"
        );
        let expiry = certificate_expiry(&response.certificate)?;
        let timestamp = response.not_after.context("missing PSU certificate expiry")?;
        ensure!(
            timestamp.seconds == expiry && timestamp.nanos == 0,
            "PSU certificate expiry mismatch"
        );
        let old = self.state.clone();
        self.state.device_id = Some(device_id);
        self.state.certificate = Some(STANDARD.encode(response.certificate));
        self.state.chain = response.chain.into_iter().map(|cert| STANDARD.encode(cert)).collect();
        self.state.root = Some(STANDARD.encode(root));
        self.state.not_after = Some(expiry);
        self.state.pending = pending;
        if let Err(error) = self.save() {
            self.state = old;
            return Err(error);
        }
        info!(%device_id, pending, "Persisted PSU device identity");
        Ok(())
    }

    fn validate_saved_certificate(&self) -> anyhow::Result<()> {
        let certificate = STANDARD
            .decode(
                self.state
                    .certificate
                    .as_ref()
                    .context("missing PSU device certificate")?,
            )
            .context("decode PSU device certificate")?;
        let root = STANDARD
            .decode(self.state.root.as_ref().context("missing PSU device root")?)
            .context("decode PSU device root")?;
        let chain = self
            .state
            .chain
            .iter()
            .map(|cert| STANDARD.decode(cert))
            .collect::<Result<Vec<_>, _>>()
            .context("decode PSU device chain")?;
        let expiry = certificate_expiry(&certificate)?;
        ensure!(
            self.state.not_after == Some(expiry),
            "persisted PSU certificate expiry mismatch"
        );
        // Expired leaf certificates remain usable only as proof for Renew.
        let at = unix_now()?.min(expiry - 1);
        validate_device_certificate(
            &certificate,
            &chain,
            &root,
            &self.state.root_thumbprint,
            self.key()?.public_key().as_ref(),
            &self.device_id()?,
            at,
        )
    }

    pub fn authorization(&self) -> anyhow::Result<String> {
        let id = self.device_id()?;
        let now = unix_now()?;
        let certificate = self
            .state
            .certificate
            .as_ref()
            .context("missing PSU device certificate")?;
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "x5c": [certificate] });
        let claims = serde_json::json!({
            "aud": "psu-agent", "sub": id, "iat": now, "nbf": now - 5,
            "exp": now + ASSERTION_LIFETIME, "jti": Uuid::new_v4().to_string()
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
        );
        let signature = self
            .key()?
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|_| anyhow::anyhow!("sign PSU device assertion"))?;
        Ok(format!("Device {input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref())))
    }

    pub fn renewal_delay(&self) -> anyhow::Result<Duration> {
        let remaining = (self.renewal_at()? - unix_now()?).max(1);
        Ok(Duration::from_secs(
            u64::try_from(remaining).context("invalid renewal deadline")?,
        ))
    }

    fn renewal_at(&self) -> anyhow::Result<i64> {
        let certificate = STANDARD.decode(
            self.state
                .certificate
                .as_ref()
                .context("missing PSU device certificate")?,
        )?;
        let (_, cert) =
            x509_parser::parse_x509_certificate(&certificate).map_err(|_| anyhow::anyhow!("parse PSU certificate"))?;
        let expiry = cert.validity().not_after.timestamp();
        let lifetime = expiry - cert.validity().not_before.timestamp();
        ensure!(lifetime > 0, "invalid PSU certificate lifetime");
        Ok(expiry - RENEW_BEFORE.min((lifetime / 5).max(1)))
    }
}

pub async fn enroll(conf: &PsuConf) -> anyhow::Result<()> {
    let mut identity = DeviceIdentity::open(conf)?;
    identity
        .prepare(connect_enrollment(conf).await?, conf, &super::machine_name())
        .await
}

pub async fn renew(conf: &PsuConf) -> anyhow::Result<()> {
    let mut identity = DeviceIdentity::open(conf)?;
    identity.device_id()?;
    let mut client = AgentEnrollmentClient::new(connect_enrollment(conf).await?);
    identity.renew_if_needed(&mut client, true).await
}

async fn connect_enrollment(conf: &PsuConf) -> anyhow::Result<Channel> {
    let settings = super::ConnectionSettings::default();
    let endpoint = super::psu_endpoint(conf.server_url.as_str(), &settings)?;
    tokio::time::timeout(settings.connect_timeout, endpoint.connect())
        .await
        .context("timed out connecting PSU enrollment endpoint")?
        .context("connect PSU enrollment endpoint")
}

fn reject_symlink(path: &camino::Utf8Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "PSU state must be a regular file"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect PSU state file"),
    }
    Ok(())
}

pub fn unix_now() -> anyhow::Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates Unix epoch")?
            .as_secs(),
    )
    .context("system clock exceeds supported range")
}

pub fn fingerprint(bytes: &[u8]) -> String {
    hex::encode_upper(Sha256::digest(bytes))
}

#[derive(Deserialize)]
struct AssertionHeader {
    alg: String,
    x5c: Vec<String>,
    #[serde(default)]
    crit: Vec<String>,
}

#[derive(Deserialize)]
struct ServerClaims {
    aud: String,
    nonce: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}

pub fn validate_trust_anchor(response: &TrustAnchorResponse, pin: &str, nonce: &str, now: i64) -> anyhow::Result<()> {
    ensure!(
        fingerprint(&response.root_certificate) == pin.to_ascii_uppercase(),
        "PSU root pin mismatch"
    );
    ensure!(
        response.root_thumbprint == fingerprint(&response.root_certificate),
        "PSU root fingerprint mismatch"
    );
    let parts = response.server_assertion.split('.').collect::<Vec<_>>();
    ensure!(parts.len() == 3, "invalid PSU server assertion");
    let header: AssertionHeader =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).context("decode server header")?)
            .context("invalid PSU server assertion header")?;
    ensure!(
        header.alg == "ES256" && header.crit.is_empty(),
        "unsupported PSU server assertion algorithm or critical header"
    );
    ensure!(
        (2..=8).contains(&header.x5c.len()),
        "PSU server assertion must include its issuing chain"
    );
    let chain = header
        .x5c
        .iter()
        .map(|cert| STANDARD.decode(cert))
        .collect::<Result<Vec<_>, _>>()
        .context("decode PSU server assertion chain")?;
    ensure!(
        chain.last() == Some(&response.root_certificate),
        "PSU server assertion chain root mismatch"
    );
    validate_chain(&chain[0], &chain[1..], &response.root_certificate, now, true)?;
    let (_, leaf) =
        x509_parser::parse_x509_certificate(&chain[0]).map_err(|_| anyhow::anyhow!("parse PSU server certificate"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .context("decode server assertion signature")?;
    signature::UnparsedPublicKey::new(
        &signature::ECDSA_P256_SHA256_FIXED,
        leaf.public_key().subject_public_key.data.as_ref(),
    )
    .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
    .map_err(|_| anyhow::anyhow!("invalid PSU server assertion signature"))?;
    let claims: ServerClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).context("decode server claims")?)
            .context("invalid PSU server assertion claims")?;
    ensure!(
        claims.aud == "psu-agent-enrollment" && claims.nonce == nonce && !nonce.is_empty(),
        "PSU server assertion audience or nonce mismatch"
    );
    ensure!(
        claims.exp > now
            && claims.nbf <= now + 120
            && claims.iat <= now + 120
            && claims
                .exp
                .checked_sub(claims.iat)
                .is_some_and(|lifetime| (1..=300).contains(&lifetime))
            && claims
                .exp
                .checked_sub(claims.nbf)
                .is_some_and(|lifetime| (1..=420).contains(&lifetime)),
        "invalid PSU server assertion lifetime"
    );
    Ok(())
}

pub fn certificate_expiry(der: &[u8]) -> anyhow::Result<i64> {
    let (remaining, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|_| anyhow::anyhow!("parse PSU certificate"))?;
    ensure!(remaining.is_empty(), "trailing PSU certificate data");
    Ok(cert.validity().not_after.timestamp())
}

fn validate_chain(leaf: &[u8], chain: &[Vec<u8>], root: &[u8], at: i64, server: bool) -> anyhow::Result<()> {
    let root_der = rustls_pki_types::CertificateDer::from(root);
    let root_cert = x509_parser::parse_x509_certificate(root)
        .map_err(|_| anyhow::anyhow!("parse PSU root certificate"))?
        .1;
    ensure!(root_cert.is_ca(), "PSU trust anchor is not a CA");
    ensure!(
        root_cert.validity().not_before.timestamp() <= at && root_cert.validity().not_after.timestamp() > at,
        "PSU root certificate is not valid at verification time"
    );
    let anchors = [webpki::anchor_from_trusted_cert(&root_der).context("parse PSU trust anchor")?];
    let leaf_der = rustls_pki_types::CertificateDer::from(leaf);
    let end_entity = webpki::EndEntityCert::try_from(&leaf_der).context("parse PSU leaf certificate")?;
    let intermediates = chain
        .iter()
        .filter(|cert| cert.as_slice() != root)
        .map(|cert| rustls_pki_types::CertificateDer::from(cert.as_slice()))
        .collect::<Vec<_>>();
    let usage = if server {
        webpki::KeyUsage::server_auth()
    } else {
        webpki::KeyUsage::client_auth()
    };
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(
                u64::try_from(at).context("invalid verification time")?,
            )),
            usage,
            None,
            None,
        )
        .context("verify PSU certificate chain")?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(leaf).map_err(|_| anyhow::anyhow!("parse PSU leaf certificate"))?;
    let eku = cert
        .extended_key_usage()
        .context("parse PSU certificate EKU")?
        .context("PSU leaf certificate requires EKU")?;
    ensure!(
        if server {
            eku.value.server_auth
        } else {
            eku.value.client_auth
        },
        "invalid PSU leaf certificate EKU"
    );
    let usage = cert
        .key_usage()
        .context("parse PSU certificate key usage")?
        .context("PSU leaf requires key usage")?;
    ensure!(
        usage.value.digital_signature() && !cert.is_ca(),
        "invalid PSU leaf certificate key usage"
    );
    Ok(())
}

pub fn validate_device_certificate(
    leaf: &[u8],
    chain: &[Vec<u8>],
    root: &[u8],
    pin: &str,
    public_key: &[u8],
    device_id: &str,
    at: i64,
) -> anyhow::Result<()> {
    ensure!(
        fingerprint(root) == pin.to_ascii_uppercase(),
        "PSU device root pin mismatch"
    );
    ensure!(
        !chain.is_empty() && chain.len() <= 8 && chain.last().map(Vec::as_slice) == Some(root),
        "invalid PSU device issuing chain"
    );
    validate_chain(leaf, chain, root, at, false)?;
    let (remaining, cert) =
        x509_parser::parse_x509_certificate(leaf).map_err(|_| anyhow::anyhow!("parse PSU device certificate"))?;
    ensure!(remaining.is_empty(), "trailing PSU device certificate data");
    ensure!(
        cert.public_key().subject_public_key.data.as_ref() == public_key,
        "PSU certificate does not match device private key"
    );
    ensure!(
        cert.subject()
            .iter_common_name()
            .any(|name| name.as_str().ok() == Some(device_id)),
        "PSU certificate device identity mismatch"
    );
    let san = cert
        .subject_alternative_name()
        .context("parse PSU device SAN")?
        .context("PSU device certificate requires UUID SAN")?;
    let expected = format!("urn:uuid:{device_id}");
    ensure!(
        san.value.general_names.iter().any(|name| matches!(
            name, x509_parser::extensions::GeneralName::URI(uri) if *uri == expected
        )),
        "PSU certificate UUID SAN mismatch"
    );
    Ok(())
}

pub fn retryable(error: &anyhow::Error) -> bool {
    if let Some(status) = error.chain().find_map(|cause| cause.downcast_ref::<tonic::Status>()) {
        return matches!(status.code(), tonic::Code::Unavailable | tonic::Code::DeadlineExceeded)
            || (status.code() == tonic::Code::PermissionDenied
                && status.message() == "The device is waiting for approval.");
    }

    error
        .chain()
        .any(|cause| cause.is::<tonic::transport::Error>() || cause.is::<tokio::time::error::Elapsed>())
}

pub fn terminal_authentication(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<tonic::Status>())
        .is_some_and(|status| {
            matches!(
                status.code(),
                tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
            ) && status.message() != "The device is waiting for approval."
        })
}
