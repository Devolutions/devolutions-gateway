//! In-memory CA per CONTRACT.md §4: a P-256 root per rotation generation and
//! per-device leaves (`CN=<device_id>`, SAN URI `urn:uuid:<device_id>`, EKU
//! clientAuth, KU digitalSignature).

use std::str::FromStr as _;

use anyhow::Context as _;
use base64::Engine as _;
use der::Encode as _;
use der::asn1::{Ia5String, ObjectIdentifier};
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate as _;
use sha2::Digest as _;
use spki::EncodePublicKey as _;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder as _, CertificateBuilder};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

/// id-kp-clientAuth (RFC 5280).
const ID_KP_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");

const ROOT_LIFETIME_SECS: i64 = 10 * 365 * 24 * 3600;
pub(crate) const DEFAULT_LEAF_LIFETIME_SECS: i64 = 90 * 24 * 3600;

/// `base64url(SHA-256(certificate DER))` (§1).
pub(crate) fn thumbprint(der: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(der))
}

/// Base64 (standard, padded) of a DER blob, for JSON bodies (§1).
pub(crate) fn base64_der(der: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(der)
}

fn unix_to_time(secs: i64) -> anyhow::Result<Time> {
    let secs = u64::try_from(secs).context("negative timestamp")?;
    let system = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    Time::try_from(system).context("timestamp out of range")
}

/// A fixed profile: explicit issuer and subject; extensions are added by the caller
/// through `CertificateBuilder::add_extension`.
struct FixedProfile {
    issuer: Name,
    subject: Name,
}

impl BuilderProfile for FixedProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::certificate::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

fn new_builder(
    issuer_name: &Name,
    subject_name: &Name,
    public_key: &VerifyingKey,
    serial: u64,
    not_before: i64,
    not_after: i64,
) -> anyhow::Result<CertificateBuilder<FixedProfile>> {
    let profile = FixedProfile {
        issuer: issuer_name.clone(),
        subject: subject_name.clone(),
    };
    let validity = Validity::new(unix_to_time(not_before)?, unix_to_time(not_after)?);
    let spki_der = public_key.to_public_key_der().context("encode subject public key")?;
    let spki = spki::SubjectPublicKeyInfoOwned::try_from(spki_der.as_bytes()).context("parse subject public key")?;
    CertificateBuilder::new(profile, SerialNumber::from(serial), validity, spki).context("create certificate builder")
}

/// A root CA (§4, §8).
pub(crate) struct RootCa {
    pub(crate) name: Name,
    /// Dropped as soon as the root stops issuing during a rotation.
    pub(crate) key: Option<SigningKey>,
    pub(crate) cert_der: Vec<u8>,
    pub(crate) thumbprint: String,
    /// Unix seconds.
    pub(crate) not_before: i64,
    /// Unix seconds.
    pub(crate) not_after: i64,
    /// Whether the root is currently listed by `trust-anchor`.
    pub(crate) published: bool,
}

impl RootCa {
    /// Creates a self-signed P-256 root, `CN=Mock Agent Identity Root <n>`, 10 years.
    pub(crate) fn generate(n: u32, now: i64) -> anyhow::Result<Self> {
        let mut rng = rand::rng();
        let key = SigningKey::generate_from_rng(&mut rng);
        let name = Name::from_str(&format!("CN=Mock Agent Identity Root {n}")).context("root name")?;
        let not_before = now;
        let not_after = now + ROOT_LIFETIME_SECS;
        let mut builder = new_builder(&name, &name, key.verifying_key(), u64::from(n), not_before, not_after)?;
        builder
            .add_extension(&BasicConstraints {
                ca: true,
                path_len_constraint: None,
            })
            .context("add basic constraints")?;
        builder
            .add_extension(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign))
            .context("add key usage")?;
        let cert = builder
            .build::<_, DerSignature>(&key)
            .context("sign root certificate")?;
        let cert_der = cert.to_der().context("encode root certificate")?;
        Ok(Self {
            thumbprint: thumbprint(&cert_der),
            name,
            key: Some(key),
            cert_der,
            not_before,
            not_after,
            published: true,
        })
    }
}

/// A freshly issued leaf certificate.
pub(crate) struct Leaf {
    pub(crate) der: Vec<u8>,
    pub(crate) thumbprint: String,
    pub(crate) serial: String,
    /// Unix seconds.
    pub(crate) not_before: i64,
    /// Unix seconds.
    pub(crate) not_after: i64,
}

/// Issues a leaf per §4; the lifetime is capped at the issuing root's `notAfter`.
pub(crate) fn issue_leaf(
    root: &RootCa,
    device_id: uuid::Uuid,
    public_key: &VerifyingKey,
    serial: u64,
    now: i64,
    lifetime_secs: i64,
) -> anyhow::Result<Leaf> {
    let not_before = now;
    let not_after = now
        .checked_add(lifetime_secs)
        .context("leaf validity end overflowed")?
        .min(root.not_after);
    anyhow::ensure!(not_after > not_before, "issuing root has expired");
    let subject = Name::from_str(&format!("CN={device_id}")).context("leaf name")?;
    let san_uri = Ia5String::new(&format!("urn:uuid:{device_id}")).context("leaf SAN URI")?;
    let mut builder = new_builder(&root.name, &subject, public_key, serial, not_before, not_after)?;
    builder
        .add_extension(&BasicConstraints {
            ca: false,
            path_len_constraint: None,
        })
        .context("add basic constraints")?;
    builder
        .add_extension(&KeyUsage(KeyUsages::DigitalSignature.into()))
        .context("add key usage")?;
    builder
        .add_extension(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]))
        .context("add extended key usage")?;
    builder
        .add_extension(&SubjectAltName(vec![GeneralName::UniformResourceIdentifier(san_uri)]))
        .context("add subject alternative name")?;
    let cert = builder
        .build::<_, DerSignature>(root.key.as_ref().context("issuing root key was destroyed")?)
        .context("sign leaf certificate")?;
    let der = cert.to_der().context("encode leaf certificate")?;
    Ok(Leaf {
        thumbprint: thumbprint(&der),
        serial: format!("{serial:x}"),
        der,
        not_before,
        not_after,
    })
}

/// Canonical public-key encoding used to compare keys across requests (SPKI DER).
pub(crate) fn public_key_der(key: &VerifyingKey) -> Vec<u8> {
    key.to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .unwrap_or_else(|_| key.to_sec1_bytes().to_vec())
}
