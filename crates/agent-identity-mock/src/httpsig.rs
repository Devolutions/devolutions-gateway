//! CONTRACT.md §6 RFC 9421 profile verifier, built by hand (no RFC 9421 library).
//!
//! The single entry point is [`verify_request`]; the HTTP server, the gRPC channel and
//! the in-crate vector test all go through it.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::Digest as _;
use uuid::Uuid;

use crate::sfv;

/// Endpoint a signature is verified for (the `tag` must match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Renew,
    Connect,
}

impl Endpoint {
    fn tag(self) -> &'static str {
        match self {
            Endpoint::Renew => "renew",
            Endpoint::Connect => "connect",
        }
    }

    fn components(self) -> &'static [&'static str] {
        match self {
            Endpoint::Renew => &["@method", "content-digest"],
            Endpoint::Connect => &["@method"],
        }
    }
}

/// §5.4 rejection codes produced by signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    SignatureInvalid,
    ClockSkew,
    DeviceUnknown,
    DeviceRevoked,
    CertificateExpired,
}

impl Rejection {
    pub fn code(self) -> &'static str {
        match self {
            Rejection::SignatureInvalid => "signature_invalid",
            Rejection::ClockSkew => "clock_skew",
            Rejection::DeviceUnknown => "device_unknown",
            Rejection::DeviceRevoked => "device_revoked",
            Rejection::CertificateExpired => "certificate_expired",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Rejection::DeviceRevoked => 403,
            _ => 401,
        }
    }
}

/// Status of a registered certificate (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Current,
    Pending,
    Retired,
}

impl CertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Pending => "pending",
            Self::Retired => "retired",
        }
    }
}

/// What the verifier needs to know about the certificate behind a `keyid`.
#[derive(Debug, Clone)]
pub struct RegisteredCert {
    pub device_id: Uuid,
    pub revoked: bool,
    pub status: CertStatus,
    /// Unix seconds.
    pub not_before: i64,
    /// Unix seconds.
    pub not_after: i64,
    pub public_key: VerifyingKey,
}

/// Replay store for `(keyid, nonce)` pairs (§6 step 6).
#[derive(Debug, Default)]
pub struct NonceStore {
    /// `(keyid, nonce)` → keep until (Unix seconds).
    entries: HashMap<(String, String), i64>,
}

impl NonceStore {
    /// Atomically inserts `(keyid, nonce)`. Returns `false` on conflict.
    pub fn insert_fresh(&mut self, keyid: &str, nonce: &str, keep_until: i64, now: i64) -> bool {
        self.entries.retain(|_, until| *until >= now);
        match self.entries.entry((keyid.to_owned(), nonce.to_owned())) {
            Entry::Vacant(entry) => {
                entry.insert(keep_until);
                true
            }
            Entry::Occupied(_) => false,
        }
    }
}

/// A successfully authenticated request. Constructible only by [`verify_request`], so
/// handlers downstream of authentication can trust the identity fields.
pub struct AuthenticatedDevice {
    device_id: Uuid,
    cert_thumbprint: String,
    /// The `nonce` parameter of the signature, UTF-8 as received (§7.3 binds it).
    nonce: String,
    public_key: VerifyingKey,
}

impl AuthenticatedDevice {
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn cert_thumbprint(&self) -> &str {
        &self.cert_thumbprint
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }
}

/// §6 policy parameters.
const MAX_WINDOW_SECS: i64 = 300;
const CLOCK_TOLERANCE_SECS: i64 = 60;
const NONCE_KEEP_SECS: i64 = 60;
const PROFILE_ALG: &str = "ecdsa-p256-sha256";

/// Verifies an RFC 9421-signed request per CONTRACT.md §6, checks in exactly the
/// contract's order.
///
/// `lookup` resolves a `keyid` (certificate thumbprint) to a registered certificate.
///
/// `signature_input`, `signature` and `content_digest` are the raw header/metadata
/// values (`content_digest` is only consulted for `renew`).
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per contract input; bundling them would just move the noise"
)]
pub fn verify_request(
    endpoint: Endpoint,
    method: &str,
    signature_input: Option<&[u8]>,
    signature: Option<&[u8]>,
    content_digest: Option<&[u8]>,
    body: &[u8],
    now: i64,
    lookup: &mut dyn FnMut(&str) -> Option<RegisteredCert>,
    nonces: &mut NonceStore,
) -> Result<AuthenticatedDevice, Rejection> {
    // Step 1: parse both headers, exactly one `sig` member each, all six parameters,
    // profile algorithm, profile covered components.
    let signature_input = header_str(signature_input)?;
    let signature = header_str(signature)?;

    let input_members = sfv::parse_dictionary(signature_input).ok_or(Rejection::SignatureInvalid)?;
    let sig_members = sfv::parse_dictionary(signature).ok_or(Rejection::SignatureInvalid)?;
    if input_members.len() != 1 || sig_members.len() != 1 {
        return Err(Rejection::SignatureInvalid);
    }
    let (input_label, input_value) = &input_members[0];
    let (sig_label, sig_value) = &sig_members[0];
    if input_label != "sig" || sig_label != "sig" {
        return Err(Rejection::SignatureInvalid);
    }
    let sfv::MemberValue::InnerList(inner) = input_value else {
        return Err(Rejection::SignatureInvalid);
    };
    let sfv::MemberValue::Item(sfv::ListItem {
        value: sfv::ItemValue::Bytes(sig_bytes),
        params: sig_params,
    }) = sig_value
    else {
        return Err(Rejection::SignatureInvalid);
    };
    if !sig_params.is_empty() {
        return Err(Rejection::SignatureInvalid);
    }

    // Covered components: exactly the profile list, in order, strings without params.
    let components = endpoint.components();
    if inner.items.len() != components.len() {
        return Err(Rejection::SignatureInvalid);
    }
    for (item, expected) in inner.items.iter().zip(components) {
        match item {
            sfv::ListItem {
                value: sfv::ItemValue::Str(s),
                params,
            } if params.is_empty() && s == expected => {}
            _ => return Err(Rejection::SignatureInvalid),
        }
    }

    let created = int_param(inner, "created")?;
    let expires = int_param(inner, "expires")?;
    let nonce = str_param(inner, "nonce")?;
    let keyid = str_param(inner, "keyid")?;
    let alg = str_param(inner, "alg")?;
    let tag = str_param(inner, "tag")?;
    let mut param_keys = HashSet::new();
    if inner.params.iter().any(|param| !param_keys.insert(param.key.as_str()))
        || !valid_base64url_bytes(nonce, 16)
        || !valid_base64url_bytes(keyid, 32)
        || alg != PROFILE_ALG
    {
        return Err(Rejection::SignatureInvalid);
    }

    // Step 2: tag matches the endpoint.
    if tag != endpoint.tag() {
        return Err(Rejection::SignatureInvalid);
    }

    // Step 3: signature window.
    if !(1..=MAX_WINDOW_SECS).contains(&(expires - created))
        || created > now + CLOCK_TOLERANCE_SECS
        || expires < now - CLOCK_TOLERANCE_SECS
    {
        return Err(Rejection::ClockSkew);
    }

    // Step 4: resolve the keyid.
    let cert = match lookup(keyid) {
        Some(cert) if matches!(cert.status, CertStatus::Current | CertStatus::Pending) => cert,
        _ => return Err(Rejection::DeviceUnknown),
    };
    if cert.revoked {
        return Err(Rejection::DeviceRevoked);
    }
    let valid = match endpoint {
        Endpoint::Connect => cert.not_before <= now && now < cert.not_after,
        Endpoint::Renew => now < cert.not_after + (cert.not_after - cert.not_before),
    };
    if !valid {
        return Err(Rejection::CertificateExpired);
    }

    // Step 5: content-digest (renew) and signature.
    if endpoint == Endpoint::Renew {
        let header = header_str(content_digest)?;
        let expected = content_digest_header(body);
        if header != expected {
            return Err(Rejection::SignatureInvalid);
        }
    }
    let base = signature_base(method, content_digest, inner);
    let sig = Signature::from_slice(sig_bytes).map_err(|_| Rejection::SignatureInvalid)?;
    cert.public_key
        .verify(base.as_bytes(), &sig)
        .map_err(|_| Rejection::SignatureInvalid)?;

    // Step 6: commit the nonce only after the signature verified.
    if !nonces.insert_fresh(keyid, nonce, expires + NONCE_KEEP_SECS, now) {
        return Err(Rejection::SignatureInvalid);
    }

    Ok(AuthenticatedDevice {
        device_id: cert.device_id,
        cert_thumbprint: keyid.to_owned(),
        nonce: nonce.to_owned(),
        public_key: cert.public_key,
    })
}

fn header_str(value: Option<&[u8]>) -> Result<&str, Rejection> {
    value
        .and_then(|v| core::str::from_utf8(v).ok())
        .ok_or(Rejection::SignatureInvalid)
}

fn find_param<'a>(inner: &'a sfv::InnerList, key: &str) -> Result<&'a sfv::ItemValue, Rejection> {
    inner
        .params
        .iter()
        .find_map(|p| (p.key == key).then_some(p.value.as_ref()))
        .flatten()
        .ok_or(Rejection::SignatureInvalid)
}

fn int_param(inner: &sfv::InnerList, key: &str) -> Result<i64, Rejection> {
    match find_param(inner, key)? {
        sfv::ItemValue::Int(i) => Ok(*i),
        _ => Err(Rejection::SignatureInvalid),
    }
}

fn str_param<'a>(inner: &'a sfv::InnerList, key: &str) -> Result<&'a str, Rejection> {
    match find_param(inner, key)? {
        sfv::ItemValue::Str(s) => Ok(s),
        _ => Err(Rejection::SignatureInvalid),
    }
}

fn valid_base64url_bytes(value: &str, expected_len: usize) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == expected_len && URL_SAFE_NO_PAD.encode(decoded) == value)
}

/// `Content-Digest: sha-256=:<base64>:  ` (RFC 9530), computed over the exact body bytes.
pub fn content_digest_header(body: &[u8]) -> String {
    use base64::Engine as _;
    let digest = sha2::Sha256::digest(body);
    format!("sha-256=:{}:", base64::engine::general_purpose::STANDARD.encode(digest))
}

/// RFC 9421 §2.5 signature base: one line per covered component as listed in the
/// parsed `Signature-Input` member, then the `@signature-params` line with the inner
/// list re-serialized canonically (parameters in received order).
///
/// In [`verify_request`] this is only reached after the covered-components check, so
/// the components are exactly the §6 profile's; the standalone construction is also
/// exercised by the vector test against `signature_base` fields.
pub(crate) fn signature_base(method: &str, content_digest: Option<&[u8]>, inner: &sfv::InnerList) -> String {
    let mut lines = Vec::with_capacity(inner.items.len() + 1);
    for item in &inner.items {
        let sfv::ItemValue::Str(component) = &item.value else {
            continue;
        };
        match component.as_str() {
            "@method" => lines.push(format!("\"@method\": {method}")),
            // The caller only reaches this point with a well-formed header.
            "content-digest" => {
                let value = content_digest
                    .and_then(|v| core::str::from_utf8(v).ok())
                    .unwrap_or_default();
                lines.push(format!("\"content-digest\": {value}"));
            }
            _ => {}
        }
    }
    lines.push(format!("\"@signature-params\": {}", sfv::serialize_inner_list(inner)));
    lines.join("\n")
}
