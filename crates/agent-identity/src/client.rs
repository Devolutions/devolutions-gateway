use std::collections::HashMap;
use std::fmt;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use agent_identity_httpsig::RequestSigner;
use agent_identity_httpsig::Tag;
use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use camino::Utf8Path;
use der::asn1::Ia5StringRef;
use der::{Decode as _, Encode as _};
use device_key::DeviceKey;
use http_client_proxy::{ProxyConfig, SystemProxySettings};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::EncodePublicKey as _;
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{debug, warn};
use url::Url;
use uuid::Uuid;
use x509_cert::Certificate;

use crate::csr::ENROLLMENT_URL_EXTENSION;
use crate::metadata::Metadata;
use crate::token::Token;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub type ClientResult<T> = Result<T, ClientError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermanentCode {
    TokenInvalid,
    TokenExhausted,
    TokenExpired,
    /// The enrollment certificate lacks the enrollment URL extension or names another URL than the token's, a local
    /// code ([CONTRACT.agent-identity.md §5.2 "`POST enroll`"][contract]).
    ///
    /// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#enroll
    AuthorityUrlMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalCode {
    IdentityRevoked,
    IdentityUnknown,
}

impl PermanentCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenInvalid => "token_invalid",
            Self::TokenExhausted => "token_exhausted",
            Self::TokenExpired => "token_expired",
            Self::AuthorityUrlMismatch => "authority_url_mismatch",
        }
    }
}

impl TerminalCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityRevoked => "identity_revoked",
            Self::IdentityUnknown => "identity_unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientError {
    Permanent(PermanentCode),
    Terminal(TerminalCode),
    CertificateExpired,
    ClockSkew {
        server_time: OffsetDateTime,
    },
    Transient {
        retry_after: Option<Duration>,
        reason: TransientReason,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransientReason {
    Network(String),
    HttpStatus(u16),
    InvalidResponse(&'static str),
    ServerCode(String),
    Local(&'static str),
}

impl ClientError {
    fn invalid_response(reason: &'static str) -> Self {
        Self::Transient {
            retry_after: None,
            reason: TransientReason::InvalidResponse(reason),
        }
    }

    fn local(reason: &'static str) -> Self {
        Self::Transient {
            retry_after: None,
            reason: TransientReason::Local(reason),
        }
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Transient { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

impl fmt::Display for TransientReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(error) => write!(formatter, "network error: {error}"),
            Self::HttpStatus(status) => write!(formatter, "http status {status}"),
            Self::InvalidResponse(reason) => write!(formatter, "invalid response: {reason}"),
            Self::ServerCode(code) => write!(formatter, "server error code: {code}"),
            Self::Local(reason) => write!(formatter, "local request error: {reason}"),
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permanent(code) => write!(formatter, "permanent identity error: {}", code.as_str()),
            Self::Terminal(code) => write!(formatter, "terminal identity error: {}", code.as_str()),
            Self::CertificateExpired => formatter.write_str("identity certificate expired"),
            Self::ClockSkew { .. } => formatter.write_str("identity request clock skew"),
            Self::Transient { reason, .. } => write!(formatter, "transient identity request failure: {reason}"),
        }
    }
}

impl std::error::Error for ClientError {}

pub struct Client {
    proxy: ProxyConfig,
    /// Reads the system proxy for a URL; tests replace it, since the real settings are machine state.
    system_proxy: fn(&Url) -> anyhow::Result<Option<String>>,
    extra_trusted_roots: Vec<reqwest::Certificate>,
    http: Mutex<HashMap<Url, reqwest::Client>>,
}

#[derive(Deserialize)]
pub struct EnrollResponse {
    #[serde(deserialize_with = "canonical_uuid")]
    pub authority_id: Uuid,
    #[serde(deserialize_with = "canonical_uuid")]
    pub identity_id: Uuid,
    pub certificate_chain: Vec<String>,
    pub config: Value,
}

#[derive(Deserialize)]
pub struct RenewResponse {
    pub certificate_chain: Vec<String>,
}

#[derive(Deserialize)]
pub struct CheckInResponse {
    pub config: Value,
    pub renewal_requested: bool,
}

#[derive(serde::Serialize)]
struct CsrRequest<'a> {
    csr: &'a str,
    metadata: &'a Metadata,
}

#[derive(serde::Serialize)]
struct CheckInRequest<'a> {
    metadata: &'a Metadata,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(default, rename = "message")]
    _message: Option<serde::de::IgnoredAny>,
    server_time: String,
}

impl Client {
    pub fn new(proxy: ProxyConfig, extra_trusted_root: Option<&Utf8Path>) -> anyhow::Result<Self> {
        let extra_trusted_roots = if let Some(path) = extra_trusted_root {
            let pem = std::fs::read(path)?;
            let roots: Vec<_> = rustls_pemfile::certs(&mut Cursor::new(&pem)).collect::<std::io::Result<_>>()?;
            anyhow::ensure!(!roots.is_empty(), "extra trusted root contains no certificates");
            roots
                .iter()
                .map(|root| reqwest::Certificate::from_der(root.as_ref()))
                .collect::<reqwest::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        Ok(Self {
            proxy,
            system_proxy: http_client_proxy::system_proxy_for_url,
            extra_trusted_roots,
            http: Mutex::new(HashMap::new()),
        })
    }

    fn http_for(&self, url: &Url) -> ClientResult<reqwest::Client> {
        // UNTESTED: one gate for the process, so that the warning is logged once per run rather than once per client
        // or identity.
        // When changing this, keep a single static gate for every client.
        static AUTOMATIC_CONFIGURATION_WARNED: AtomicBool = AtomicBool::new(false);
        warn_on_automatic_configuration(
            &AUTOMATIC_CONFIGURATION_WARNED,
            &self.proxy,
            http_client_proxy::read_system_proxy_settings,
        );
        // UNTESTED: Each identity request must use the proxy selected for its own URL, including bypasses.
        // Reqwest otherwise applies environment proxies to bypassed targets.
        // A client cached for another URL keeps the proxy selected for that URL.
        // Check per-authority routing, Manual Exclude and System NO_PROXY when changing this cache or builder.
        let mut clients = self
            .http
            .lock()
            .map_err(|_| ClientError::local("identity HTTP client cache unavailable"))?;
        if let Some(client) = clients.get(url) {
            return Ok(client.clone());
        }
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            // Disable the bundled WebPKI roots, then restore only the OS roots.
            .tls_built_in_root_certs(false)
            .tls_built_in_native_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .no_proxy();
        for root in &self.extra_trusted_roots {
            builder = builder.add_root_certificate(root.clone());
        }
        let proxy = http_client_proxy::try_proxy_for_url(url, &self.proxy, self.system_proxy).map_err(|error| {
            warn!(error = format!("{error:#}"), "Failed to read the system proxy");
            ClientError::local("system proxy unreadable")
        })?;
        if let Some(proxy) = proxy {
            check_proxy_is_usable(&proxy)?;
            let proxy = reqwest::Proxy::all(proxy).map_err(|_| ClientError::local("configure identity HTTP client"))?;
            builder = builder.proxy(proxy);
        }
        let client = builder
            .build()
            .map_err(|_| ClientError::local("configure identity HTTP client"))?;
        clients.insert(url.clone(), client.clone());
        Ok(client)
    }

    pub async fn enroll(
        &self,
        token: &Token,
        csr_der: &str,
        metadata: &Metadata,
        key: &dyn DeviceKey,
    ) -> ClientResult<EnrollResponse> {
        let url = Url::parse(&operation_url(token.base_url(), "enroll"))
            .map_err(|_| ClientError::local("invalid authority URL"))?;
        let body = serde_json::to_vec(&CsrRequest { csr: csr_der, metadata })
            .map_err(|_| ClientError::local("encode enroll request"))?;
        let request = self
            .http_for(&url)?
            .post(url)
            .bearer_auth(token.as_str())
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        let (status, body) = self.send(request).await?;
        if status != StatusCode::OK {
            return Err(ClientError::invalid_response("unexpected enroll status"));
        }
        let response: EnrollResponse = parse_response(&body)?;
        validate_certificate_chain(&response.certificate_chain, &key.public_key())?;
        validate_config(&response.config)?;
        // UNTESTED: every enrollment response, first enrollments included, is refused when its leaf doesn't name the
        // token's base URL, so that a server holding a token for another address can't relay the enrollment.
        // No client test runs an HTTPS authority; when changing this, keep the check on the enroll path.
        check_enrollment_url(&response.certificate_chain, token.base_url())?;
        Ok(response)
    }

    /// Sends a renewal for the key of `csr_der` and requires the returned leaf to hold `new_key`.
    pub async fn renew(
        &self,
        base_url: &str,
        signer: &RequestSigner,
        csr_der: &str,
        new_key: &VerifyingKey,
        metadata: &Metadata,
        clock_offset_secs: Option<i64>,
    ) -> ClientResult<RenewResponse> {
        let body = serde_json::to_vec(&CsrRequest { csr: csr_der, metadata })
            .map_err(|_| ClientError::local("encode renew request"))?;
        let (status, response) = self
            .signed_post(base_url, "renew", Tag::Renew, signer, &body, clock_offset_secs)
            .await?;
        if status != StatusCode::OK {
            return Err(ClientError::invalid_response("unexpected renew status"));
        }
        let response: RenewResponse = parse_response(&response)?;
        validate_certificate_chain(&response.certificate_chain, new_key)?;
        Ok(response)
    }

    pub async fn confirm(
        &self,
        base_url: &str,
        signer: &RequestSigner,
        clock_offset_secs: Option<i64>,
    ) -> ClientResult<()> {
        let (status, response) = self
            .signed_post(base_url, "confirm", Tag::Confirm, signer, &[], clock_offset_secs)
            .await?;
        if status != StatusCode::NO_CONTENT {
            Err(ClientError::invalid_response("unexpected confirm status"))
        } else if !response.is_empty() {
            Err(ClientError::invalid_response("unexpected confirm body"))
        } else {
            Ok(())
        }
    }

    pub async fn check_in(
        &self,
        base_url: &str,
        signer: &RequestSigner,
        metadata: &Metadata,
        clock_offset_secs: Option<i64>,
    ) -> ClientResult<CheckInResponse> {
        let body = serde_json::to_vec(&CheckInRequest { metadata })
            .map_err(|_| ClientError::local("encode check-in request"))?;
        let (status, response) = self
            .signed_post(base_url, "check-in", Tag::CheckIn, signer, &body, clock_offset_secs)
            .await?;
        if status != StatusCode::OK {
            return Err(ClientError::invalid_response("unexpected check-in status"));
        }
        let response: CheckInResponse = parse_response(&response)?;
        validate_config(&response.config)?;
        Ok(response)
    }

    async fn signed_post(
        &self,
        base_url: &str,
        operation: &str,
        tag: Tag,
        signer: &RequestSigner,
        body: &[u8],
        clock_offset_secs: Option<i64>,
    ) -> ClientResult<(StatusCode, Vec<u8>)> {
        let url =
            Url::parse(&operation_url(base_url, operation)).map_err(|_| ClientError::local("invalid authority URL"))?;
        let first = self
            .send_signed(&url, tag, signer, body, clock_offset_secs.unwrap_or_default())
            .await;
        if let Err(ClientError::ClockSkew { server_time }) = first {
            let offset = server_time.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp();
            self.send_signed(&url, tag, signer, body, offset).await
        } else {
            first
        }
    }

    async fn send_signed(
        &self,
        url: &Url,
        tag: Tag,
        signer: &RequestSigner,
        body: &[u8],
        clock_offset_secs: i64,
    ) -> ClientResult<(StatusCode, Vec<u8>)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClientError::local("system clock precedes Unix epoch"))?;
        let created = i64::try_from(now.as_secs())
            .ok()
            .and_then(|now| now.checked_add(clock_offset_secs))
            .and_then(|created| u64::try_from(created).ok())
            .ok_or_else(|| ClientError::local("invalid signature timestamp"))?;
        let headers = signer
            .sign(
                tag,
                &Method::POST,
                matches!(tag, Tag::Renew | Tag::CheckIn).then_some(body),
                created,
            )
            .map_err(|_| ClientError::local("sign identity request"))?;
        let mut request = self
            .http_for(url)?
            .post(url.clone())
            .header(CONTENT_TYPE, "application/json")
            .header("signature-input", headers.signature_input)
            .header("signature", headers.signature)
            .body(body.to_vec());
        if let Some(digest) = headers.content_digest {
            request = request.header("content-digest", digest);
        }
        self.send(request).await
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> ClientResult<(StatusCode, Vec<u8>)> {
        let mut response = request.send().await.map_err(|error| ClientError::Transient {
            retry_after: None,
            reason: TransientReason::Network(error.to_string()),
        })?;
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_retry_after(value, SystemTime::now()));
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ClientError::Transient {
                retry_after,
                reason: TransientReason::InvalidResponse("response too large"),
            });
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| ClientError::Transient {
            retry_after,
            reason: TransientReason::Network(error.to_string()),
        })? {
            if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
                return Err(ClientError::Transient {
                    retry_after,
                    reason: TransientReason::InvalidResponse("response too large"),
                });
            }
            body.extend_from_slice(&chunk);
        }
        if response.status().is_success() {
            Ok((response.status(), body))
        } else {
            Err(classify_error(response.status(), &body, retry_after))
        }
    }
}

/// Fails with a transient error for a proxy that reqwest would ignore, connecting directly instead, which identity
/// requests never do (`crates/agent-identity/INTENT.md`, "Trust and transport").
///
/// Reqwest 0.12.28 reads a proxy URL without a host, such as `proxy.corp:8080` whose scheme is its host name, as an
/// `http://` URL.
/// It hands the proxy to hyper-util 0.1.20 `parse_env_uri`, which ignores any scheme other than these, and any proxy
/// whose text is not an `http::Uri` with a host.
fn check_proxy_is_usable(proxy: &Url) -> ClientResult<()> {
    let read_as_http;
    let proxy = if proxy.has_host() {
        proxy
    } else {
        read_as_http = Url::parse(&format!("http://{proxy}")).map_err(|_| ClientError::local("invalid proxy URL"))?;
        &read_as_http
    };
    if !matches!(
        proxy.scheme(),
        "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h"
    ) {
        return Err(ClientError::local("unsupported proxy scheme"));
    }
    let has_host = proxy
        .as_str()
        .parse::<http::Uri>()
        .is_ok_and(|uri| uri.host().is_some_and(|host| !host.is_empty()));
    if !has_host {
        return Err(ClientError::local("invalid proxy URL"));
    }
    Ok(())
}

/// Warns once, through `warned`, that System mode connects directly instead of evaluating the Windows automatic proxy
/// configuration of the settings `read` returns.
///
/// It doesn't evaluate a PAC script or WPAD discovery yet (`crates/agent-identity/INTENT.md`, "Trust and transport").
/// Settings that name a proxy, or that can't be read, log no warning.
fn warn_on_automatic_configuration(
    warned: &AtomicBool,
    proxy: &ProxyConfig,
    read: impl FnOnce() -> anyhow::Result<SystemProxySettings>,
) {
    if !matches!(proxy, ProxyConfig::System) || warned.load(Ordering::Relaxed) {
        return;
    }
    let settings = match read() {
        Ok(settings) => settings,
        Err(error) => {
            debug!(error = format!("{error:#}"), "Failed to read the system proxy settings");
            return;
        }
    };
    let configuration = settings.automatic_configuration;
    if !settings.names_proxy
        && (configuration.automatic_detection || configuration.configuration_script)
        && !warned.swap(true, Ordering::Relaxed)
    {
        warn!(
            automatic_detection = configuration.automatic_detection,
            configuration_script = configuration.configuration_script,
            "Windows automatic proxy configuration is not evaluated; identity requests connect directly"
        );
    }
}

/// Joins an operation's path onto `base_url` as text, without its trailing slashes ([CONTRACT.agent-identity.md §2
/// "Enrollment token"][contract] and `crates/agent-identity/INTENT.md`, "Stored identities").
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#enrollment-token
fn operation_url(base_url: &str, operation: &str) -> String {
    format!("{}/api/agent-identity/v1/{operation}", base_url.trim_end_matches('/'))
}

fn parse_response<T: DeserializeOwned>(body: &[u8]) -> ClientResult<T> {
    serde_json::from_slice(body).map_err(|_| ClientError::invalid_response("invalid JSON response"))
}

fn validate_config(config: &Value) -> ClientResult<()> {
    let Some(config) = config.as_object() else {
        return Err(ClientError::invalid_response("config is not an object"));
    };
    if config.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(ClientError::invalid_response("unsupported config version"));
    }
    if config.get("revision").and_then(Value::as_u64).is_none() {
        return Err(ClientError::invalid_response("missing config revision"));
    }
    Ok(())
}

fn canonical_uuid<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
    let text = String::deserialize(deserializer)?;
    let id = Uuid::parse_str(&text).map_err(D::Error::custom)?;
    if id.to_string() == text {
        Ok(id)
    } else {
        Err(D::Error::custom("noncanonical UUID"))
    }
}

fn classify_error(status: StatusCode, body: &[u8], retry_after: Option<Duration>) -> ClientError {
    let parsed = serde_json::from_slice::<ErrorResponse>(body);
    if status.is_server_error() || status.is_redirection() || status == StatusCode::TOO_MANY_REQUESTS {
        return ClientError::Transient {
            retry_after,
            reason: TransientReason::HttpStatus(status.as_u16()),
        };
    }
    let Ok(error) = parsed else {
        return ClientError::Transient {
            retry_after,
            reason: TransientReason::InvalidResponse("invalid error body"),
        };
    };
    let Ok(server_time) = OffsetDateTime::parse(&error.server_time, &Rfc3339) else {
        return ClientError::Transient {
            retry_after,
            reason: TransientReason::InvalidResponse("invalid server time"),
        };
    };
    match (status, error.error.as_str()) {
        (StatusCode::UNAUTHORIZED, "token_invalid") => ClientError::Permanent(PermanentCode::TokenInvalid),
        (StatusCode::FORBIDDEN, "token_exhausted") => ClientError::Permanent(PermanentCode::TokenExhausted),
        (StatusCode::UNAUTHORIZED, "token_expired") => ClientError::Permanent(PermanentCode::TokenExpired),
        (StatusCode::FORBIDDEN, "identity_revoked") => ClientError::Terminal(TerminalCode::IdentityRevoked),
        (StatusCode::UNAUTHORIZED, "identity_unknown") => ClientError::Terminal(TerminalCode::IdentityUnknown),
        (StatusCode::UNAUTHORIZED, "certificate_expired") => ClientError::CertificateExpired,
        (StatusCode::UNAUTHORIZED, "clock_skew") => ClientError::ClockSkew { server_time },
        _ => ClientError::Transient {
            retry_after,
            reason: server_code_reason(error.error),
        },
    }
}

fn server_code_reason(code: String) -> TransientReason {
    if code.len() <= 64
        && code.as_bytes().first().is_some_and(|byte| byte.is_ascii_lowercase())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !code.starts_with("dvaet1")
    {
        TransientReason::ServerCode(code)
    } else {
        TransientReason::InvalidResponse("invalid server error code")
    }
}

fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)))
    } else {
        httpdate::parse_http_date(value)
            .ok()
            .map(|date| date.duration_since(now).unwrap_or_default())
    }
}

fn validate_chain_der(chain: &[String]) -> ClientResult<Vec<Certificate>> {
    if chain.is_empty() {
        return Err(ClientError::invalid_response("empty certificate chain"));
    }
    chain
        .iter()
        .map(|encoded| {
            let der = STANDARD
                .decode(encoded)
                .map_err(|_| ClientError::invalid_response("invalid base64 certificate"))?;
            Certificate::from_der(&der).map_err(|_| ClientError::invalid_response("invalid DER certificate"))
        })
        .collect()
}

/// Requires the leaf of an enrollment chain to carry exactly one enrollment URL extension, whose `IA5String` is
/// `base_url` byte for byte ([CONTRACT.agent-identity.md §5.2 "`POST enroll`"][enroll] and [§4
/// "Certificates"][certificates]).
///
/// `base_url` is the token's `u` without its trailing slashes, the URL the agent names in its CSR.
/// A leaf without the extension, with a value that is not an `IA5String`, or naming another URL is refused as the
/// permanent [`PermanentCode::AuthorityUrlMismatch`], so that a server holding a token for another address can't
/// relay the device's enrollment.
/// Renewal responses are not checked.
///
/// [enroll]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#enroll
/// [certificates]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#certificates
fn check_enrollment_url(chain: &[String], base_url: &str) -> ClientResult<()> {
    let certificates = validate_chain_der(chain)?;
    let mut urls = certificates[0]
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .filter(|extension| extension.extn_id == ENROLLMENT_URL_EXTENSION)
        .map(|extension| Ia5StringRef::from_der(extension.extn_value.as_bytes()));
    match (urls.next(), urls.next()) {
        (Some(Ok(url)), None) if url.as_str() == base_url => Ok(()),
        _ => Err(ClientError::Permanent(PermanentCode::AuthorityUrlMismatch)),
    }
}

/// Returns a signer for a stored key and the leaf of its certificate chain.
pub fn request_signer(key: Arc<dyn DeviceKey>, chain: &[String]) -> anyhow::Result<RequestSigner> {
    Ok(RequestSigner::new(key, &leaf_certificate_der(chain)?))
}

/// Returns the DER leaf certificate of a stored chain.
pub fn leaf_certificate_der(chain: &[String]) -> anyhow::Result<Vec<u8>> {
    let leaf = chain.first().context("stored certificate chain is empty")?;
    STANDARD.decode(leaf).context("decode stored leaf certificate")
}

/// Parses a config pushed on the agent channel ([CONTRACT.agent-identity.md §7.3 "Sequence"][contract], step 7) and
/// checks it as a check-in config.
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#73-sequence
pub fn parse_pushed_config(config_json: &str) -> ClientResult<Value> {
    let config = serde_json::from_str(config_json).map_err(|_| ClientError::invalid_response("invalid config JSON"))?;
    validate_config(&config)?;
    Ok(config)
}

/// Returns the `notBefore` and `notAfter` of a stored chain's leaf certificate.
pub fn leaf_validity(chain: &[String]) -> anyhow::Result<(SystemTime, SystemTime)> {
    let certificates = validate_chain_der(chain)?;
    let validity = certificates[0].tbs_certificate().validity();
    Ok((
        validity.not_before.to_system_time(),
        validity.not_after.to_system_time(),
    ))
}

/// Validates a DER chain and requires the leaf SPKI to match the key.
pub fn validate_certificate_chain(chain: &[String], key: &VerifyingKey) -> ClientResult<()> {
    let certificates = validate_chain_der(chain)?;
    let public_key = key
        .to_public_key_der()
        .map_err(|_| ClientError::local("encode device public key"))?;
    let leaf_spki = certificates[0]
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| ClientError::invalid_response("invalid leaf public key"))?;
    if leaf_spki == public_key.as_bytes() {
        Ok(())
    } else {
        Err(ClientError::invalid_response("leaf key mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use der::asn1::{OctetString, Utf8StringRef};
    use http_client_proxy::{AutomaticConfiguration, ManualProxyConfig};
    use p256::ecdsa::{DerSignature, Signature, SigningKey};
    use rstest::rstest;
    use spki::SubjectPublicKeyInfoOwned;
    use tracing_subscriber::layer::SubscriberExt as _;
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder as _, CertificateBuilder};
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    use super::*;

    struct TestProfile(Vec<Extension>);

    impl BuilderProfile for TestProfile {
        fn get_issuer(&self, subject: &Name) -> Name {
            subject.clone()
        }

        fn get_subject(&self) -> Name {
            "CN=Identity test".parse().expect("valid test name")
        }

        fn build_extensions(
            &self,
            _spk: spki::SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
            _tbs: &x509_cert::certificate::TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            Ok(self.0.clone())
        }
    }

    fn self_signed_leaf(key: &SigningKey, not_before: u64, not_after: u64) -> anyhow::Result<String> {
        leaf_with_extensions(key, not_before, not_after, Vec::new())
    }

    fn leaf_with_extensions(
        key: &SigningKey,
        not_before: u64,
        not_after: u64,
        extensions: Vec<Extension>,
    ) -> anyhow::Result<String> {
        let spki = key.verifying_key().to_public_key_der()?;
        let spki = SubjectPublicKeyInfoOwned::try_from(spki.as_bytes())?;
        let before = Time::try_from(UNIX_EPOCH + Duration::from_secs(not_before))?;
        let after = Time::try_from(UNIX_EPOCH + Duration::from_secs(not_after))?;
        let builder = CertificateBuilder::new(
            TestProfile(extensions),
            SerialNumber::from(1u64),
            Validity::new(before, after),
            spki,
        )?;
        let certificate = builder.build::<_, DerSignature>(key)?;
        Ok(STANDARD.encode(certificate.to_der()?))
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[test]
    fn leaf_validity_reads_the_first_certificate_of_the_chain() -> anyhow::Result<()> {
        let leaf = self_signed_leaf(&SigningKey::from_slice(&[7u8; 32])?, 1_800_000_000, 1_800_086_400)?;
        let issuer = self_signed_leaf(&SigningKey::from_slice(&[8u8; 32])?, 1_700_000_000, 1_900_000_000)?;
        assert_eq!(
            leaf_validity(&[leaf, issuer])?,
            (
                UNIX_EPOCH + Duration::from_secs(1_800_000_000),
                UNIX_EPOCH + Duration::from_secs(1_800_086_400)
            )
        );
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    #[test]
    fn enrollment_leaf_must_match_the_pending_key() -> anyhow::Result<()> {
        let key = SigningKey::from_slice(&[7u8; 32])?;
        let leaf = self_signed_leaf(&key, 1_800_000_000, 1_800_086_400)?;
        assert!(validate_certificate_chain(std::slice::from_ref(&leaf), key.verifying_key()).is_ok());
        let other_key = SigningKey::from_slice(&[8u8; 32])?;
        assert_eq!(
            validate_certificate_chain(std::slice::from_ref(&leaf), other_key.verifying_key()),
            Err(ClientError::invalid_response("leaf key mismatch"))
        );
        assert_eq!(
            validate_certificate_chain(&[], key.verifying_key()),
            Err(ClientError::invalid_response("empty certificate chain"))
        );
        assert_eq!(
            validate_certificate_chain(&[leaf, "not base64".to_owned()], key.verifying_key()),
            Err(ClientError::invalid_response("invalid base64 certificate"))
        );
        Ok(())
    }

    /// An enrollment URL extension whose `extnValue` holds the DER `value`.
    fn enrollment_url_extension(value: &[u8]) -> Extension {
        Extension {
            extn_id: ENROLLMENT_URL_EXTENSION,
            critical: false,
            extn_value: OctetString::new(value).expect("extension value fits an OCTET STRING"),
        }
    }

    fn ia5(url: &str) -> Vec<u8> {
        Ia5StringRef::new(url)
            .and_then(|url| url.to_der())
            .expect("test URL is an IA5String")
    }

    /// An enrollment chain whose leaf carries `extensions`.
    fn enrollment_chain(extensions: Vec<Extension>) -> anyhow::Result<Vec<String>> {
        let leaf = leaf_with_extensions(
            &SigningKey::from_slice(&[7u8; 32])?,
            1_800_000_000,
            1_800_086_400,
            extensions,
        )?;
        let root = self_signed_leaf(&SigningKey::from_slice(&[8u8; 32])?, 1_700_000_000, 1_900_000_000)?;
        Ok(vec![leaf, root])
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[test]
    fn an_enrollment_leaf_naming_the_token_base_url_is_accepted() -> anyhow::Result<()> {
        let chain = enrollment_chain(vec![enrollment_url_extension(&ia5("https://example.test/dvls"))])?;
        assert_eq!(check_enrollment_url(&chain, "https://example.test/dvls"), Ok(()));
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[rstest]
    #[case::absent(Vec::new())]
    #[case::another_host(vec![enrollment_url_extension(&ia5("https://other.test/dvls"))])]
    #[case::another_path(vec![enrollment_url_extension(&ia5("https://example.test"))])]
    #[case::trailing_slash(vec![enrollment_url_extension(&ia5("https://example.test/dvls/"))])]
    #[case::host_case(vec![enrollment_url_extension(&ia5("https://EXAMPLE.test/dvls"))])]
    #[case::not_an_ia5_string(vec![enrollment_url_extension(
        &Utf8StringRef::new("https://example.test/dvls").and_then(|url| url.to_der()).expect("UTF8String")
    )])]
    // oracle: spec RFC 5280 §4.2
    #[case::twice(vec![
        enrollment_url_extension(&ia5("https://example.test/dvls")),
        enrollment_url_extension(&ia5("https://example.test/dvls")),
    ])]
    fn an_enrollment_leaf_not_naming_the_token_base_url_is_refused_as_permanent(
        #[case] extensions: Vec<Extension>,
    ) -> anyhow::Result<()> {
        let chain = enrollment_chain(extensions)?;
        assert_eq!(
            check_enrollment_url(&chain, "https://example.test/dvls"),
            Err(ClientError::Permanent(PermanentCode::AuthorityUrlMismatch))
        );
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §http-api
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
    #[test]
    fn joins_path_prefix_without_duplicate_slashes() {
        for (base, expected) in [
            (
                "https://example.test",
                "https://example.test/api/agent-identity/v1/enroll",
            ),
            (
                "https://example.test/",
                "https://example.test/api/agent-identity/v1/enroll",
            ),
            (
                "https://example.test//",
                "https://example.test/api/agent-identity/v1/enroll",
            ),
            (
                "https://example.test/mock",
                "https://example.test/mock/api/agent-identity/v1/enroll",
            ),
            (
                "https://example.test/mock/",
                "https://example.test/mock/api/agent-identity/v1/enroll",
            ),
            (
                "https://example.test/mock//",
                "https://example.test/mock/api/agent-identity/v1/enroll",
            ),
        ] {
            assert_eq!(operation_url(base, "enroll"), expected, "{base}");
        }
    }

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    #[test]
    fn joins_paths_onto_the_base_url_as_received() {
        assert_eq!(
            operation_url("https://EXAMPLE.test:443/Dv%20ls", "enroll"),
            "https://EXAMPLE.test:443/Dv%20ls/api/agent-identity/v1/enroll"
        );
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    #[test]
    fn classifies_only_valid_status_code_pairs() {
        let body =
            |code: &str| format!(r#"{{"error":"{code}","message":"text","server_time":"2026-09-24T12:00:00Z"}}"#);
        assert_eq!(
            classify_error(StatusCode::UNAUTHORIZED, body("token_expired").as_bytes(), None),
            ClientError::Permanent(PermanentCode::TokenExpired)
        );
        assert_eq!(
            classify_error(StatusCode::FORBIDDEN, body("identity_revoked").as_bytes(), None),
            ClientError::Terminal(TerminalCode::IdentityRevoked)
        );
        for (status, code, reason) in [
            (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                TransientReason::ServerCode("invalid_request".to_owned()),
            ),
            (
                StatusCode::UNAUTHORIZED,
                "signature_invalid",
                TransientReason::ServerCode("signature_invalid".to_owned()),
            ),
            (
                StatusCode::FORBIDDEN,
                "token_invalid",
                TransientReason::ServerCode("token_invalid".to_owned()),
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                "token_invalid",
                TransientReason::HttpStatus(429),
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "token_invalid",
                TransientReason::HttpStatus(503),
            ),
            (StatusCode::FOUND, "token_invalid", TransientReason::HttpStatus(302)),
            (
                StatusCode::BAD_REQUEST,
                "unrecognized",
                TransientReason::ServerCode("unrecognized".to_owned()),
            ),
        ] {
            assert_eq!(
                classify_error(status, body(code).as_bytes(), None),
                ClientError::Transient {
                    retry_after: None,
                    reason
                }
            );
        }
        assert_eq!(
            classify_error(StatusCode::BAD_REQUEST, b"bad JSON", Some(Duration::from_secs(5))),
            ClientError::Transient {
                retry_after: Some(Duration::from_secs(5)),
                reason: TransientReason::InvalidResponse("invalid error body")
            }
        );
        let suspicious = br#"{"error":"dvaet1.fake.secret","server_time":"2026-09-24T12:00:00Z"}"#;
        let error = classify_error(StatusCode::BAD_REQUEST, suspicious, None);
        assert_eq!(error, ClientError::invalid_response("invalid server error code"));
        // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Security invariants
        assert!(!error.to_string().contains("dvaet1"));
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    #[test]
    fn classifies_error_codes_when_message_is_absent_or_null() {
        let server_time = OffsetDateTime::parse("2026-09-24T12:00:00Z", &Rfc3339).expect("valid server time");
        for (status, code, expected) in [
            (
                StatusCode::UNAUTHORIZED,
                "token_invalid",
                ClientError::Permanent(PermanentCode::TokenInvalid),
            ),
            (
                StatusCode::FORBIDDEN,
                "token_exhausted",
                ClientError::Permanent(PermanentCode::TokenExhausted),
            ),
            (
                StatusCode::UNAUTHORIZED,
                "token_expired",
                ClientError::Permanent(PermanentCode::TokenExpired),
            ),
            (
                StatusCode::FORBIDDEN,
                "identity_revoked",
                ClientError::Terminal(TerminalCode::IdentityRevoked),
            ),
            (
                StatusCode::UNAUTHORIZED,
                "identity_unknown",
                ClientError::Terminal(TerminalCode::IdentityUnknown),
            ),
            (
                StatusCode::UNAUTHORIZED,
                "certificate_expired",
                ClientError::CertificateExpired,
            ),
            (
                StatusCode::UNAUTHORIZED,
                "clock_skew",
                ClientError::ClockSkew { server_time },
            ),
        ] {
            for message in ["", r#","message":null"#] {
                let body = format!(r#"{{"error":"{code}","server_time":"2026-09-24T12:00:00Z"{message}}}"#);
                assert_eq!(classify_error(status, body.as_bytes(), None), expected);
            }
        }
    }

    // oracle: spec RFC 9110 §10.2.3
    #[test]
    fn parses_retry_after_seconds_and_http_date() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(parse_retry_after(" 15 ", now), Some(Duration::from_secs(15)));
        assert_eq!(
            parse_retry_after(&httpdate::fmt_http_date(now + Duration::from_secs(10)), now),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            parse_retry_after(&httpdate::fmt_http_date(now - Duration::from_secs(10)), now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("never", now), None);
        // oracle: intent crates/agent-identity/INTENT.md §Schedules
        // The agent waits at least the delay the authority asks for and never longer than 1 h, so a delay too large to
        // represent must still ask for the full hour.
        assert!(
            parse_retry_after("18446744073709551616", now).is_some_and(|delay| delay >= Duration::from_secs(60 * 60))
        );
    }

    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §conventions
    #[test]
    fn accepts_null_optional_config_fields_without_losing_unknown_values() {
        let response: EnrollResponse = parse_response(
            br#"{"authority_id":"00000000-0000-4000-8000-000000000001","identity_id":"00000000-0000-4000-8000-000000000002","certificate_chain":[],"config":{"version":1,"revision":4,"agent_channel_url":null,"extra":true}}"#,
        )
        .expect("parse response");
        assert!(response.config["agent_channel_url"].is_null());
        assert_eq!(response.config["extra"], true);
        assert_eq!(response.config["revision"], 4);
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
    #[test]
    fn config_with_a_version_other_than_1_is_transient() {
        // `CONTRACT.agent-identity.md` §5.2: a config whose `version` is not 1 is a transient failure.
        assert_eq!(
            validate_config(&serde_json::json!({"version": 1, "revision": 1})),
            Ok(())
        );
        for config in [
            serde_json::json!({"version": 2, "revision": 1}),
            serde_json::json!({"version": 0, "revision": 1}),
            serde_json::json!({"version": "1", "revision": 1}),
            serde_json::json!({"revision": 1}),
        ] {
            assert!(
                matches!(validate_config(&config), Err(ClientError::Transient { .. })),
                "{config}"
            );
        }
    }

    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    #[rstest]
    #[tokio::test]
    async fn a_manual_proxy_of_an_unsupported_scheme_fails_the_request_without_connecting_directly(
        #[values(Request::Enroll, Request::CheckIn)] request: Request,
    ) -> anyhow::Result<()> {
        let authority = CountingListener::start().await?;

        let error = request
            .send(manual_proxy("ftp://127.0.0.1:1", &[])?, &authority)
            .await?;

        assert!(matches!(error, Some(ClientError::Transient { .. })), "{error:?}");
        assert_eq!(authority.connections(), 0);
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    #[rstest]
    #[case::http_host_outside_uri_syntax("http://pro{xy:3128")]
    #[case::socks_host_outside_uri_syntax("socks5://pro{xy:1080")]
    #[tokio::test]
    async fn a_manual_proxy_url_reqwest_cannot_read_fails_the_request_without_connecting_directly(
        #[case] proxy: &str,
        #[values(Request::Enroll, Request::CheckIn)] request: Request,
    ) -> anyhow::Result<()> {
        let authority = CountingListener::start().await?;

        let error = request.send(manual_proxy(proxy, &[])?, &authority).await?;

        assert!(matches!(error, Some(ClientError::Transient { .. })), "{error:?}");
        assert_eq!(authority.connections(), 0);
        Ok(())
    }

    fn unreadable_system_proxy(_: &Url) -> anyhow::Result<Option<String>> {
        anyhow::bail!("system proxy settings unreadable")
    }

    fn unparseable_system_proxy(_: &Url) -> anyhow::Result<Option<String>> {
        // The port is out of range.
        Ok(Some("http://proxy.test:99999".to_owned()))
    }

    fn unsupported_system_proxy(_: &Url) -> anyhow::Result<Option<String>> {
        Ok(Some("ftp://proxy.test:21".to_owned()))
    }

    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    #[rstest]
    #[case::detection_fails(unreadable_system_proxy)]
    #[case::unparseable_proxy(unparseable_system_proxy)]
    #[case::unsupported_scheme(unsupported_system_proxy)]
    #[tokio::test]
    async fn a_system_proxy_the_request_cannot_use_fails_it_without_connecting_directly(
        #[case] system_proxy: fn(&Url) -> anyhow::Result<Option<String>>,
        #[values(Request::Enroll, Request::CheckIn)] request: Request,
    ) -> anyhow::Result<()> {
        let authority = CountingListener::start().await?;
        let mut client = Client::new(ProxyConfig::System, None)?;
        client.system_proxy = system_proxy;

        let error = request.send_with(client, &authority).await?;

        assert!(matches!(error, Some(ClientError::Transient { .. })), "{error:?}");
        assert_eq!(authority.connections(), 0);
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    // oracle: reference reqwest 0.12.28 `IntoProxy`, which reads a proxy URL without a host as an `http://` URL
    #[tokio::test]
    async fn a_manual_proxy_without_a_scheme_carries_the_request_as_an_http_proxy() -> anyhow::Result<()> {
        let authority = CountingListener::start().await?;
        let proxy = CountingListener::start().await?;
        // A URL parser reads `localhost` here as the scheme, and the port as the path.
        let proxy_setting = format!("localhost:{}", proxy.port);

        // The proxy closes the connection, so the request fails once it reaches the proxy.
        Request::Enroll
            .send(manual_proxy(&proxy_setting, &[])?, &authority)
            .await?;

        assert!(0 < proxy.connections());
        assert_eq!(authority.connections(), 0);
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    // oracle: reference hyper-util 0.1.20 `parse_env_uri`, which lists the proxy schemes reqwest connects through
    #[rstest]
    #[case::http("http")]
    #[case::https("https")]
    #[case::socks4("socks4")]
    #[case::socks4a("socks4a")]
    #[case::socks5("socks5")]
    #[case::socks5h("socks5h")]
    #[tokio::test]
    async fn a_manual_proxy_of_each_supported_scheme_carries_the_request(#[case] scheme: &str) -> anyhow::Result<()> {
        let authority = CountingListener::start().await?;
        let proxy = CountingListener::start().await?;
        let proxy_url = format!("{scheme}://127.0.0.1:{}", proxy.port);

        // The proxy closes the connection, so the request fails once it reaches the proxy.
        Request::Enroll.send(manual_proxy(&proxy_url, &[])?, &authority).await?;

        assert!(0 < proxy.connections());
        assert_eq!(authority.connections(), 0);
        Ok(())
    }

    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    #[tokio::test]
    async fn an_authority_the_manual_proxy_settings_exclude_is_reached_directly() -> anyhow::Result<()> {
        let authority = CountingListener::start().await?;
        // A proxy the request can't use shows that the exclusion, not the proxy, decides the route.
        let proxy = manual_proxy("ftp://127.0.0.1:1", &["127.0.0.1"])?;

        // The authority closes the connection, so the request fails once it reaches the authority.
        Request::Enroll.send(proxy, &authority).await?;

        assert!(0 < authority.connections());
        Ok(())
    }

    #[derive(Clone, Copy, Debug)]
    enum Request {
        Enroll,
        CheckIn,
    }

    impl Request {
        /// Sends this request to `authority` through `proxy`, and returns its error.
        async fn send(self, proxy: ProxyConfig, authority: &CountingListener) -> anyhow::Result<Option<ClientError>> {
            self.send_with(Client::new(proxy, None)?, authority).await
        }

        /// Sends this request to `authority` with `client`, and returns its error.
        async fn send_with(self, client: Client, authority: &CountingListener) -> anyhow::Result<Option<ClientError>> {
            let key = TestKey(SigningKey::from_slice(&[7u8; 32])?);
            let error = match self {
                Self::Enroll => {
                    let bag = URL_SAFE_NO_PAD.encode(format!(r#"{{"u":"{}"}}"#, authority.base_url()));
                    let token = Token::parse(&format!("dvaet1.{bag}.{}", "A".repeat(43)))?;
                    client.enroll(&token, "csr", &Metadata::new(), &key).await.err()
                }
                Self::CheckIn => {
                    let signer = RequestSigner::new(Arc::new(key), b"leaf certificate");
                    client
                        .check_in(&authority.base_url(), &signer, &Metadata::new(), None)
                        .await
                        .err()
                }
            };
            Ok(error)
        }
    }

    struct TestKey(SigningKey);

    impl DeviceKey for TestKey {
        fn name(&self) -> &str {
            "test_key"
        }

        fn public_key(&self) -> VerifyingKey {
            *self.0.verifying_key()
        }

        fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
            signature::Signer::<Signature>::try_sign(&self.0, message)
        }
    }

    /// A loopback port that counts the TCP connections it receives and closes each one at once.
    struct CountingListener {
        port: u16,
        connections: Arc<AtomicUsize>,
    }

    impl CountingListener {
        async fn start() -> anyhow::Result<Self> {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            let connections = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&connections);
            tokio::spawn(async move {
                // Counting before the close orders the count before the error the client sees.
                while let Ok((stream, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
            });
            Ok(Self { port, connections })
        }

        fn base_url(&self) -> String {
            format!("https://127.0.0.1:{}", self.port)
        }

        fn connections(&self) -> usize {
            self.connections.load(Ordering::SeqCst)
        }
    }

    fn manual_proxy(proxy: &str, exclude: &[&str]) -> anyhow::Result<ProxyConfig> {
        Ok(ProxyConfig::Manual(ManualProxyConfig {
            all: Some(Url::parse(proxy)?),
            exclude: exclude.iter().map(|pattern| (*pattern).to_owned()).collect(),
            ..Default::default()
        }))
    }

    /// Counts the warnings logged.
    struct WarningCount(Arc<AtomicUsize>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarningCount {
        fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn without_a_proxy(automatic_detection: bool, configuration_script: bool) -> SystemProxySettings {
        SystemProxySettings {
            names_proxy: false,
            automatic_configuration: AutomaticConfiguration {
                automatic_detection,
                configuration_script,
            },
        }
    }

    /// Returns how many warnings the first identity request of a run and a later one log.
    fn warnings_of_two_requests(proxy: &ProxyConfig, settings: SystemProxySettings) -> usize {
        let warned = AtomicBool::new(false);
        let warnings = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(WarningCount(Arc::clone(&warnings)));

        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..2 {
                warn_on_automatic_configuration(&warned, proxy, || Ok(settings));
            }
        });

        warnings.load(Ordering::SeqCst)
    }

    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    #[rstest]
    #[case::automatic_detection(ProxyConfig::System, without_a_proxy(true, false), 1)]
    #[case::configuration_script(ProxyConfig::System, without_a_proxy(false, true), 1)]
    #[case::neither(ProxyConfig::System, without_a_proxy(false, false), 0)]
    #[case::proxy_off(ProxyConfig::Off, without_a_proxy(true, true), 0)]
    fn warns_once_per_run_that_system_mode_skips_automatic_proxy_configuration(
        #[case] proxy: ProxyConfig,
        #[case] settings: SystemProxySettings,
        #[case] expected_warnings: usize,
    ) {
        assert_eq!(warnings_of_two_requests(&proxy, settings), expected_warnings);
    }

    // oracle: intent crates/agent-identity/INTENT.md §Trust and transport
    #[test]
    fn a_user_proxy_silences_the_warning_about_a_stale_machine_automatic_configuration() {
        // The current user's settings name a proxy, which System mode uses without consulting the machine's settings,
        // so identity requests go through it although the machine's settings still enable a PAC script and automatic
        // detection.
        let settings = SystemProxySettings {
            names_proxy: true,
            automatic_configuration: AutomaticConfiguration {
                automatic_detection: true,
                configuration_script: true,
            },
        };
        assert_eq!(warnings_of_two_requests(&ProxyConfig::System, settings), 0);
    }
}
