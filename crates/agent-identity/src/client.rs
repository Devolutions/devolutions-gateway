use std::fmt;
use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_identity_httpsig::{RequestSigner, Tag};
use agent_identity_keys::IdentityKey;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use camino::Utf8Path;
use der::{Decode as _, Encode as _};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::EncodePublicKey as _;
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;
use uuid::Uuid;
use x509_cert::Certificate;

use crate::metadata::Metadata;
use crate::token::Token;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub type ClientResult<T> = Result<T, ClientError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermanentCode {
    TokenInvalid,
    TokenExhausted,
    TokenExpired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalCode {
    DeviceRevoked,
    DeviceUnknown,
}

impl PermanentCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenInvalid => "token_invalid",
            Self::TokenExhausted => "token_exhausted",
            Self::TokenExpired => "token_expired",
        }
    }
}

impl TerminalCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceRevoked => "device_revoked",
            Self::DeviceUnknown => "device_unknown",
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
    http: reqwest::Client,
}

#[derive(Deserialize)]
pub struct EnrollResponse {
    #[serde(deserialize_with = "canonical_uuid")]
    pub authority_id: Uuid,
    #[serde(deserialize_with = "canonical_uuid")]
    pub device_id: Uuid,
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
    pub fn new(extra_trusted_root: Option<&Utf8Path>) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            // Disable the bundled WebPKI roots, then restore only the OS roots.
            .tls_built_in_root_certs(false)
            .tls_built_in_native_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30));
        if let Some(path) = extra_trusted_root {
            let pem = std::fs::read(path)?;
            let roots: Vec<_> = rustls_pemfile::certs(&mut Cursor::new(&pem)).collect::<std::io::Result<_>>()?;
            anyhow::ensure!(!roots.is_empty(), "extra trusted root contains no certificates");
            for root in roots {
                builder = builder.add_root_certificate(reqwest::Certificate::from_der(root.as_ref())?);
            }
        }
        Ok(Self { http: builder.build()? })
    }

    pub async fn enroll(
        &self,
        token: &Token,
        csr_der: &str,
        metadata: &Metadata,
        key: &dyn IdentityKey,
    ) -> ClientResult<EnrollResponse> {
        let url = operation_url(token.base_url(), "enroll")?;
        let body = serde_json::to_vec(&CsrRequest { csr: csr_der, metadata })
            .map_err(|_| ClientError::local("encode enroll request"))?;
        let request = self
            .http
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
        if response
            .config
            .as_object()
            .and_then(|config| config.get("revision"))
            .and_then(Value::as_u64)
            .is_none()
        {
            return Err(ClientError::invalid_response("missing config revision"));
        }
        Ok(response)
    }

    pub async fn renew(
        &self,
        base_url: &Url,
        signer: &RequestSigner,
        csr_der: &str,
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
        validate_chain_der(&response.certificate_chain)?;
        Ok(response)
    }

    pub async fn confirm(
        &self,
        base_url: &Url,
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
        base_url: &Url,
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
        parse_response(&response)
    }

    async fn signed_post(
        &self,
        base_url: &Url,
        operation: &str,
        tag: Tag,
        signer: &RequestSigner,
        body: &[u8],
        clock_offset_secs: Option<i64>,
    ) -> ClientResult<(StatusCode, Vec<u8>)> {
        let url = operation_url(base_url, operation)?;
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
            .http
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

fn operation_url(base_url: &Url, operation: &str) -> ClientResult<Url> {
    let mut url = base_url.clone();
    let mut segments = url
        .path_segments_mut()
        .map_err(|()| ClientError::local("invalid authority URL"))?;
    segments
        .pop_if_empty()
        .push("api")
        .push("agent-identity")
        .push("v1")
        .push(operation);
    drop(segments);
    Ok(url)
}

fn parse_response<T: DeserializeOwned>(body: &[u8]) -> ClientResult<T> {
    serde_json::from_slice(body).map_err(|_| ClientError::invalid_response("invalid JSON response"))
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
        (StatusCode::FORBIDDEN, "device_revoked") => ClientError::Terminal(TerminalCode::DeviceRevoked),
        (StatusCode::UNAUTHORIZED, "device_unknown") => ClientError::Terminal(TerminalCode::DeviceUnknown),
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
        value.parse().ok().map(Duration::from_secs)
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
    use p256::ecdsa::{DerSignature, SigningKey};
    use spki::SubjectPublicKeyInfoOwned;
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder as _, CertificateBuilder};
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    use super::*;

    struct TestProfile;

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
            Ok(Vec::new())
        }
    }

    #[test]
    fn enrollment_leaf_must_match_the_pending_key() -> anyhow::Result<()> {
        let key = SigningKey::from_slice(&[7u8; 32])?;
        let spki = key.verifying_key().to_public_key_der()?;
        let spki = SubjectPublicKeyInfoOwned::try_from(spki.as_bytes())?;
        let before = Time::try_from(UNIX_EPOCH + Duration::from_secs(1_800_000_000))?;
        let after = Time::try_from(UNIX_EPOCH + Duration::from_secs(1_800_086_400))?;
        let builder = CertificateBuilder::new(
            TestProfile,
            SerialNumber::from(1u64),
            Validity::new(before, after),
            spki,
        )?;
        let certificate = builder.build::<_, DerSignature>(&key)?;
        let leaf = STANDARD.encode(certificate.to_der()?);
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
                "https://example.test/mock",
                "https://example.test/mock/api/agent-identity/v1/enroll",
            ),
            (
                "https://example.test/mock/",
                "https://example.test/mock/api/agent-identity/v1/enroll",
            ),
        ] {
            let base = Url::parse(base).expect("valid test URL");
            assert_eq!(operation_url(&base, "enroll").expect("join URL").as_str(), expected);
        }
    }

    #[test]
    fn classifies_only_valid_status_code_pairs() {
        let body =
            |code: &str| format!(r#"{{"error":"{code}","message":"text","server_time":"2026-09-24T12:00:00Z"}}"#);
        assert_eq!(
            classify_error(StatusCode::UNAUTHORIZED, body("token_expired").as_bytes(), None),
            ClientError::Permanent(PermanentCode::TokenExpired)
        );
        assert_eq!(
            classify_error(StatusCode::FORBIDDEN, body("device_revoked").as_bytes(), None),
            ClientError::Terminal(TerminalCode::DeviceRevoked)
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
        assert!(!error.to_string().contains("dvaet1"));
    }

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
                "device_revoked",
                ClientError::Terminal(TerminalCode::DeviceRevoked),
            ),
            (
                StatusCode::UNAUTHORIZED,
                "device_unknown",
                ClientError::Terminal(TerminalCode::DeviceUnknown),
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
    }

    #[test]
    fn accepts_null_optional_config_fields_without_losing_unknown_values() {
        let response: EnrollResponse = parse_response(
            br#"{"authority_id":"00000000-0000-4000-8000-000000000001","device_id":"00000000-0000-4000-8000-000000000002","certificate_chain":[],"config":{"version":1,"revision":4,"agent_channel_url":null,"extra":true}}"#,
        )
        .expect("parse response");
        assert!(response.config["agent_channel_url"].is_null());
        assert_eq!(response.config["extra"], true);
        assert_eq!(response.config["revision"], 4);
    }
}
