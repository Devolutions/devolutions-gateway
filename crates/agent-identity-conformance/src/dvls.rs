//! DVLS's management API, which the mock replicates.
//!
//! Management APIs are product-specific, so tests reach an authority's only through the module for that authority.
//! Every route, header, field name, paging rule, enum spelling, status code and error body of DVLS's management API lives here, so tests depend only on the operations and records below.
//! DVLS's OpenAPI document for Agent Identity is the reference for all of them; `docs/agent-identity/INTENT.DVLS.md`, "Management API", holds the decisions behind them.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context as _, ensure};
use http::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::client::{Target, Token};
use crate::{Context, TargetKind};

const BASE_PATH: &str = "/api/v1/agent-identity";

/// The request header that carries the management API credential, a DVLS session token.
const CREDENTIAL_HEADER: &str = "tokenId";

/// The largest page of identities a listing returns.
pub(crate) const MAX_PAGE_SIZE: u64 = 100;

/// The largest page of enrollment tokens a listing returns.
pub(crate) const MAX_TOKEN_PAGE_SIZE: u64 = 500;

/// Why a test cannot apply to a target at all, as opposed to a fixture the run lacks.
///
/// DVLS has no mock controls, so a test that needs them never applies to it.
pub(crate) fn unsupported(kind: TargetKind, needs_mock_controls: bool) -> Option<&'static str> {
    (kind == TargetKind::Dvls && needs_mock_controls).then_some("DVLS has no mock controls")
}

/// The permissions that guard the management API's route groups.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Permission {
    View,
    Manage,
    Revoke,
    RotateRoot,
}

impl Permission {
    pub(crate) const ALL: [Self; 4] = [Self::View, Self::Manage, Self::Revoke, Self::RotateRoot];

    /// The name of this permission in a mock credential scope (`<admin-token>.<scope>`).
    const fn mock_scope(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Manage => "manage",
            Self::Revoke => "revoke",
            Self::RotateRoot => "rotate-root",
        }
    }
}

/// A valid credential without `missing`, or `None` when the run lacks that fixture.
///
/// The mock derives one holding every other permission from its admin token.
/// On DVLS, the `--unprivileged-admin-token` fixture lacks every permission, so it lacks `missing` too.
pub(crate) fn credential_lacking(ctx: &Context, missing: Permission) -> Option<String> {
    if !ctx.mock() {
        return ctx.unprivileged_admin_token.clone();
    }
    let scope = Permission::ALL
        .into_iter()
        .filter(|permission| *permission != missing)
        .map(Permission::mock_scope)
        .collect::<Vec<_>>()
        .join("+");
    Some(format!("{}.{scope}", ctx.target.admin_token))
}

/// How the management API refused a request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Refusal {
    /// The request is invalid.
    Invalid,
    /// The request carries no valid credential.
    Unauthenticated,
    /// The credential lacks the permission the request needs.
    Forbidden,
    /// The resource does not exist.
    NotFound,
    /// The request conflicts with the resource's state.
    Conflict,
    /// The request is valid but exceeds what the authority can carry out, such as a rotation deadline after the rotation maximum.
    Unprocessable,
    /// Any other unsuccessful HTTP status.
    Other(u16),
}

impl Refusal {
    const fn from_status(status: u16) -> Self {
        match status {
            400 => Self::Invalid,
            401 => Self::Unauthenticated,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            422 => Self::Unprocessable,
            _ => Self::Other(status),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the management API refused the request ({self:?})")
    }
}

impl std::error::Error for Refusal {}

/// The refusal that ended `result`; an error when the request succeeded or failed for another reason.
pub(crate) fn refusal<T>(result: anyhow::Result<T>) -> anyhow::Result<Refusal> {
    match result {
        Ok(_) => anyhow::bail!("the management API accepted a request it must refuse"),
        Err(error) => error.downcast::<Refusal>(),
    }
}

/// The refusal an unsuccessful `status` stands for, once its body is the error body the status documents.
///
/// A 400 carries a `PublicApiValidationError`, and every other documented refusal a `PublicApiError`.
fn refusal_from(status: u16, body: &[u8]) -> anyhow::Result<Refusal> {
    // The document's error bodies are objects whose members are all optional and limited to the schema's own:
    // `errors` is an array of field errors, and every other member is a string or null.
    fn conforms(value: &Value, members: &[&str]) -> bool {
        value.as_object().is_some_and(|object| {
            object.iter().all(|(name, member)| {
                members.contains(&name.as_str())
                    && match name.as_str() {
                        "errors" => member
                            .as_array()
                            .is_some_and(|errors| errors.iter().all(|error| conforms(error, &["field", "message"]))),
                        _ => member.is_null() || member.is_string(),
                    }
            })
        })
    }
    let refusal = Refusal::from_status(status);
    let body = || serde_json::from_slice::<Value>(body).ok();
    let (documented, schema) = match refusal {
        Refusal::Other(_) => return Ok(refusal),
        Refusal::Invalid => (
            body().is_some_and(|body| conforms(&body, &["errors"])),
            "PublicApiValidationError",
        ),
        _ => (
            body().is_some_and(|body| conforms(&body, &["message"])),
            "PublicApiError",
        ),
    };
    ensure!(documented, "HTTP {status} body is not a {schema}");
    Ok(refusal)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
pub(crate) enum TokenState {
    Active,
    Exhausted,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TokenRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(rename = "useCount")]
    pub(crate) used_count: u64,
    pub(crate) state: TokenState,
    #[serde(deserialize_with = "timestamp")]
    pub(crate) created_on: OffsetDateTime,
    #[serde(deserialize_with = "timestamp")]
    pub(crate) expires_on: OffsetDateTime,
    // The members below are only compared, so a record may omit them.
    #[serde(default)]
    max_uses: Option<u64>,
    #[serde(default)]
    created_by: Option<String>,
    #[serde(default)]
    friendly_name_format: Option<String>,
    #[serde(default)]
    config: Option<BTreeMap<String, String>>,
}

/// What a token creation request asks for.
pub(crate) struct TokenSpec {
    pub(crate) name: String,
    pub(crate) max_uses: u64,
    /// When the token stops enrolling devices; `None` leaves it to the authority's default.
    pub(crate) expires_on: Option<OffsetDateTime>,
    pub(crate) friendly_name_format: Option<String>,
    /// Product-specific config entries for the identities the token enrolls.
    pub(crate) config: Option<BTreeMap<String, String>>,
}

impl TokenSpec {
    /// A uniquely named token that expires `lifetime` from now.
    pub(crate) fn new(max_uses: u64, lifetime: Duration) -> anyhow::Result<Self> {
        Ok(Self {
            name: format!("conformance-{}", uuid::Uuid::new_v4()),
            max_uses,
            expires_on: Some(OffsetDateTime::now_utc() + time::Duration::try_from(lifetime)?),
            friendly_name_format: None,
            config: None,
        })
    }

    fn body(&self) -> anyhow::Result<Vec<u8>> {
        let mut body = json!({
            "name": self.name,
            "maxUses": self.max_uses,
        });
        if let Some(instant) = self.expires_on {
            body["expiresOn"] = json!(instant.format(&Rfc3339)?);
        }
        if let Some(format) = &self.friendly_name_format {
            body["friendlyNameFormat"] = json!(format);
        }
        if let Some(config) = &self.config {
            body["config"] = json!(config);
        }
        Ok(serde_json::to_vec(&body)?)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
pub(crate) enum IdentityStatus {
    Active,
    Grace,
    Expired,
    Revoked,
}

impl IdentityStatus {
    const fn query_value(self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Grace => "Grace",
            Self::Expired => "Expired",
            Self::Revoked => "Revoked",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
pub(crate) enum CertificateStatus {
    Pending,
    Current,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateRecord {
    pub(crate) thumbprint: String,
    /// Only compared, so a record may omit it.
    #[serde(default)]
    serial_number: Option<String>,
    #[serde(rename = "validFrom", deserialize_with = "timestamp")]
    pub(crate) not_before: OffsetDateTime,
    #[serde(rename = "validUntil", deserialize_with = "timestamp")]
    pub(crate) not_after: OffsetDateTime,
    /// The issuing root's thumbprint.
    #[serde(rename = "issuerThumbprint")]
    pub(crate) issuer: String,
    pub(crate) status: CertificateStatus,
}

/// The current certificate, as an identity's summary shows it.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub(crate) struct CurrentCertificate {
    #[serde(rename = "validUntil", deserialize_with = "timestamp")]
    pub(crate) not_after: OffsetDateTime,
    /// The issuing root's thumbprint.
    #[serde(rename = "issuerThumbprint")]
    pub(crate) issuer: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IdentityRecord {
    pub(crate) id: String,
    pub(crate) friendly_name: String,
    pub(crate) status: IdentityStatus,
    #[serde(rename = "isConnected")]
    pub(crate) connected: bool,
    /// A summary omits the keys it was not asked for, and the member when none remain.
    #[serde(default, deserialize_with = "null_as_default")]
    pub(crate) metadata: BTreeMap<String, String>,
    /// Every certificate issued to the identity; only the full view lists them.
    #[serde(default)]
    pub(crate) certificates: Option<Vec<CertificateRecord>>,
    #[serde(default)]
    pub(crate) certificate: Option<CurrentCertificate>,
    // The enrollment token members are only compared, so a record may omit them.
    #[serde(default)]
    enrollment_token_id: Option<String>,
    #[serde(default)]
    enrollment_token_name: Option<String>,
    /// When the identity was created; only the full view shows it.
    #[serde(rename = "createdOn", default, deserialize_with = "optional_timestamp")]
    pub(crate) created_at: Option<OffsetDateTime>,
    #[serde(rename = "lastSeenOn", default, deserialize_with = "optional_timestamp")]
    pub(crate) last_seen_at: Option<OffsetDateTime>,
    /// The request-renewal flag; a summary omits it, which reads as `false`.
    #[serde(rename = "isRenewalRequested", default, deserialize_with = "null_as_default")]
    pub(crate) renewal_requested: bool,
    #[serde(rename = "revokedOn", default, deserialize_with = "optional_timestamp")]
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

impl IdentityRecord {
    /// The identity's certificates; empty in a summary view.
    pub(crate) fn certificates(&self) -> &[CertificateRecord] {
        self.certificates.as_deref().unwrap_or_default()
    }

    pub(crate) fn certificate_with(&self, status: CertificateStatus) -> Option<&CertificateRecord> {
        self.certificates()
            .iter()
            .find(|certificate| certificate.status == status)
    }

    pub(crate) fn has_certificate(&self, thumbprint: &str, status: CertificateStatus) -> bool {
        self.certificates()
            .iter()
            .any(|certificate| certificate.thumbprint == thumbprint && certificate.status == status)
    }

    /// The thumbprint of the root that issued the current certificate.
    pub(crate) fn issuer(&self) -> Option<&str> {
        self.certificate.as_ref().map(|certificate| certificate.issuer.as_str())
    }

    /// The end of the current certificate's validity.
    pub(crate) fn not_after(&self) -> Option<OffsetDateTime> {
        self.certificate.as_ref().map(|certificate| certificate.not_after)
    }

    pub(crate) fn metadata_value(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(String::as_str)
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub(crate) struct Page<T> {
    #[serde(rename = "data")]
    pub(crate) items: Vec<T>,
    #[serde(rename = "currentPage")]
    pub(crate) number: u64,
    #[serde(rename = "pageSize")]
    pub(crate) size: u64,
    #[serde(rename = "totalCount")]
    pub(crate) total_count: u64,
    #[serde(rename = "totalPage")]
    pub(crate) total_pages: u64,
}

/// Which identities a listing returns, and how.
#[derive(Clone, Default)]
pub(crate) struct IdentityQuery {
    full: Option<bool>,
    metadata: Vec<String>,
    status: Option<IdentityStatus>,
    token_id: Option<String>,
    issuer: Option<String>,
    last_seen_to: Option<OffsetDateTime>,
    last_seen_from: Option<OffsetDateTime>,
    name_contains: Option<String>,
    page: Option<(u64, u64)>,
}

impl IdentityQuery {
    pub(crate) fn enrolled_with(token: &Token) -> Self {
        Self {
            token_id: Some(token.id.clone()),
            ..Self::default()
        }
    }

    /// Every field of each identity, including all its metadata and certificates.
    pub(crate) fn full(mut self) -> Self {
        self.full = Some(true);
        self
    }

    pub(crate) fn summary(mut self) -> Self {
        self.full = Some(false);
        self
    }

    /// Only these metadata keys in a summary.
    pub(crate) fn metadata(mut self, keys: &[&str]) -> Self {
        self.metadata = keys.iter().map(|key| (*key).to_owned()).collect();
        self
    }

    pub(crate) fn status(mut self, status: IdentityStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Identities whose current certificate the root with this thumbprint issued.
    pub(crate) fn issuer(mut self, thumbprint: &str) -> Self {
        self.issuer = Some(thumbprint.to_owned());
        self
    }

    /// Identities last seen at or before `instant`.
    pub(crate) fn last_seen_to(mut self, instant: OffsetDateTime) -> Self {
        self.last_seen_to = Some(instant);
        self
    }

    /// Identities last seen at or after `instant`.
    pub(crate) fn last_seen_from(mut self, instant: OffsetDateTime) -> Self {
        self.last_seen_from = Some(instant);
        self
    }

    /// Identities whose friendly name contains `text`, ignoring case.
    pub(crate) fn name_contains(mut self, text: &str) -> Self {
        self.name_contains = Some(text.to_owned());
        self
    }

    /// One page, counted from 1, of at most `size` identities.
    pub(crate) fn page(mut self, number: u64, size: u64) -> Self {
        self.page = Some((number, size));
        self
    }

    fn query_string(&self) -> anyhow::Result<String> {
        let (number, size) = self.page.unwrap_or((1, MAX_PAGE_SIZE));
        let mut parameters = vec![("pageNumber", number.to_string()), ("pageSize", size.to_string())];
        if let Some(full) = self.full {
            parameters.push(("view", if full { "Full" } else { "Summary" }.to_owned()));
        }
        for key in &self.metadata {
            parameters.push(("metadataKey", key.clone()));
        }
        if let Some(status) = self.status {
            parameters.push(("status", status.query_value().to_owned()));
        }
        if let Some(id) = &self.token_id {
            parameters.push(("enrollmentTokenId", id.clone()));
        }
        if let Some(issuer) = &self.issuer {
            parameters.push(("issuerThumbprint", issuer.clone()));
        }
        if let Some(instant) = self.last_seen_from {
            parameters.push(("lastSeenFrom", instant.format(&Rfc3339)?));
        }
        if let Some(instant) = self.last_seen_to {
            parameters.push(("lastSeenTo", instant.format(&Rfc3339)?));
        }
        if let Some(text) = &self.name_contains {
            parameters.push(("search", text.clone()));
        }
        Ok(parameters
            .iter()
            .map(|(name, value)| format!("{name}={}", percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&"))
    }
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-_.~:,".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
pub(crate) enum RotationPhase {
    Idle,
    Rotating,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RootSummary {
    pub(crate) thumbprint: String,
    // The validity members are only compared, so a summary may omit them.
    #[serde(default, deserialize_with = "optional_timestamp")]
    valid_from: Option<OffsetDateTime>,
    #[serde(default, deserialize_with = "optional_timestamp")]
    valid_until: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RotationStatus {
    pub(crate) phase: RotationPhase,
    /// Only compared, so a status may omit it.
    #[serde(default, deserialize_with = "optional_timestamp")]
    started_on: Option<OffsetDateTime>,
    #[serde(default)]
    pub(crate) old_root: Option<RootSummary>,
    #[serde(default)]
    pub(crate) new_root: Option<RootSummary>,
    #[serde(rename = "deadlineOn", default, deserialize_with = "optional_timestamp")]
    pub(crate) deadline: Option<OffsetDateTime>,
    /// Non-revoked identities that still hold an unexpired current or pending old-root certificate.
    #[serde(rename = "oldRootActiveIdentityCount")]
    pub(crate) active_identities_on_old_root: u64,
}

impl RotationStatus {
    pub(crate) fn rotating(&self) -> bool {
        self.phase == RotationPhase::Rotating
    }

    pub(crate) fn new_root(&self) -> anyhow::Result<&str> {
        Ok(&self.new_root.as_ref().context("rotation has no new root")?.thumbprint)
    }

    pub(crate) fn old_root(&self) -> anyhow::Result<&str> {
        Ok(&self.old_root.as_ref().context("rotation has no old root")?.thumbprint)
    }

    pub(crate) fn deadline(&self) -> anyhow::Result<OffsetDateTime> {
        self.deadline.context("rotation has no deadline")
    }
}

/// When a requested rotation must complete.
#[derive(Clone, Copy)]
pub(crate) enum RotationDeadline {
    /// The rotation maximum.
    Default,
    /// An emergency rotation.
    Now,
    At(OffsetDateTime),
}

impl RotationDeadline {
    fn body(self) -> anyhow::Result<Vec<u8>> {
        let body = match self {
            Self::Default => json!({}),
            // Any deadline at or before the authority's current time requests an emergency rotation.
            // An hour in the past stays at or before it despite clock skew or an advanced mock clock.
            Self::Now => json!({ "deadlineOn": (OffsetDateTime::now_utc() - time::Duration::HOUR).format(&Rfc3339)? }),
            Self::At(instant) => json!({ "deadlineOn": instant.format(&Rfc3339)? }),
        };
        Ok(serde_json::to_vec(&body)?)
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Settings {
    /// The `authority_id` agents receive at enrollment.
    pub(crate) authority_id: String,
    /// The administrator's switch for the agent channel.
    #[serde(rename = "isAgentChannelEnabled")]
    pub(crate) channel_enabled: bool,
    /// Whether the authority offers the agent channel: it is enabled and the hosting supports it.
    #[serde(rename = "isAgentChannelAvailable")]
    pub(crate) channel_available: bool,
    /// The lifetime of the certificates issued from now on.
    pub(crate) certificate_lifetime_days: u64,
    pub(crate) rotation_notifications_per_second: u64,
}

/// The settings a change sets; the others keep their value.
#[derive(Clone, Default)]
pub(crate) struct SettingsChange {
    pub(crate) channel_enabled: Option<bool>,
    pub(crate) certificate_lifetime_days: Option<u64>,
    pub(crate) rotation_notifications_per_second: Option<u64>,
}

impl SettingsChange {
    fn body(&self) -> anyhow::Result<Vec<u8>> {
        let mut body = json!({});
        if let Some(enabled) = self.channel_enabled {
            body["isAgentChannelEnabled"] = json!(enabled);
        }
        if let Some(days) = self.certificate_lifetime_days {
            body["certificateLifetimeDays"] = json!(days);
        }
        if let Some(rate) = self.rotation_notifications_per_second {
            body["rotationNotificationsPerSecond"] = json!(rate);
        }
        Ok(serde_json::to_vec(&body)?)
    }
}

/// One management API request, with the permission it requires.
pub(crate) struct Route {
    method: Method,
    path: String,
    body: Option<Vec<u8>>,
    success: u16,
    pub(crate) permission: Permission,
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {BASE_PATH}{}", self.method, self.path)
    }
}

/// Every management API route, acting on one token and one identity.
///
/// The token creation route asks for `create`, the rename route for `rename`, the rotation route for an emergency rotation, and the settings route turns the agent channel off.
/// When `inert` is set, the rotation request is malformed and the settings change is empty, so that neither can change the target even if authorization is broken.
pub(crate) fn routes(
    token_id: &str,
    identity_id: &str,
    create: &TokenSpec,
    rename: &str,
    inert: bool,
) -> anyhow::Result<Vec<Route>> {
    let token = format!("/enrollment-token/{token_id}");
    let identity = format!("/{identity_id}");
    let (rotation, settings) = if inert {
        (b"{".to_vec(), SettingsChange::default().body()?)
    } else {
        let settings = SettingsChange {
            channel_enabled: Some(false),
            ..SettingsChange::default()
        };
        (RotationDeadline::Now.body()?, settings.body()?)
    };
    let route = |method: Method, path: String, body: Option<Vec<u8>>, success: u16, permission: Permission| Route {
        method,
        path,
        body,
        success,
        permission,
    };
    Ok(vec![
        route(
            Method::POST,
            "/enrollment-token".to_owned(),
            Some(create.body()?),
            201,
            Permission::Manage,
        ),
        route(Method::GET, "/enrollment-token".to_owned(), None, 200, Permission::View),
        route(Method::GET, token.clone(), None, 200, Permission::View),
        route(Method::DELETE, token, None, 204, Permission::Manage),
        route(
            Method::GET,
            format!("?enrollmentTokenId={token_id}"),
            None,
            200,
            Permission::View,
        ),
        route(Method::GET, identity.clone(), None, 200, Permission::View),
        route(
            Method::PATCH,
            identity.clone(),
            Some(serde_json::to_vec(&json!({ "friendlyName": rename }))?),
            200,
            Permission::Manage,
        ),
        route(Method::DELETE, identity.clone(), None, 204, Permission::Manage),
        route(
            Method::POST,
            format!("{identity}/revoke"),
            None,
            204,
            Permission::Revoke,
        ),
        route(
            Method::POST,
            format!("{identity}/request-renewal"),
            None,
            202,
            Permission::Manage,
        ),
        route(Method::GET, "/rotation".to_owned(), None, 200, Permission::View),
        route(
            Method::POST,
            "/rotation".to_owned(),
            Some(rotation),
            202,
            Permission::RotateRoot,
        ),
        route(Method::GET, "/settings".to_owned(), None, 200, Permission::View),
        route(
            Method::PATCH,
            "/settings".to_owned(),
            Some(settings),
            200,
            Permission::Manage,
        ),
    ])
}

/// The management API of one target, called with one credential.
pub(crate) struct Management<'a> {
    target: &'a Target,
    credential: Option<&'a str>,
}

impl<'a> Management<'a> {
    pub(crate) fn new(target: &'a Target, credential: Option<&'a str>) -> Self {
        Self { target, credential }
    }

    /// Sends a request and returns its JSON body, or the refusal when the status is not `success`.
    async fn request(&self, method: Method, path: &str, body: Option<&[u8]>, success: u16) -> anyhow::Result<Value> {
        let mut request = self
            .target
            .http
            .request(method.clone(), format!("{}{BASE_PATH}{path}", self.target.base_url));
        if let Some(credential) = self.credential {
            request = request.header(CREDENTIAL_HEADER, credential);
        }
        if let Some(body) = body {
            request = request
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request.send().await.with_context(|| format!("send {method} {path}"))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .with_context(|| format!("read the {method} {path} response"))?;
        if status != success {
            ensure!(
                !(200..300).contains(&status),
                "{method} {path} succeeded with HTTP {status} instead of {success}"
            );
            let refusal = refusal_from(status, &bytes).with_context(|| format!("{method} {path} refusal"))?;
            return Err(refusal.into());
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).with_context(|| format!("decode the {method} {path} response"))
    }

    async fn fetch<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        success: u16,
    ) -> anyhow::Result<T> {
        let value = self.request(method.clone(), path, body, success).await?;
        serde_json::from_value(value).with_context(|| format!("unexpected {method} {path} response"))
    }

    /// Sends `route` and succeeds only when the management API performs it.
    pub(crate) async fn call(&self, route: &Route) -> anyhow::Result<()> {
        self.request(route.method.clone(), &route.path, route.body.as_deref(), route.success)
            .await
            .map(drop)
    }

    pub(crate) async fn create_token(
        &self,
        max_uses: u64,
        lifetime: Duration,
        friendly_name_format: Option<&str>,
    ) -> anyhow::Result<Token> {
        let mut spec = TokenSpec::new(max_uses, lifetime)?;
        spec.friendly_name_format = friendly_name_format.map(str::to_owned);
        self.create_token_from(&spec).await
    }

    pub(crate) async fn create_token_from(&self, spec: &TokenSpec) -> anyhow::Result<Token> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Created {
            token: String,
            enrollment_token: CreatedRecord,
        }
        #[derive(Deserialize)]
        struct CreatedRecord {
            id: String,
        }
        let created: Created = self
            .fetch(Method::POST, "/enrollment-token", Some(&spec.body()?), 201)
            .await?;
        Ok(Token {
            text: created.token,
            id: created.enrollment_token.id,
        })
    }

    pub(crate) async fn token(&self, id: &str) -> anyhow::Result<TokenRecord> {
        self.fetch(Method::GET, &format!("/enrollment-token/{id}"), None, 200)
            .await
    }

    /// Whether the token's record holds its secret text anywhere, which only token creation may return.
    pub(crate) async fn token_discloses_secret(&self, token: &Token) -> anyhow::Result<bool> {
        let (_, secret) = token.text.rsplit_once('.').context("token has no secret")?;
        let record = self
            .request(Method::GET, &format!("/enrollment-token/{}", token.id), None, 200)
            .await?;
        Ok(contains_text(&record, secret))
    }

    /// One page, counted from 1, of at most `size` tokens.
    pub(crate) async fn tokens(&self, number: u64, size: u64) -> anyhow::Result<Page<TokenRecord>> {
        self.fetch(
            Method::GET,
            &format!("/enrollment-token?pageNumber={number}&pageSize={size}"),
            None,
            200,
        )
        .await
    }

    /// Every token, walking all pages.
    pub(crate) async fn all_tokens(&self) -> anyhow::Result<Vec<TokenRecord>> {
        let mut tokens = Vec::new();
        for number in 1.. {
            let page = self.tokens(number, MAX_TOKEN_PAGE_SIZE).await?;
            tokens.extend(page.items);
            if number >= page.total_pages {
                break;
            }
        }
        Ok(tokens)
    }

    pub(crate) async fn delete_token(&self, id: &str) -> anyhow::Result<()> {
        self.request(Method::DELETE, &format!("/enrollment-token/{id}"), None, 204)
            .await
            .map(drop)
    }

    /// The full view of one identity.
    pub(crate) async fn identity(&self, id: &str) -> anyhow::Result<IdentityRecord> {
        let path = format!("/{id}");
        let value = self.request(Method::GET, &path, None, 200).await?;
        for name in [
            "certificates",
            "enrollmentTokenId",
            "enrollmentTokenName",
            "createdOn",
            "isRenewalRequested",
        ] {
            ensure!(
                value.get(name).is_some_and(|field| !field.is_null()),
                "full identity record omits {name}"
            );
        }
        serde_json::from_value(value).with_context(|| format!("unexpected GET {path} response"))
    }

    /// The full view of one identity, or `None` when it does not exist.
    pub(crate) async fn find_identity(&self, id: &str) -> anyhow::Result<Option<IdentityRecord>> {
        match self.identity(id).await {
            Ok(record) => Ok(Some(record)),
            Err(error) => match error.downcast::<Refusal>()? {
                Refusal::NotFound => Ok(None),
                other => Err(other.into()),
            },
        }
    }

    pub(crate) async fn identities(&self, query: &IdentityQuery) -> anyhow::Result<Page<IdentityRecord>> {
        self.fetch(Method::GET, &format!("?{}", query.query_string()?), None, 200)
            .await
    }

    /// Every identity `query` selects, walking all pages and checking that they agree with the reported total.
    pub(crate) async fn all_identities(&self, query: &IdentityQuery) -> anyhow::Result<Vec<IdentityRecord>> {
        let mut identities: Vec<IdentityRecord> = Vec::new();
        for number in 1.. {
            let page = self.identities(&query.clone().page(number, MAX_PAGE_SIZE)).await?;
            for identity in page.items {
                ensure!(
                    identities.iter().all(|seen| seen.id != identity.id),
                    "identity listing repeated an identity ID"
                );
                identities.push(identity);
            }
            if number >= page.total_pages {
                ensure!(
                    identities.len() as u64 == page.total_count,
                    "identity listing count disagrees with all pages"
                );
                break;
            }
        }
        Ok(identities)
    }

    /// How many identities `token` enrolled that still exist.
    pub(crate) async fn identity_count(&self, token: &Token) -> anyhow::Result<u64> {
        Ok(self.identities(&IdentityQuery::enrolled_with(token)).await?.total_count)
    }

    pub(crate) async fn rename(&self, id: &str, friendly_name: &str) -> anyhow::Result<IdentityRecord> {
        let body = serde_json::to_vec(&json!({ "friendlyName": friendly_name }))?;
        self.fetch(Method::PATCH, &format!("/{id}"), Some(&body), 200).await
    }

    pub(crate) async fn revoke(&self, id: &str) -> anyhow::Result<()> {
        self.request(Method::POST, &format!("/{id}/revoke"), None, 204)
            .await
            .map(drop)
    }

    pub(crate) async fn delete_identity(&self, id: &str) -> anyhow::Result<()> {
        self.request(Method::DELETE, &format!("/{id}"), None, 204)
            .await
            .map(drop)
    }

    pub(crate) async fn request_renewal(&self, id: &str) -> anyhow::Result<()> {
        self.request(Method::POST, &format!("/{id}/request-renewal"), None, 202)
            .await
            .map(drop)
    }

    pub(crate) async fn rotation(&self) -> anyhow::Result<RotationStatus> {
        self.fetch(Method::GET, "/rotation", None, 200).await
    }

    pub(crate) async fn rotate(&self, deadline: RotationDeadline) -> anyhow::Result<RotationStatus> {
        self.fetch(Method::POST, "/rotation", Some(&deadline.body()?), 202)
            .await
    }

    pub(crate) async fn settings(&self) -> anyhow::Result<Settings> {
        self.fetch(Method::GET, "/settings", None, 200).await
    }

    /// Applies `change` and returns the resulting settings.
    pub(crate) async fn change_settings(&self, change: &SettingsChange) -> anyhow::Result<Settings> {
        self.fetch(Method::PATCH, "/settings", Some(&change.body()?), 200).await
    }
}

fn timestamp<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OffsetDateTime, D::Error> {
    let text = String::deserialize(deserializer)?;
    OffsetDateTime::parse(&text, &Rfc3339).map_err(serde::de::Error::custom)
}

fn optional_timestamp<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|text| OffsetDateTime::parse(&text, &Rfc3339).map_err(serde::de::Error::custom))
        .transpose()
}

/// Reads a nullable member, so that `null` means the same as an absent member.
fn null_as_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(deserializer: D) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn contains_text(value: &Value, text: &str) -> bool {
    match value {
        Value::String(value) => value.contains(text),
        Value::Array(items) => items.iter().any(|item| contains_text(item, text)),
        Value::Object(members) => members
            .iter()
            .any(|(name, member)| name.contains(text) || contains_text(member, text)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Value {
        json!({
            "id": "identity-id",
            "friendlyName": "test",
            "status": "Active",
            "isConnected": false,
            "metadata": { "hostname": "test" },
            "certificates": [],
            "enrollmentTokenId": "token-id",
            "enrollmentTokenName": "test",
            "createdOn": "2026-09-25T12:00:00Z",
            "isRenewalRequested": false,
            "certificate": { "issuerThumbprint": "root-id", "validUntil": "2026-12-24T12:00:00Z" }
        })
    }

    #[test]
    fn records_ignore_unknown_fields_and_treat_null_optional_fields_as_absent() -> anyhow::Result<()> {
        let record: IdentityRecord = serde_json::from_value(identity())?;
        let mut noisy = identity();
        noisy["request_id"] = json!("different");
        noisy["certificate"]["request_id"] = json!("different");
        noisy["lastSeenOn"] = Value::Null;
        noisy["revokedOn"] = Value::Null;
        ensure!(
            serde_json::from_value::<IdentityRecord>(noisy)? == record,
            "unknown or null optional identity fields changed the record"
        );
        let mut no_certificate = identity();
        no_certificate
            .as_object_mut()
            .context("identity fixture must be an object")?
            .remove("certificate");
        let mut null_certificate = no_certificate.clone();
        null_certificate["certificate"] = Value::Null;
        ensure!(
            serde_json::from_value::<IdentityRecord>(no_certificate)?
                == serde_json::from_value::<IdentityRecord>(null_certificate)?,
            "null optional identity certificate was not treated as absent"
        );
        // A summary omits the metadata and the renewal flag; the document declares both nullable.
        let mut summary = identity();
        let members = summary.as_object_mut().context("identity fixture must be an object")?;
        members.remove("metadata");
        members.remove("isRenewalRequested");
        let mut null_summary = identity();
        null_summary["metadata"] = Value::Null;
        null_summary["isRenewalRequested"] = Value::Null;
        let summary: IdentityRecord = serde_json::from_value(summary)?;
        ensure!(
            summary.metadata.is_empty()
                && !summary.renewal_requested
                && serde_json::from_value::<IdentityRecord>(null_summary)? == summary,
            "null metadata or renewal flag was not treated as absent"
        );
        let rotation: RotationStatus = serde_json::from_value(json!({
            "phase": "Idle",
            "oldRootActiveIdentityCount": 0,
            "request_id": "different",
            "startedOn": null,
            "deadlineOn": null,
            "oldRoot": null,
            "newRoot": null
        }))?;
        ensure!(
            !rotation.rotating() && rotation.deadline.is_none() && rotation.old_root.is_none(),
            "null optional rotation fields were not treated as absent"
        );
        Ok(())
    }

    #[test]
    fn secret_disclosure_is_found_in_member_names_and_values_but_not_in_redactions() {
        let secret = "s3cr3t-text";
        let record = |extra: Value| {
            let mut record = json!({ "id": "token-id", "name": "test", "hint": "s3c…" });
            record["nested"] = extra;
            record
        };
        assert!(contains_text(
            &record(json!([{ "value": "dvaet1.bag.s3cr3t-text" }])),
            secret
        ));
        assert!(contains_text(
            &record(json!({ "dvaet1.bag.s3cr3t-text": null })),
            secret
        ));
        assert!(!contains_text(&record(json!({ "token": "dvaet1.bag.****" })), secret));
    }

    #[test]
    fn records_reject_null_or_malformed_required_fields() {
        for (name, value) in [
            ("status", Value::Null),
            ("status", json!("active")),
            ("isConnected", Value::Null),
            ("createdOn", json!("not a timestamp")),
            ("lastSeenOn", json!(123)),
        ] {
            let mut record = identity();
            record[name] = value.clone();
            assert!(
                serde_json::from_value::<IdentityRecord>(record).is_err(),
                "{name} = {value} was accepted"
            );
        }
        assert!(
            serde_json::from_value::<RotationStatus>(json!({ "phase": null, "oldRootActiveIdentityCount": 0 }))
                .is_err(),
            "explicit null rotation phase was accepted"
        );
    }

    #[test]
    fn refusals_require_the_documented_error_body() {
        // The document: 400 carries a PublicApiValidationError, and 401, 403, 404, 409 and 422 a PublicApiError.
        // Every member of each schema is optional, its messages and fields are nullable, and it admits no other member.
        for (status, body, expected) in [
            (
                400,
                r#"{"errors":[{"field":"maxUses","message":"too small"}]}"#,
                Some(Refusal::Invalid),
            ),
            (
                400,
                r#"{"errors":[{"field":null,"message":"malformed"}]}"#,
                Some(Refusal::Invalid),
            ),
            (
                400,
                r#"{"errors":[{"field":"expiresOn","message":null}]}"#,
                Some(Refusal::Invalid),
            ),
            (400, r#"{"errors":[{}]}"#, Some(Refusal::Invalid)),
            (400, "{}", Some(Refusal::Invalid)),
            (400, r#"{"message":"invalid"}"#, None),
            (400, r#"{"errors":null}"#, None),
            (400, r#"{"errors":[{"field":1,"message":"wrong type"}]}"#, None),
            (400, r#"{"errors":["not an object"]}"#, None),
            (409, r#"{"message":"rotation in progress"}"#, Some(Refusal::Conflict)),
            (409, r#"{"message":null}"#, Some(Refusal::Conflict)),
            (404, "{}", Some(Refusal::NotFound)),
            (422, r#"{"message":"deadline too late"}"#, Some(Refusal::Unprocessable)),
            (409, r#"{"message":42}"#, None),
            (409, r#"["not an object"]"#, None),
            (403, r#"{"errors":[{"field":null,"message":"forbidden"}]}"#, None),
            (401, "", None),
        ] {
            assert_eq!(
                refusal_from(status, body.as_bytes()).ok(),
                expected,
                "HTTP {status} with {body:?}"
            );
        }
    }

    #[test]
    fn identity_query_repeats_metadata_keys() -> anyhow::Result<()> {
        // The document's example for `metadataKey`: "?metadataKey=hostname&metadataKey=os_name".
        let query = IdentityQuery::default()
            .metadata(&["hostname", "os_name"])
            .query_string()?;
        assert!(query.contains("metadataKey=hostname&metadataKey=os_name"), "{query}");
        Ok(())
    }
}
