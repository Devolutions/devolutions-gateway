//! DVLS's management API, which the mock replicates.
//!
//! Management APIs are product-specific, so tests reach an authority's only through the module for that authority.
//! Every route, field name, paging rule, enum spelling and status code of DVLS's management API lives here, so tests depend only on the operations and records below.
//! `docs/agent-identity/INTENT.DVLS.md`, "Management API", holds the decisions behind them.

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

const BASE_PATH: &str = "/api/v3/agent-identity";

/// The largest page a listing returns.
pub(crate) const MAX_PAGE_SIZE: u64 = 100;

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

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
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
    pub(crate) used_count: u64,
    pub(crate) state: TokenState,
    // The members below are only compared, so a record may omit them.
    #[serde(default)]
    max_uses: Option<u64>,
    #[serde(default, deserialize_with = "optional_timestamp")]
    expires_at: Option<OffsetDateTime>,
    #[serde(default, deserialize_with = "optional_timestamp")]
    created_at: Option<OffsetDateTime>,
    #[serde(default)]
    created_by: Option<Value>,
    #[serde(default)]
    friendly_name_format: Option<String>,
    #[serde(default)]
    config: Option<Value>,
}

/// What a token creation request asks for.
pub(crate) struct TokenSpec {
    pub(crate) name: String,
    pub(crate) max_uses: u64,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) friendly_name_format: Option<String>,
    pub(crate) config: Option<Value>,
}

impl TokenSpec {
    /// A uniquely named token that expires `lifetime` from now.
    pub(crate) fn new(max_uses: u64, lifetime: Duration) -> anyhow::Result<Self> {
        Ok(Self {
            name: format!("conformance-{}", uuid::Uuid::new_v4()),
            max_uses,
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(i64::try_from(lifetime.as_secs())?),
            friendly_name_format: None,
            config: None,
        })
    }

    fn body(&self) -> anyhow::Result<Vec<u8>> {
        let mut body = json!({
            "name": self.name,
            "maxUses": self.max_uses,
            "expiresAt": self.expires_at.format(&Rfc3339)?,
        });
        if let Some(format) = &self.friendly_name_format {
            body["friendlyNameFormat"] = json!(format);
        }
        if let Some(config) = &self.config {
            body["config"] = config.clone();
        }
        Ok(serde_json::to_vec(&body)?)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum IdentityStatus {
    Active,
    Grace,
    Expired,
    Revoked,
}

impl IdentityStatus {
    const fn query_value(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
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
    #[serde(deserialize_with = "timestamp")]
    pub(crate) not_before: OffsetDateTime,
    #[serde(deserialize_with = "timestamp")]
    pub(crate) not_after: OffsetDateTime,
    /// The issuing root's thumbprint.
    pub(crate) issuer: String,
    pub(crate) status: CertificateStatus,
}

/// The current certificate, as an identity's summary shows it.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CurrentCertificate {
    #[serde(deserialize_with = "timestamp")]
    pub(crate) not_after: OffsetDateTime,
    /// The issuing root's thumbprint.
    pub(crate) issuer: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub(crate) struct TokenReference {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IdentityRecord {
    pub(crate) id: String,
    pub(crate) friendly_name: String,
    pub(crate) status: IdentityStatus,
    pub(crate) connected: bool,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, String>,
    /// Every certificate issued to the identity; only the full view lists them.
    #[serde(default)]
    pub(crate) certificates: Option<Vec<CertificateRecord>>,
    #[serde(default)]
    pub(crate) certificate: Option<CurrentCertificate>,
    #[serde(default)]
    pub(crate) enrollment_token: Option<TokenReference>,
    /// When the identity was created; only the full view shows it.
    #[serde(default, deserialize_with = "optional_timestamp")]
    pub(crate) created_at: Option<OffsetDateTime>,
    #[serde(default, deserialize_with = "optional_timestamp")]
    pub(crate) last_seen_at: Option<OffsetDateTime>,
    /// The request-renewal flag; a summary omits it, which reads as `false`.
    #[serde(default)]
    pub(crate) renewal_requested: bool,
    #[serde(default, deserialize_with = "optional_timestamp")]
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
    #[serde(rename = "totalPages")]
    pub(crate) total_pages: u64,
}

/// Which identities a listing returns, and how.
#[derive(Clone, Default)]
pub(crate) struct IdentityQuery {
    full: Option<bool>,
    metadata: Option<Vec<String>>,
    status: Option<IdentityStatus>,
    token_id: Option<String>,
    issuer: Option<String>,
    last_seen_before: Option<OffsetDateTime>,
    last_seen_after: Option<OffsetDateTime>,
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
        self.metadata = Some(keys.iter().map(|key| (*key).to_owned()).collect());
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

    pub(crate) fn last_seen_before(mut self, instant: OffsetDateTime) -> Self {
        self.last_seen_before = Some(instant);
        self
    }

    pub(crate) fn last_seen_after(mut self, instant: OffsetDateTime) -> Self {
        self.last_seen_after = Some(instant);
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
            parameters.push(("view", if full { "full" } else { "summary" }.to_owned()));
        }
        if let Some(keys) = &self.metadata {
            parameters.push(("metadata", keys.join(",")));
        }
        if let Some(status) = self.status {
            parameters.push(("status", status.query_value().to_owned()));
        }
        if let Some(id) = &self.token_id {
            parameters.push(("enrollmentTokenId", id.clone()));
        }
        if let Some(issuer) = &self.issuer {
            parameters.push(("issuer", issuer.clone()));
        }
        if let Some(instant) = self.last_seen_before {
            parameters.push(("lastSeenBefore", instant.format(&Rfc3339)?));
        }
        if let Some(instant) = self.last_seen_after {
            parameters.push(("lastSeenAfter", instant.format(&Rfc3339)?));
        }
        if let Some(text) = &self.name_contains {
            parameters.push(("q", text.clone()));
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
#[serde(rename_all = "lowercase")]
pub(crate) enum RotationPhase {
    Idle,
    Rotating,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RootSummary {
    pub(crate) thumbprint: String,
    /// Only compared, so a summary may omit it.
    #[serde(default, deserialize_with = "optional_timestamp")]
    not_after: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RotationStatus {
    pub(crate) phase: RotationPhase,
    #[serde(default)]
    pub(crate) old_root: Option<RootSummary>,
    #[serde(default)]
    pub(crate) new_root: Option<RootSummary>,
    #[serde(default, deserialize_with = "optional_timestamp")]
    pub(crate) deadline: Option<OffsetDateTime>,
    /// Non-revoked identities that still hold an unexpired current or pending old-root certificate.
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
            Self::Now => json!({ "deadline": "now" }),
            Self::At(instant) => json!({ "deadline": instant.format(&Rfc3339)? }),
        };
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
        write!(f, "{} {}", self.method, self.path)
    }
}

/// Every management API route, acting on one token and one identity.
///
/// The token creation route asks for `create`, the rename route for `rename`, and the rotation route for an emergency rotation.
/// When `inert_rotation` is set, the rotation request is malformed so that it cannot rotate the target even if authorization is broken.
pub(crate) fn routes(
    token_id: &str,
    identity_id: &str,
    create: &TokenSpec,
    rename: &str,
    inert_rotation: bool,
) -> anyhow::Result<Vec<Route>> {
    let token = format!("/enrollment-tokens/{token_id}");
    let identity = format!("/identities/{identity_id}");
    let rotation = if inert_rotation {
        b"{".to_vec()
    } else {
        RotationDeadline::Now.body()?
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
            "/enrollment-tokens".to_owned(),
            Some(create.body()?),
            201,
            Permission::Manage,
        ),
        route(
            Method::GET,
            "/enrollment-tokens".to_owned(),
            None,
            200,
            Permission::View,
        ),
        route(Method::GET, token.clone(), None, 200, Permission::View),
        route(Method::DELETE, token, None, 204, Permission::Manage),
        route(
            Method::GET,
            format!("/identities?enrollmentTokenId={token_id}"),
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
        route(Method::GET, "/ca/rotation".to_owned(), None, 200, Permission::View),
        route(
            Method::POST,
            "/ca/rotation".to_owned(),
            Some(rotation),
            202,
            Permission::RotateRoot,
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
    ///
    /// A refusal is identified by its status alone, which is all DVLS's intent fixes.
    async fn request(&self, method: Method, path: &str, body: Option<&[u8]>, success: u16) -> anyhow::Result<Value> {
        let (status, bytes) = self
            .target
            .exchange(
                method.clone(),
                &format!("{BASE_PATH}{path}"),
                body,
                self.credential,
                None,
            )
            .await?;
        if status != success {
            ensure!(
                !(200..300).contains(&status),
                "{method} {path} succeeded with HTTP {status} instead of {success}"
            );
            return Err(Refusal::from_status(status).into());
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
        struct Created {
            token: String,
            record: CreatedRecord,
        }
        #[derive(Deserialize)]
        struct CreatedRecord {
            id: String,
        }
        let created: Created = self
            .fetch(Method::POST, "/enrollment-tokens", Some(&spec.body()?), 201)
            .await?;
        Ok(Token {
            text: created.token,
            id: created.record.id,
        })
    }

    pub(crate) async fn token(&self, id: &str) -> anyhow::Result<TokenRecord> {
        self.fetch(Method::GET, &format!("/enrollment-tokens/{id}"), None, 200)
            .await
    }

    /// Whether the token's record holds its secret text anywhere, which only token creation may return.
    pub(crate) async fn token_discloses_secret(&self, token: &Token) -> anyhow::Result<bool> {
        let (_, secret) = token.text.rsplit_once('.').context("token has no secret")?;
        let record = self
            .request(Method::GET, &format!("/enrollment-tokens/{}", token.id), None, 200)
            .await?;
        Ok(contains_text(&record, secret))
    }

    /// Every token, walking all pages.
    pub(crate) async fn all_tokens(&self) -> anyhow::Result<Vec<TokenRecord>> {
        let mut tokens = Vec::new();
        for number in 1.. {
            let page: Page<TokenRecord> = self
                .fetch(
                    Method::GET,
                    &format!("/enrollment-tokens?pageNumber={number}&pageSize={MAX_PAGE_SIZE}"),
                    None,
                    200,
                )
                .await?;
            tokens.extend(page.items);
            if number >= page.total_pages {
                break;
            }
        }
        Ok(tokens)
    }

    pub(crate) async fn delete_token(&self, id: &str) -> anyhow::Result<()> {
        self.request(Method::DELETE, &format!("/enrollment-tokens/{id}"), None, 204)
            .await
            .map(drop)
    }

    /// The full view of one identity.
    pub(crate) async fn identity(&self, id: &str) -> anyhow::Result<IdentityRecord> {
        let path = format!("/identities/{id}");
        let value = self.request(Method::GET, &path, None, 200).await?;
        for name in ["certificates", "enrollmentToken", "createdAt", "renewalRequested"] {
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
        self.fetch(
            Method::GET,
            &format!("/identities?{}", query.query_string()?),
            None,
            200,
        )
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
        self.fetch(Method::PATCH, &format!("/identities/{id}"), Some(&body), 200)
            .await
    }

    pub(crate) async fn revoke(&self, id: &str) -> anyhow::Result<()> {
        self.request(Method::POST, &format!("/identities/{id}/revoke"), None, 204)
            .await
            .map(drop)
    }

    pub(crate) async fn delete_identity(&self, id: &str) -> anyhow::Result<()> {
        self.request(Method::DELETE, &format!("/identities/{id}"), None, 204)
            .await
            .map(drop)
    }

    pub(crate) async fn request_renewal(&self, id: &str) -> anyhow::Result<()> {
        self.request(Method::POST, &format!("/identities/{id}/request-renewal"), None, 202)
            .await
            .map(drop)
    }

    pub(crate) async fn rotation(&self) -> anyhow::Result<RotationStatus> {
        self.fetch(Method::GET, "/ca/rotation", None, 200).await
    }

    pub(crate) async fn rotate(&self, deadline: RotationDeadline) -> anyhow::Result<RotationStatus> {
        self.fetch(Method::POST, "/ca/rotation", Some(&deadline.body()?), 202)
            .await
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

fn contains_text(value: &Value, text: &str) -> bool {
    match value {
        Value::String(value) => value.contains(text),
        Value::Array(items) => items.iter().any(|item| contains_text(item, text)),
        Value::Object(members) => members.values().any(|member| contains_text(member, text)),
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
            "status": "active",
            "connected": false,
            "metadata": {},
            "certificates": [],
            "enrollmentToken": { "id": "token-id", "name": "test" },
            "createdAt": "2026-09-25T12:00:00Z",
            "renewalRequested": false,
            "certificate": { "issuer": "root-id", "notAfter": "2026-12-24T12:00:00Z" }
        })
    }

    #[test]
    fn records_ignore_unknown_fields_and_treat_null_optional_fields_as_absent() -> anyhow::Result<()> {
        let record: IdentityRecord = serde_json::from_value(identity())?;
        let mut noisy = identity();
        noisy["request_id"] = json!("different");
        noisy["certificate"]["request_id"] = json!("different");
        noisy["lastSeenAt"] = Value::Null;
        noisy["revokedAt"] = Value::Null;
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
        let rotation: RotationStatus = serde_json::from_value(json!({
            "phase": "idle",
            "activeIdentitiesOnOldRoot": 0,
            "request_id": "different",
            "deadline": null,
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
    fn records_reject_null_or_malformed_required_fields() {
        for (name, value) in [
            ("metadata", Value::Null),
            ("status", Value::Null),
            ("createdAt", json!("not a timestamp")),
            ("lastSeenAt", json!(123)),
        ] {
            let mut record = identity();
            record[name] = value;
            assert!(
                serde_json::from_value::<IdentityRecord>(record).is_err(),
                "malformed {name} was accepted"
            );
        }
        assert!(
            serde_json::from_value::<RotationStatus>(json!({ "phase": null, "activeIdentitiesOnOldRoot": 0 })).is_err(),
            "explicit null rotation phase was accepted"
        );
    }
}
