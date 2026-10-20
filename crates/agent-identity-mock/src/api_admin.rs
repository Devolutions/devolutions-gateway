//! This module serves DVLS's management API ([DVLS intent][dvls-intent], "Management API")
//! under `<prefix>/api/v3/agent-identity`.
//!
//! Follows DVLS conventions: camelCase keys, DVLS paging, `Authorization: Bearer`, and
//! `{ "error", "message" }` error bodies.
//! Each route requires one of DVLS's four permissions, and a credential without it gets `403`.
//!
//! [dvls-intent]: ../../../docs/agent-identity/INTENT.DVLS.md#management-api

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State as AxumState};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{MethodRouter, delete, get, patch, post};
use axum::{Json, Router, middleware};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::app::{App, parse_rfc3339, rfc3339};
use crate::oracle::CertStatus;
use crate::state::{ApiError, Identity, IdentityStatus, State, Token};

const MAX_PAGE_SIZE: u64 = 100;
const DEFAULT_PAGE_SIZE: u64 = 25;
const MAX_TOKEN_LIFETIME_SECS: i64 = 365 * 24 * 3600;

pub(crate) fn router(app: Arc<App>) -> Router {
    use Permission::{Manage, Revoke, RotateRoot, View};

    let routes = Router::new()
        .route("/enrollment-tokens", requires(Manage, post(create_token)))
        .route("/enrollment-tokens", requires(View, get(list_tokens)))
        .route("/enrollment-tokens/{id}", requires(View, get(get_token)))
        .route("/enrollment-tokens/{id}", requires(Manage, delete(delete_token)))
        .route("/identities", requires(View, get(list_identities)))
        .route("/identities/{id}", requires(View, get(get_identity)))
        .route("/identities/{id}", requires(Manage, patch(patch_identity)))
        .route("/identities/{id}", requires(Manage, delete(delete_identity)))
        .route("/identities/{id}/revoke", requires(Revoke, post(revoke_identity)))
        .route(
            "/identities/{id}/request-renewal",
            requires(Manage, post(request_renewal)),
        )
        .route("/ca/rotation", requires(RotateRoot, post(start_rotation)))
        .route("/ca/rotation", requires(View, get(get_rotation)))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&app), authenticate));
    Router::new().nest("/api/v3/agent-identity", routes).with_state(app)
}

/// DVLS's Agent Identity permissions ([DVLS intent][dvls-intent], "Management API").
///
/// [dvls-intent]: ../../../docs/agent-identity/INTENT.DVLS.md#management-api
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Permission {
    View,
    Manage,
    Revoke,
    RotateRoot,
}

impl Permission {
    const ALL: [Permission; 4] = [
        Permission::View,
        Permission::Manage,
        Permission::Revoke,
        Permission::RotateRoot,
    ];

    /// Returns the permission's name in a scoped mock credential.
    fn credential_name(self) -> &'static str {
        match self {
            Permission::View => "view",
            Permission::Manage => "manage",
            Permission::Revoke => "revoke",
            Permission::RotateRoot => "rotate-root",
        }
    }

    /// Returns the permission's name in DVLS.
    fn display_name(self) -> &'static str {
        match self {
            Permission::View => "View",
            Permission::Manage => "Manage",
            Permission::Revoke => "Revoke",
            Permission::RotateRoot => "Rotate root",
        }
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// The permissions a management API credential holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Permissions(u8);

impl Permissions {
    fn all() -> Self {
        Permission::ALL.into_iter().collect()
    }

    fn contains(self, permission: Permission) -> bool {
        self.0 & permission.bit() != 0
    }
}

impl FromIterator<Permission> for Permissions {
    fn from_iter<I: IntoIterator<Item = Permission>>(iter: I) -> Self {
        Self(iter.into_iter().fold(0, |mask, permission| mask | permission.bit()))
    }
}

/// Returns the permissions a management API credential holds, or `None` when the credential is invalid.
///
/// `<admin-token>` holds every permission, `<admin-token>-unprivileged` none, and `<admin-token>.<scope>` the ones its scope lists.
/// The scope is `none` or a `+`-separated list of `view`, `manage`, `revoke` and `rotate-root`.
fn credential_permissions(admin_token: &str, credential: &str) -> Option<Permissions> {
    let suffix = credential.strip_prefix(admin_token)?;
    match suffix {
        "" => return Some(Permissions::all()),
        "-unprivileged" => return Some(Permissions::default()),
        _ => {}
    }
    let scope = suffix.strip_prefix('.')?;
    if scope == "none" {
        return Some(Permissions::default());
    }
    scope
        .split('+')
        .map(|name| {
            Permission::ALL
                .into_iter()
                .find(|permission| permission.credential_name() == name)
        })
        .collect()
}

fn requires(permission: Permission, route: MethodRouter<Arc<App>>) -> MethodRouter<Arc<App>> {
    route.route_layer(middleware::from_fn_with_state(permission, authorize))
}

async fn authenticate(AxumState(app): AxumState<Arc<App>>, mut request: Request, next: Next) -> Response {
    let permissions = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|credential| credential_permissions(&app.admin_token, credential));
    let Some(permissions) = permissions else {
        return management_error(&ApiError::new(401, "unauthorized", "missing or invalid bearer token"));
    };
    request.extensions_mut().insert(permissions);
    next.run(request).await
}

async fn authorize(AxumState(required): AxumState<Permission>, request: Request, next: Next) -> Response {
    let granted = request.extensions().get::<Permissions>().copied().unwrap_or_default();
    if !granted.contains(required) {
        return management_error(&ApiError::new(
            403,
            "forbidden",
            format!("missing {} permission", required.display_name()),
        ));
    }
    next.run(request).await
}

fn management_error(err: &ApiError) -> Response {
    (
        StatusCode::from_u16(err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(json!({ "error": err.code, "message": err.message })),
    )
        .into_response()
}

fn parse_page_params(query: &HashMap<String, String>) -> Result<(u64, u64), ApiError> {
    let page_number = match query.get("pageNumber") {
        None => 1,
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|&n| n >= 1)
            .ok_or_else(|| ApiError::invalid_request("pageNumber must be >= 1"))?,
    };
    let page_size = match query.get("pageSize") {
        None => DEFAULT_PAGE_SIZE,
        Some(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|&n| (1..=MAX_PAGE_SIZE).contains(&n))
            .ok_or_else(|| ApiError::invalid_request("pageSize must be between 1 and 100"))?,
    };
    Ok((page_number, page_size))
}

/// Paginates a creation-order-sorted list into the DVLS page shape.
fn paginate(items: Vec<Value>, page_number: u64, page_size: u64) -> Value {
    let total_count = items.len() as u64;
    let total_pages = total_count.div_ceil(page_size);
    let start = page_number.saturating_sub(1).saturating_mul(page_size).min(total_count);
    let end = start.saturating_add(page_size).min(total_count);
    let data: Vec<Value> = items
        .into_iter()
        .skip(usize::try_from(start).unwrap_or(usize::MAX))
        .take(usize::try_from(end - start).unwrap_or(usize::MAX))
        .collect();
    json!({
        "data": data,
        "currentPage": page_number,
        "pageSize": page_size,
        "totalCount": total_count,
        "totalPages": total_pages,
    })
}

// ==== DVLS enrollment tokens ====

/// Parses a management request body, which follows CONTRACT.md §1 and so rejects a member name repeated at any depth
/// ([DVLS intent][dvls], "Management API").
///
/// [dvls]: ../../../docs/agent-identity/INTENT.DVLS.md#management-api
fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    crate::json::parse_unique_members(body)
        .and_then(serde_json::from_value)
        .map_err(|error| ApiError::invalid_request(format!("malformed JSON body: {error}")))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenRequest {
    name: String,
    max_uses: u64,
    expires_at: String,
    friendly_name_format: Option<String>,
    config: Option<Value>,
}

fn validate_token_config(config: &Value) -> Result<(), ApiError> {
    let fields = config
        .as_object()
        .ok_or_else(|| ApiError::invalid_request("config must be a JSON object"))?;
    if fields
        .keys()
        .any(|name| matches!(name.as_str(), "version" | "revision" | "agent_channel_url"))
    {
        return Err(ApiError::invalid_request("config cannot replace reserved fields"));
    }
    Ok(())
}

fn token_record(token: &Token, now: i64) -> Value {
    let mut record = json!({
        "id": token.id,
        "name": token.name,
        "maxUses": token.max_uses,
        "usedCount": token.used_count,
        "expiresAt": rfc3339(token.expires_at),
        "state": token.state(now),
        "createdAt": rfc3339(token.created_at),
        "createdBy": token.created_by,
    });
    if let Some(format) = &token.friendly_name_format {
        record["friendlyNameFormat"] = json!(format);
    }
    if let Some(config) = &token.config {
        record["config"] = config.clone();
    }
    record
}

async fn create_token(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    app.tick().await;
    let request: CreateTokenRequest = match parse_body(&body) {
        Ok(r) => r,
        Err(error) => return management_error(&error),
    };
    let now = app.now();
    if !(1..=1_000_000).contains(&request.max_uses) {
        return management_error(&ApiError::invalid_request("maxUses must be between 1 and 1000000"));
    }
    let Some(expires_at) = parse_rfc3339(&request.expires_at) else {
        return management_error(&ApiError::invalid_request("expiresAt must be RFC 3339"));
    };
    if expires_at > now + MAX_TOKEN_LIFETIME_SECS {
        return management_error(&ApiError::invalid_request("expiresAt is more than 365 days out"));
    }
    if let Some(format) = &request.friendly_name_format
        && let Err(message) = crate::name_eval::validate_friendly_name_format(format)
    {
        return management_error(&ApiError::invalid_request(message));
    }
    if let Some(config) = &request.config
        && let Err(error) = validate_token_config(config)
    {
        return management_error(&error);
    }

    let mut state = app.state.lock().await;
    let (id, secret) = state.create_token(
        request.name,
        request.max_uses,
        expires_at,
        request.friendly_name_format,
        request.config,
        now,
    );
    let token = &state.tokens[&id];
    let record = token_record(token, now);
    drop(state);

    let full_token = crate::api_agent::enrollment_token(&app.base_url, &secret);
    (
        StatusCode::CREATED,
        Json(json!({ "token": full_token, "record": record })),
    )
        .into_response()
}

async fn list_tokens(AxumState(app): AxumState<Arc<App>>, Query(query): Query<HashMap<String, String>>) -> Response {
    app.tick().await;
    let (page_number, page_size) = match parse_page_params(&query) {
        Ok(p) => p,
        Err(err) => return management_error(&err),
    };
    let state = app.state.lock().await;
    let now = app.now();
    let mut tokens: Vec<&Token> = state
        .tokens
        .values()
        .filter(|token| token.deleted_at.is_none())
        .collect();
    tokens.sort_by_key(|t| (t.created_at, t.id));
    let records: Vec<Value> = tokens.into_iter().map(|t| token_record(t, now)).collect();
    Json(paginate(records, page_number, page_size)).into_response()
}

async fn get_token(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let state = app.state.lock().await;
    match state.tokens.get(&id).filter(|token| token.deleted_at.is_none()) {
        Some(token) => Json(token_record(token, app.now())).into_response(),
        None => management_error(&ApiError::not_found("unknown token")),
    }
}

async fn delete_token(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let mut state = app.state.lock().await;
    match state.tokens.get_mut(&id) {
        Some(token) => {
            token.deleted_at.get_or_insert_with(|| app.now());
            StatusCode::NO_CONTENT.into_response()
        }
        None => management_error(&ApiError::not_found("unknown token")),
    }
}

// ==== DVLS identities ====

fn identity_summary(app: &App, state: &State, identity: &Identity, metadata_keys: Option<&[String]>) -> Value {
    let now = app.now();
    let mut view = json!({
        "id": identity.id,
        "friendlyName": identity.friendly_name,
        "status": identity.status(now).as_str(),
        "connected": state.is_connected(identity.id),
    });
    if let Some(last_seen_at) = identity.last_seen_at {
        view["lastSeenAt"] = json!(rfc3339(last_seen_at));
    }
    if let Some(current) = identity.current_cert() {
        view["certificate"] = json!({
            "notAfter": rfc3339(current.not_after),
            "issuer": current.issuer,
        });
    }
    if let Some(keys) = metadata_keys {
        view["metadata"] = metadata_subset(identity, keys);
    }
    view
}

fn metadata_subset(identity: &Identity, keys: &[String]) -> Value {
    let mut map = serde_json::Map::new();
    for key in keys {
        if let Some(value) = identity.metadata.get(key) {
            map.insert(key.clone(), value.clone());
        }
    }
    Value::Object(map)
}

fn identity_full(app: &App, state: &State, identity: &Identity) -> Value {
    let mut view = identity_summary(app, state, identity, None);
    view["metadata"] = Value::Object(identity.metadata.clone());
    view["certificates"] = Value::Array(
        identity
            .certs
            .iter()
            .map(|c| {
                json!({
                    "thumbprint": c.thumbprint,
                    "serialNumber": c.serial,
                    "notBefore": rfc3339(c.not_before),
                    "notAfter": rfc3339(c.not_after),
                    "issuer": c.issuer,
                    "status": match c.status {
                        CertStatus::Current => "current",
                        CertStatus::Pending => "pending",
                        CertStatus::Retired => "retired",
                    },
                })
            })
            .collect(),
    );
    view["enrollmentToken"] = json!({ "id": identity.token_id, "name": identity.token_name });
    view["createdAt"] = json!(rfc3339(identity.created_at));
    if let Some(revoked_at) = identity.revoked_at {
        view["revokedAt"] = json!(rfc3339(revoked_at));
    }
    view["renewalRequested"] = json!(identity.renewal_requested.is_some());
    view
}

struct IdentityQuery {
    view_full: bool,
    metadata_keys: Option<Vec<String>>,
    status: Option<IdentityStatus>,
    enrollment_token_id: Option<Uuid>,
    issuer: Option<String>,
    last_seen_before: Option<i64>,
    last_seen_after: Option<i64>,
    q: Option<String>,
    page_number: u64,
    page_size: u64,
}

fn parse_identity_query(query: &HashMap<String, String>) -> Result<IdentityQuery, ApiError> {
    let (page_number, page_size) = parse_page_params(query)?;
    let view_full = match query.get("view").map(String::as_str) {
        None | Some("summary") => false,
        Some("full") => true,
        Some(_) => return Err(ApiError::invalid_request("view must be summary or full")),
    };
    let metadata_keys = query
        .get("metadata")
        .map(|raw| raw.split(',').map(ToOwned::to_owned).collect::<Vec<_>>());
    let status = match query.get("status") {
        None => None,
        Some(raw) => Some(
            IdentityStatus::parse(raw)
                .ok_or_else(|| ApiError::invalid_request("status must be active, grace, expired or revoked"))?,
        ),
    };
    let enrollment_token_id = match query.get("enrollmentTokenId") {
        None => None,
        Some(raw) => Some(
            raw.parse::<Uuid>()
                .map_err(|_| ApiError::invalid_request("enrollmentTokenId must be a UUID"))?,
        ),
    };
    let last_seen_before = match query.get("lastSeenBefore") {
        None => None,
        Some(raw) => {
            Some(parse_rfc3339(raw).ok_or_else(|| ApiError::invalid_request("lastSeenBefore must be RFC 3339"))?)
        }
    };
    let last_seen_after = match query.get("lastSeenAfter") {
        None => None,
        Some(raw) => {
            Some(parse_rfc3339(raw).ok_or_else(|| ApiError::invalid_request("lastSeenAfter must be RFC 3339"))?)
        }
    };
    Ok(IdentityQuery {
        view_full,
        metadata_keys,
        status,
        enrollment_token_id,
        issuer: query.get("issuer").cloned(),
        last_seen_before,
        last_seen_after,
        q: query.get("q").cloned(),
        page_number,
        page_size,
    })
}

async fn list_identities(
    AxumState(app): AxumState<Arc<App>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    app.tick().await;
    let query = match parse_identity_query(&query) {
        Ok(q) => q,
        Err(err) => return management_error(&err),
    };
    let state = app.state.lock().await;
    let now = app.now();

    let mut identities: Vec<&Identity> = state
        .identities
        .values()
        .filter(|d| {
            query.status.is_none_or(|s| d.status(now) == s)
                && query.enrollment_token_id.is_none_or(|t| d.token_id == t)
                && query
                    .issuer
                    .as_ref()
                    .is_none_or(|i| d.current_cert().is_some_and(|c| c.issuer == *i))
                && query
                    .last_seen_before
                    .is_none_or(|t| d.last_seen_at.is_some_and(|l| l < t))
                && query
                    .last_seen_after
                    .is_none_or(|t| d.last_seen_at.is_some_and(|l| l > t))
                && query
                    .q
                    .as_ref()
                    .is_none_or(|q| d.friendly_name.to_lowercase().contains(&q.to_lowercase()))
        })
        .collect();
    identities.sort_by_key(|identity| identity.created_seq);

    let views: Vec<Value> = identities
        .into_iter()
        .map(|d| {
            if query.view_full {
                identity_full(&app, &state, d)
            } else {
                identity_summary(&app, &state, d, query.metadata_keys.as_deref())
            }
        })
        .collect();
    Json(paginate(views, query.page_number, query.page_size)).into_response()
}

async fn get_identity(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let state = app.state.lock().await;
    match state.identities.get(&id) {
        Some(identity) => Json(identity_full(&app, &state, identity)).into_response(),
        None => management_error(&ApiError::not_found("unknown identity")),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchIdentityRequest {
    friendly_name: String,
}

async fn patch_identity(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>, body: Bytes) -> Response {
    app.tick().await;
    let request: PatchIdentityRequest = match parse_body(&body) {
        Ok(r) => r,
        Err(error) => return management_error(&error),
    };
    let len = request.friendly_name.chars().count();
    if !(1..=crate::name_eval::MAX_FRIENDLY_NAME_CHARS).contains(&len) {
        return management_error(&ApiError::invalid_request("friendlyName must be 1..255 characters"));
    }
    let mut state = app.state.lock().await;
    let Some(identity) = state.identities.get_mut(&id) else {
        return management_error(&ApiError::not_found("unknown identity"));
    };
    identity.friendly_name = request.friendly_name;
    let identity = state.identities.get(&id).expect("identity exists");
    Json(identity_full(&app, &state, identity)).into_response()
}

async fn revoke_identity(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let now = app.now();
    let mut state = app.state.lock().await;
    match state.revoke(id, now) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => management_error(&err),
    }
}

async fn delete_identity(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let mut state = app.state.lock().await;
    match state.delete_identity(id, app.now()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => management_error(&err),
    }
}

async fn request_renewal(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let mut state = app.state.lock().await;
    match state.request_renewal(id) {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(err) => management_error(&err),
    }
}

// ==== DVLS rotation ====

#[derive(Deserialize)]
struct StartRotationRequest {
    deadline: Option<String>,
}

fn rotation_view(state: &State, now: i64) -> Value {
    match &state.rotation {
        None => json!({ "phase": "idle", "activeIdentitiesOnOldRoot": 0 }),
        Some(rotation) => {
            let root_view = |thumbprint: &str| {
                state
                    .roots
                    .iter()
                    .find(|r| r.thumbprint == thumbprint)
                    .map(|r| json!({ "thumbprint": r.thumbprint, "notAfter": rfc3339(r.not_after) }))
            };
            let mut view = json!({
                "phase": "rotating",
                "deadline": rfc3339(rotation.deadline),
                "activeIdentitiesOnOldRoot": state.active_identities_on_old_root(now),
            });
            if let Some(old) = root_view(&rotation.old_root) {
                view["oldRoot"] = old;
            }
            if let Some(new) = root_view(&rotation.new_root) {
                view["newRoot"] = new;
            }
            view
        }
    }
}

async fn start_rotation(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    app.tick().await;
    let now = app.now();
    let deadline = if body.is_empty() {
        None
    } else {
        let request: StartRotationRequest = match parse_body(&body) {
            Ok(r) => r,
            Err(error) => return management_error(&error),
        };
        match request.deadline.as_deref() {
            None => None,
            Some("now") => Some(now),
            Some(raw) => match parse_rfc3339(raw) {
                Some(d) => Some(d),
                None => return management_error(&ApiError::invalid_request("deadline must be RFC 3339 or \"now\"")),
            },
        }
    };
    let mut state = app.state.lock().await;
    match state.start_rotation(deadline, now) {
        Ok(()) => (StatusCode::ACCEPTED, Json(rotation_view(&state, now))).into_response(),
        Err(err) => management_error(&err),
    }
}

async fn get_rotation(AxumState(app): AxumState<Arc<App>>) -> Response {
    app.tick().await;
    let state = app.state.lock().await;
    Json(rotation_view(&state, app.now())).into_response()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::body::Body;
    use axum::http::header::AUTHORIZATION;
    use axum::http::{Method, Request};
    use rstest::rstest;
    use serde_json::json;
    use tower::ServiceExt as _;

    use super::{Permission, Permissions, credential_permissions, parse_identity_query, router, validate_token_config};
    use crate::app::App;
    use crate::state::IdentityStatus;

    #[rstest]
    #[case::admin_token("admin", &[Permission::View, Permission::Manage, Permission::Revoke, Permission::RotateRoot])]
    #[case::unprivileged("admin-unprivileged", &[])]
    #[case::scope_none("admin.none", &[])]
    #[case::scope_one("admin.rotate-root", &[Permission::RotateRoot])]
    #[case::scope_several("admin.view+revoke", &[Permission::View, Permission::Revoke])]
    fn credential_holds_its_permissions(#[case] credential: &str, #[case] expected: &[Permission]) {
        let held = credential_permissions("admin", credential).expect("credential is valid");
        let held: Vec<Permission> = Permission::ALL.into_iter().filter(|p| held.contains(*p)).collect();
        assert_eq!(held, expected);
    }

    #[rstest]
    #[case::empty("")]
    #[case::other_secret("other")]
    #[case::longer_secret("admin2")]
    #[case::empty_scope("admin.")]
    #[case::unknown_permission("admin.view+audit")]
    #[case::trailing_separator("admin.view+")]
    #[case::display_name("admin.View")]
    fn invalid_credential_is_refused(#[case] credential: &str) {
        assert_eq!(credential_permissions("admin", credential), None::<Permissions>);
    }

    /// The route-to-permission map of DVLS's management API (INTENT.DVLS.md, "Management API").
    #[rstest]
    #[case::create_token(Method::POST, "/enrollment-tokens", "manage", "view+revoke+rotate-root")]
    #[case::list_tokens(Method::GET, "/enrollment-tokens", "view", "manage+revoke+rotate-root")]
    #[case::read_token(Method::GET, "/enrollment-tokens/{id}", "view", "manage+revoke+rotate-root")]
    #[case::delete_token(Method::DELETE, "/enrollment-tokens/{id}", "manage", "view+revoke+rotate-root")]
    #[case::list_identities(Method::GET, "/identities", "view", "manage+revoke+rotate-root")]
    #[case::read_identity(Method::GET, "/identities/{id}", "view", "manage+revoke+rotate-root")]
    #[case::rename_identity(Method::PATCH, "/identities/{id}", "manage", "view+revoke+rotate-root")]
    #[case::delete_identity(Method::DELETE, "/identities/{id}", "manage", "view+revoke+rotate-root")]
    #[case::revoke_identity(Method::POST, "/identities/{id}/revoke", "revoke", "view+manage+rotate-root")]
    #[case::request_renewal(
        Method::POST,
        "/identities/{id}/request-renewal",
        "manage",
        "view+revoke+rotate-root"
    )]
    #[case::start_rotation(Method::POST, "/ca/rotation", "rotate-root", "view+manage+revoke")]
    #[case::read_rotation(Method::GET, "/ca/rotation", "view", "manage+revoke+rotate-root")]
    #[tokio::test]
    async fn route_requires_its_permission(
        #[case] method: Method,
        #[case] route: &str,
        #[case] required: &str,
        #[case] all_others: &str,
    ) -> anyhow::Result<()> {
        let app = App::for_test()?;
        let path = route.replace("{id}", "00000000-0000-0000-0000-000000000000");
        let status = |scope: &str| {
            let request = Request::builder()
                .method(method.clone())
                .uri(format!("/api/v3/agent-identity{path}"))
                .header(AUTHORIZATION, format!("Bearer admin.{scope}"))
                .body(Body::empty())
                .expect("valid request");
            let router = router(std::sync::Arc::clone(&app));
            async move { router.oneshot(request).await.map(|response| response.status().as_u16()) }
        };
        assert_eq!(status(all_others).await?, 403);
        let granted = status(required).await?;
        assert!(!matches!(granted, 401 | 403), "{granted}");
        Ok(())
    }

    #[rstest]
    #[case::active("active", IdentityStatus::Active)]
    #[case::grace("grace", IdentityStatus::Grace)]
    #[case::expired("expired", IdentityStatus::Expired)]
    #[case::revoked("revoked", IdentityStatus::Revoked)]
    fn identity_status_filter_accepts_each_status(#[case] raw: &str, #[case] expected: IdentityStatus) {
        let query = HashMap::from([("status".to_owned(), raw.to_owned())]);
        let query = parse_identity_query(&query).expect("status filter is valid");
        assert_eq!(query.status, Some(expected));
    }

    #[test]
    fn identity_status_filter_refuses_a_certificate_status() {
        let query = HashMap::from([("status".to_owned(), "pending".to_owned())]);
        let error = parse_identity_query(&query).err().expect("status filter is invalid");
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn token_config_accepts_only_product_fields() {
        assert!(validate_token_config(&json!({ "psu_channel_url": "https://psu.example" })).is_ok());

        for config in [
            json!(true),
            json!({ "version": 2 }),
            json!({ "revision": 3 }),
            json!({ "agent_channel_url": "https://elsewhere.example" }),
        ] {
            assert_eq!(
                validate_token_config(&config).expect_err("config is invalid").code,
                "invalid_request"
            );
        }
    }

    /// The management API follows CONTRACT.md §1 (INTENT.DVLS.md, "Management API"),
    /// which rejects a body that repeats a member name at any depth with `invalid_request`.
    #[rstest]
    #[case::distinct_members(r#"{"flag":"first","other":"second"}"#, 201)]
    #[case::repeated_member(r#"{"flag":"first","flag":"second"}"#, 400)]
    #[tokio::test]
    async fn create_token_refuses_a_repeated_member_name(
        #[case] config: &str,
        #[case] expected: u16,
    ) -> anyhow::Result<()> {
        let app = App::for_test()?;
        let body = format!(
            r#"{{"name":"t","maxUses":1,"expiresAt":"{}","config":{config}}}"#,
            crate::app::rfc3339(app.now() + 3600)
        );
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/v3/agent-identity/enrollment-tokens")
            .header(AUTHORIZATION, "Bearer admin")
            .body(Body::from(body))
            .expect("valid request");
        let response = router(std::sync::Arc::clone(&app)).oneshot(request).await?;
        assert_eq!(response.status().as_u16(), expected);
        Ok(())
    }
}
