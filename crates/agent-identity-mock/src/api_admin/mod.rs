//! This module serves DVLS's management API ([DVLS intent][dvls-intent], "Management API") under
//! `<prefix>/api/v1/agent-identity`, with the operations, models, paging, errors and enum spelling of DVLS's OpenAPI
//! document.
//!
//! The `tokenId` header carries a session that DVLS's login opens, and each operation requires one of DVLS's four
//! permissions.
//! Invalid parameters are `400` with a `PublicApiValidationError` body; every other error carries a `PublicApiError`
//! body.
//!
//! [dvls-intent]: ../../../../docs/agent-identity/INTENT.DVLS.md#management-api

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, Request, State as AxumState};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, get, patch, post};
use axum::{Json, Router, middleware};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::app::{App, nanos, parse_date_time, rfc3339, rfc3339_nanos};
use crate::oracle::CertStatus;
use crate::state::{ApiError, Cert, Identity, IdentityStatus, State, Token};

mod login;

pub use login::ManagementLogin;

const BASE_PATH: &str = "/api/v1/agent-identity";
const TOKEN_ID_HEADER: &str = "tokenId";

const SECS_PER_DAY: i64 = 24 * 3600;
const DEFAULT_PAGE_SIZE: i64 = 25;
const MAX_IDENTITY_PAGE_SIZE: i64 = 100;
const MAX_TOKEN_PAGE_SIZE: i64 = 500;
const DEFAULT_TOKEN_LIFETIME_SECS: i64 = 90 * SECS_PER_DAY;
const MAX_TOKEN_LIFETIME_SECS: i64 = 365 * SECS_PER_DAY;
const MAX_TOKEN_USES: i64 = 1_000_000;
const MAX_TOKEN_NAME_CHARS: usize = 255;
const MAX_FRIENDLY_NAME_FORMAT_CHARS: usize = 1024;
const MAX_TOKEN_CONFIG_ENTRIES: usize = 32;
const MAX_TOKEN_CONFIG_KEY_BYTES: usize = 64;
const MAX_TOKEN_CONFIG_VALUE_BYTES: usize = 1024;
const MAX_CERTIFICATE_LIFETIME_DAYS: i64 = 365;
const MAX_ROTATION_NOTIFICATIONS_PER_SECOND: i64 = 1000;

const IDENTITY_NOT_FOUND: &str = "identity not found";
const TOKEN_NOT_FOUND: &str = "enrollment token not found";

const TOKEN_SORT_FIELDS: [&str; 3] = ["createdOn", "name", "expiresOn"];
const IDENTITY_SORT_FIELDS: [&str; 1] = ["createdOn"];

pub(crate) fn router(app: Arc<App>) -> Router {
    use Permission::{Manage, Revoke, RotateRoot, View};

    let path = |suffix: &str| format!("{BASE_PATH}{suffix}");
    Router::new()
        .route(&path(""), requires(View, get(list_identities)))
        .route(&path("/enrollment-token"), requires(Manage, post(create_token)))
        .route(&path("/enrollment-token"), requires(View, get(list_tokens)))
        .route(&path("/enrollment-token/{id}"), requires(View, get(get_token)))
        .route(&path("/enrollment-token/{id}"), requires(Manage, delete(delete_token)))
        .route(&path("/rotation"), requires(View, get(get_rotation)))
        .route(&path("/rotation"), requires(RotateRoot, post(start_rotation)))
        .route(&path("/settings"), requires(View, get(get_settings)))
        .route(&path("/settings"), requires(Manage, patch(patch_settings)))
        .route(&path("/{id}"), requires(View, get(get_identity)))
        .route(&path("/{id}"), requires(Manage, patch(patch_identity)))
        .route(&path("/{id}"), requires(Manage, delete(delete_identity)))
        .route(&path("/{id}/revoke"), requires(Revoke, post(revoke_identity)))
        .route(&path("/{id}/request-renewal"), requires(Manage, post(request_renewal)))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&app), authenticate))
        .route("/api/v1/login", post(login::login))
        .route("/api/v1/logout", post(login::logout))
        .with_state(app)
}

// ==== Authentication and permissions ====

/// DVLS's Agent Identity permissions ([DVLS intent][dvls-intent], "Management API").
///
/// [dvls-intent]: ../../../../docs/agent-identity/INTENT.DVLS.md#management-api
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

    /// Returns the permission's name in a scoped application key.
    fn key_name(self) -> &'static str {
        match self {
            Permission::View => "view",
            Permission::Manage => "manage",
            Permission::Revoke => "revoke",
            Permission::RotateRoot => "rotate-root",
        }
    }

    /// Returns the permission's name in DVLS's OpenAPI document.
    fn display_name(self) -> &'static str {
        match self {
            Permission::View => "AgentIdentityView",
            Permission::Manage => "AgentIdentityManage",
            Permission::Revoke => "AgentIdentityRevoke",
            Permission::RotateRoot => "AgentIdentityRotateRoot",
        }
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// The permissions a management API session holds.
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

/// Returns the permissions of a session that `key` opens, or `None` when `key` is not one of the keys of the application
/// identity `app_key`.
///
/// `<app-key>` holds every permission, `<app-key>-unprivileged` none, and `<app-key>.<scope>` the ones its scope lists.
/// The scope is `none` or a `+`-separated list of `view`, `manage`, `revoke` and `rotate-root`.
fn key_permissions(app_key: &str, key: &str) -> Option<Permissions> {
    let suffix = key.strip_prefix(app_key)?;
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
                .find(|permission| permission.key_name() == name)
        })
        .collect()
}

fn requires(permission: Permission, route: MethodRouter<Arc<App>>) -> MethodRouter<Arc<App>> {
    route.route_layer(middleware::from_fn_with_state(permission, authorize))
}

/// Authenticates the session the single `tokenId` header names.
async fn authenticate(AxumState(app): AxumState<Arc<App>>, mut request: Request, next: Next) -> Response {
    let mut token_ids = request.headers().get_all(TOKEN_ID_HEADER).iter();
    let token_id = match (token_ids.next(), token_ids.next()) {
        (Some(token_id), None) => token_id.to_str().ok().map(str::to_owned),
        _ => None,
    };
    let permissions = match token_id {
        Some(token_id) => app.login.session_permissions(&token_id).await,
        None => None,
    };
    let Some(permissions) = permissions else {
        return ManagementError::status(StatusCode::UNAUTHORIZED, "missing or invalid token").into_response();
    };
    request.extensions_mut().insert(permissions);
    next.run(request).await
}

async fn authorize(AxumState(required): AxumState<Permission>, request: Request, next: Next) -> Response {
    let granted = request.extensions().get::<Permissions>().copied().unwrap_or_default();
    if !granted.contains(required) {
        return ManagementError::status(
            StatusCode::FORBIDDEN,
            format!("missing the {} permission", required.display_name()),
        )
        .into_response();
    }
    next.run(request).await
}

// ==== Errors ====

/// A management API error: a `PublicApiValidationError` for `400`, and a `PublicApiError` otherwise.
#[derive(Debug)]
enum ManagementError {
    Validation(Vec<FieldError>),
    Status(StatusCode, String),
}

/// A `PublicApiFieldError`; `field` is `None` when the request as a whole is invalid.
#[derive(Debug)]
struct FieldError {
    field: Option<String>,
    message: String,
}

impl ManagementError {
    fn invalid(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation(vec![FieldError {
            field: Some(field.into()),
            message: message.into(),
        }])
    }

    fn invalid_request(message: impl Into<String>) -> Self {
        Self::Validation(vec![FieldError {
            field: None,
            message: message.into(),
        }])
    }

    fn status(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Status(status, message.into())
    }

    fn not_found(message: &str) -> Self {
        Self::status(StatusCode::NOT_FOUND, message)
    }
}

impl From<ApiError> for ManagementError {
    fn from(error: ApiError) -> Self {
        match StatusCode::from_u16(error.status) {
            Ok(StatusCode::BAD_REQUEST) => Self::invalid_request(error.message),
            Ok(status) => Self::Status(status, error.message),
            Err(_) => Self::Status(StatusCode::INTERNAL_SERVER_ERROR, error.message),
        }
    }
}

impl IntoResponse for ManagementError {
    fn into_response(self) -> Response {
        match self {
            ManagementError::Validation(errors) => {
                let errors: Vec<Value> = errors
                    .into_iter()
                    .map(|error| json!({ "field": error.field, "message": error.message }))
                    .collect();
                (StatusCode::BAD_REQUEST, Json(json!({ "errors": errors }))).into_response()
            }
            ManagementError::Status(status, message) => (status, Json(json!({ "message": message }))).into_response(),
        }
    }
}

type ManagementResult = Result<Response, ManagementError>;

/// Collects the field errors of one request, so that a `400` reports all of them.
#[derive(Default)]
struct FieldErrors(Vec<FieldError>);

impl FieldErrors {
    fn add(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.0.push(FieldError {
            field: Some(field.into()),
            message: message.into(),
        });
    }

    fn finish(self) -> Result<(), ManagementError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ManagementError::Validation(self.0))
        }
    }
}

// ==== Request parsing ====

/// Parses a JSON request body into its members.
///
/// A member name repeated at any depth is refused, as for agent-facing bodies ([CONTRACT.md][contract], "1. Protocol
/// conventions"), and so is a member the request schema does not define, since every schema in DVLS's OpenAPI document
/// sets `additionalProperties: false`.
///
/// [contract]: ../../../../docs/agent-identity/CONTRACT.md#1-protocol-conventions
fn parse_body(body: &[u8], members: &[&str]) -> Result<Map<String, Value>, ManagementError> {
    let value = crate::json::parse_unique_members(body)
        .map_err(|error| ManagementError::invalid_request(format!("malformed JSON body: {error}")))?;
    let Value::Object(object) = value else {
        return Err(ManagementError::invalid_request("body must be a JSON object"));
    };
    let mut errors = FieldErrors::default();
    for name in object.keys().filter(|name| !members.contains(&name.as_str())) {
        errors.add(name, "unknown member");
    }
    errors.finish()?;
    Ok(object)
}

/// Returns a member's value, where `null` counts as absent.
fn member<'a>(body: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    body.get(name).filter(|value| !value.is_null())
}

fn string_member<'a>(body: &'a Map<String, Value>, name: &str, errors: &mut FieldErrors) -> Option<&'a str> {
    let value = member(body, name)?;
    let text = value.as_str();
    if text.is_none() {
        errors.add(name, format!("{name} must be a string"));
    }
    text
}

fn bool_member(body: &Map<String, Value>, name: &str, errors: &mut FieldErrors) -> Option<bool> {
    let value = member(body, name)?;
    let flag = value.as_bool();
    if flag.is_none() {
        errors.add(name, format!("{name} must be a boolean"));
    }
    flag
}

/// Returns an integer member within `min..=max`.
fn integer_member(body: &Map<String, Value>, name: &str, min: i64, max: i64, errors: &mut FieldErrors) -> Option<i64> {
    let value = member(body, name)?;
    let integer = value.as_i64().filter(|integer| (min..=max).contains(integer));
    if integer.is_none() {
        errors.add(name, format!("{name} must be an integer from {min} to {max}"));
    }
    integer
}

/// Returns a date-time member in Unix nanoseconds.
fn date_time_member(body: &Map<String, Value>, name: &str, errors: &mut FieldErrors) -> Option<i128> {
    let text = string_member(body, name, errors)?;
    let time = parse_date_time(text);
    if time.is_none() {
        errors.add(name, format!("{name} must be a date-time"));
    }
    time
}

/// Parses an `{id}` route parameter; an ID that is not a GUID names no record.
fn parse_id(raw: &str, not_found: &str) -> Result<Uuid, ManagementError> {
    raw.parse().map_err(|_| ManagementError::not_found(not_found))
}

/// The query string of a request.
/// A single-valued parameter takes its first value; an empty value is present and validated like any other.
struct QueryParams(Vec<(String, String)>);

impl QueryParams {
    fn new(query: Result<Query<Vec<(String, String)>>, QueryRejection>) -> Result<Self, ManagementError> {
        query
            .map(|Query(pairs)| Self(pairs))
            .map_err(|rejection| ManagementError::invalid_request(format!("malformed query string: {rejection}")))
    }

    fn single<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        self.all(name).next()
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.0
            .iter()
            .filter(move |(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Returns an integer parameter within `min..=max`, or `default` when absent.
    fn integer(&self, name: &str, default: i64, min: i64, max: i64, errors: &mut FieldErrors) -> i64 {
        let Some(raw) = self.single(name) else {
            return default;
        };
        match raw.parse::<i32>().map(i64::from) {
            Ok(value) if (min..=max).contains(&value) => value,
            _ => {
                errors.add(name, format!("{name} must be an integer from {min} to {max}"));
                default
            }
        }
    }

    /// Returns a date-time parameter in Unix nanoseconds.
    fn date_time(&self, name: &str, errors: &mut FieldErrors) -> Option<i128> {
        let raw = self.single(name)?;
        let time = parse_date_time(raw);
        if time.is_none() {
            errors.add(name, format!("{name} must be a date-time"));
        }
        time
    }
}

// ==== Paging ====

/// The paging parameters every list operation of DVLS's OpenAPI document takes.
struct Paging {
    page_number: u64,
    page_size: u64,
    ascending: bool,
    sort_field: &'static str,
}

impl Paging {
    /// Parses `pageNumber`, `pageSize` (at most `max_page_size`), `sortOrder` (1 ascending, 0 descending) and
    /// `sortField` (one of `sort_fields`, the first being the default).
    fn parse(query: &QueryParams, max_page_size: i64, sort_fields: &[&'static str], errors: &mut FieldErrors) -> Self {
        let page_number = query.integer("pageNumber", 1, 1, i64::from(i32::MAX), errors);
        let page_size = query.integer("pageSize", DEFAULT_PAGE_SIZE, 1, max_page_size, errors);
        let sort_order = query.integer("sortOrder", 1, 0, 1, errors);
        let sort_field = match query.single("sortField") {
            None => sort_fields[0],
            Some(raw) => match sort_fields.iter().find(|field| **field == raw) {
                Some(field) => field,
                None => {
                    errors.add(
                        "sortField",
                        format!("sortField must be one of {}", sort_fields.join(", ")),
                    );
                    sort_fields[0]
                }
            },
        };
        Self {
            page_number: u64::try_from(page_number).expect("pageNumber is at least 1"),
            page_size: u64::try_from(page_size).expect("pageSize is at least 1"),
            ascending: sort_order == 1,
            sort_field,
        }
    }

    /// Returns the requested page of `items`, already sorted, as a `PagedResultOf*`; a page past the last is invalid.
    fn page(&self, items: Vec<Value>) -> Result<Value, ManagementError> {
        let total_count = items.len() as u64;
        let total_page = total_count.div_ceil(self.page_size);
        let last_page = total_page.max(1);
        if last_page < self.page_number {
            return Err(ManagementError::invalid(
                "pageNumber",
                format!("pageNumber must be at most {last_page}"),
            ));
        }
        let skip = (self.page_number - 1) * self.page_size;
        let data: Vec<Value> = items
            .into_iter()
            .skip(usize::try_from(skip).expect("the skipped items exist"))
            .take(usize::try_from(self.page_size).unwrap_or(usize::MAX))
            .collect();
        Ok(json!({
            "currentPage": self.page_number,
            "data": data,
            "pageSize": self.page_size,
            "totalCount": total_count,
            "totalPage": total_page,
        }))
    }
}

// ==== Enrollment tokens ====

/// Returns an `AgentIdentityEnrollmentToken`.
fn token_view(token: &Token, now: i64) -> Value {
    let mut view = json!({
        "id": token.id,
        "name": token.name,
        "maxUses": token.max_uses,
        "useCount": token.used_count,
        "expiresOn": rfc3339_nanos(token.expires_at_ns),
        "state": token.state(now),
        "createdOn": rfc3339(token.created_at),
        "createdBy": token.created_by,
    });
    if let Some(format) = &token.friendly_name_format {
        view["friendlyNameFormat"] = json!(format);
    }
    if let Some(config) = &token.config {
        view["config"] = config.clone();
    }
    view
}

/// Checks `AgentIdentityEnrollmentTokenCreateDTO.config`: at most 32 entries, each key matching
/// `^[a-z][a-z0-9_]{0,63}$` and other than `version`, `revision` and `agent_channel_url`, each value a string of at most
/// 1024 UTF-8 bytes without control characters.
fn validate_token_config(config: &Value, errors: &mut FieldErrors) {
    let Some(entries) = config.as_object() else {
        errors.add("config", "config must be an object");
        return;
    };
    if MAX_TOKEN_CONFIG_ENTRIES < entries.len() {
        errors.add(
            "config",
            format!("config allows at most {MAX_TOKEN_CONFIG_ENTRIES} entries"),
        );
    }
    for (key, value) in entries {
        let field = format!("config.{key}");
        if !is_config_key(key) {
            errors.add(&field, "config key must match ^[a-z][a-z0-9_]{0,63}$");
        } else if matches!(key.as_str(), "version" | "revision" | "agent_channel_url") {
            errors.add(&field, "config key is reserved");
        }
        match value.as_str() {
            None => errors.add(&field, "config value must be a string"),
            Some(text) if MAX_TOKEN_CONFIG_VALUE_BYTES < text.len() => {
                errors.add(
                    &field,
                    format!("config value must be at most {MAX_TOKEN_CONFIG_VALUE_BYTES} bytes"),
                );
            }
            Some(text) if text.chars().any(char::is_control) => {
                errors.add(&field, "config value must not contain control characters");
            }
            Some(_) => {}
        }
    }
}

fn is_config_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && key.len() <= MAX_TOKEN_CONFIG_KEY_BYTES
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// `AgentIdentityPublicApi_CreateAgentIdentityEnrollmentToken`.
async fn create_token(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> ManagementResult {
    app.tick().await;
    let body = parse_body(&body, &["name", "maxUses", "expiresOn", "friendlyNameFormat", "config"])?;
    let now = app.now();
    let mut errors = FieldErrors::default();

    let name = string_member(&body, "name", &mut errors);
    if member(&body, "name").is_none() {
        errors.add("name", "name is required");
    }
    if name.is_some_and(|name| !(1..=MAX_TOKEN_NAME_CHARS).contains(&name.chars().count()) || name.trim().is_empty()) {
        errors.add("name", "name must be 1 to 255 Unicode scalar values, not blank");
    }
    let max_uses = integer_member(&body, "maxUses", 1, MAX_TOKEN_USES, &mut errors);
    if member(&body, "maxUses").is_none() {
        errors.add("maxUses", "maxUses is required");
    }
    let expires_at_ns = match date_time_member(&body, "expiresOn", &mut errors) {
        None => nanos(now + DEFAULT_TOKEN_LIFETIME_SECS),
        Some(expires_at_ns) => {
            if !(nanos(now) < expires_at_ns && expires_at_ns <= nanos(now + MAX_TOKEN_LIFETIME_SECS)) {
                errors.add(
                    "expiresOn",
                    "expiresOn must be in the future and at most 365 days ahead",
                );
            }
            expires_at_ns
        }
    };
    let friendly_name_format = string_member(&body, "friendlyNameFormat", &mut errors);
    if let Some(format) = friendly_name_format {
        if MAX_FRIENDLY_NAME_FORMAT_CHARS < format.chars().count() {
            errors.add(
                "friendlyNameFormat",
                format!("friendlyNameFormat must be at most {MAX_FRIENDLY_NAME_FORMAT_CHARS} Unicode scalar values"),
            );
        } else if let Err(message) = crate::name_eval::validate_friendly_name_format(format) {
            errors.add("friendlyNameFormat", message);
        }
    }
    let config = member(&body, "config");
    if let Some(config) = config {
        validate_token_config(config, &mut errors);
    }
    errors.finish()?;
    let name = name.expect("a missing name is a field error");
    let max_uses = max_uses.expect("a missing maxUses is a field error");

    let mut state = app.state.lock().await;
    state.ensure_root(now)?;
    let (id, secret) = state.create_token(
        name.to_owned(),
        u64::try_from(max_uses).expect("maxUses is at least 1"),
        expires_at_ns,
        friendly_name_format.map(ToOwned::to_owned),
        config.cloned(),
        now,
    );
    let view = token_view(&state.tokens[&id], now);
    drop(state);

    let token = crate::api_agent::enrollment_token(&app.base_url, &secret);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "enrollmentToken": view, "token": token })),
    )
        .into_response())
}

/// `AgentIdentityPublicApi_GetAgentIdentityEnrollmentTokens`.
async fn list_tokens(
    AxumState(app): AxumState<Arc<App>>,
    query: Result<Query<Vec<(String, String)>>, QueryRejection>,
) -> ManagementResult {
    app.tick().await;
    let query = QueryParams::new(query)?;
    let mut errors = FieldErrors::default();
    let paging = Paging::parse(&query, MAX_TOKEN_PAGE_SIZE, &TOKEN_SORT_FIELDS, &mut errors);
    errors.finish()?;

    let state = app.state.lock().await;
    let now = app.now();
    let mut tokens: Vec<&Token> = state
        .tokens
        .values()
        .filter(|token| token.deleted_at.is_none())
        .collect();
    match paging.sort_field {
        "name" => tokens.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then((a.created_at, a.created_seq).cmp(&(b.created_at, b.created_seq)))
        }),
        "expiresOn" => tokens.sort_by_key(|token| (token.expires_at_ns, token.created_at, token.created_seq)),
        // The creation order breaks ties within a second.
        _ => tokens.sort_by_key(|token| (token.created_at, token.created_seq)),
    }
    if !paging.ascending {
        tokens.reverse();
    }
    let views = tokens.into_iter().map(|token| token_view(token, now)).collect();
    Ok(Json(paging.page(views)?).into_response())
}

/// `AgentIdentityPublicApi_GetAgentIdentityEnrollmentToken`.
async fn get_token(AxumState(app): AxumState<Arc<App>>, Path(id): Path<String>) -> ManagementResult {
    app.tick().await;
    let id = parse_id(&id, TOKEN_NOT_FOUND)?;
    let state = app.state.lock().await;
    let token = state
        .tokens
        .get(&id)
        .filter(|token| token.deleted_at.is_none())
        .ok_or_else(|| ManagementError::not_found(TOKEN_NOT_FOUND))?;
    Ok(Json(token_view(token, app.now())).into_response())
}

/// `AgentIdentityPublicApi_DeleteAgentIdentityEnrollmentToken`.
async fn delete_token(AxumState(app): AxumState<Arc<App>>, Path(id): Path<String>) -> ManagementResult {
    app.tick().await;
    let id = parse_id(&id, TOKEN_NOT_FOUND)?;
    let mut state = app.state.lock().await;
    let token = state
        .tokens
        .get_mut(&id)
        .filter(|token| token.deleted_at.is_none())
        .ok_or_else(|| ManagementError::not_found(TOKEN_NOT_FOUND))?;
    token.deleted_at = Some(app.now());
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ==== Identities ====

fn last_seen_on(identity: &Identity) -> i64 {
    identity.last_seen_at.unwrap_or(identity.created_at)
}

/// Returns the members of an `AgentIdentity` that both views carry.
fn identity_view(state: &State, identity: &Identity, now: i64) -> Value {
    let mut view = json!({
        "id": identity.id,
        "friendlyName": identity.friendly_name,
        "status": identity.status(now).as_str(),
        "isConnected": state.is_connected(identity.id),
        "lastSeenOn": rfc3339(last_seen_on(identity)),
    });
    if let Some(current) = identity.current_cert() {
        view["certificate"] = json!({
            "issuerThumbprint": current.issuer,
            "validUntil": rfc3339(current.not_after),
        });
    }
    view
}

/// Returns an `AgentIdentity` in the Summary view, with the requested metadata keys it has.
fn identity_summary(state: &State, identity: &Identity, now: i64, metadata_keys: &[&str]) -> Value {
    let mut view = identity_view(state, identity, now);
    let metadata: Map<String, Value> = metadata_keys
        .iter()
        .filter_map(|key| {
            identity
                .metadata
                .get(*key)
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect();
    if !metadata.is_empty() {
        view["metadata"] = Value::Object(metadata);
    }
    view
}

/// Returns an `AgentIdentityCertificate`.
fn certificate_view(cert: &Cert) -> Value {
    json!({
        "issuerThumbprint": cert.issuer,
        "serialNumber": cert.serial,
        "status": match cert.status {
            CertStatus::Pending => "Pending",
            CertStatus::Current => "Current",
            CertStatus::Retired => "Retired",
        },
        "thumbprint": cert.thumbprint,
        "validFrom": rfc3339(cert.not_before),
        "validUntil": rfc3339(cert.not_after),
    })
}

/// Returns an `AgentIdentity` in the Full view.
fn identity_full(state: &State, identity: &Identity, now: i64) -> Value {
    let mut view = identity_view(state, identity, now);
    view["metadata"] = Value::Object(identity.metadata.clone());
    view["certificates"] = identity.certs.iter().rev().map(certificate_view).collect();
    view["createdOn"] = json!(rfc3339(identity.created_at));
    view["enrollmentTokenId"] = json!(identity.token_id);
    view["enrollmentTokenName"] = json!(identity.token_name);
    view["isRenewalRequested"] = json!(identity.renewal_requested.is_some());
    if let Some(revoked_at) = identity.revoked_at {
        view["revokedOn"] = json!(rfc3339(revoked_at));
    }
    view
}

/// `AgentIdentityPublicApi_GetAgentIdentities`.
async fn list_identities(
    AxumState(app): AxumState<Arc<App>>,
    query: Result<Query<Vec<(String, String)>>, QueryRejection>,
) -> ManagementResult {
    app.tick().await;
    let query = QueryParams::new(query)?;
    let mut errors = FieldErrors::default();
    let paging = Paging::parse(&query, MAX_IDENTITY_PAGE_SIZE, &IDENTITY_SORT_FIELDS, &mut errors);
    let full = match query.single("view") {
        None | Some("Summary") => false,
        Some("Full") => true,
        Some(_) => {
            errors.add("view", "view must be Summary or Full");
            false
        }
    };
    let metadata_keys: Vec<&str> = query.all("metadataKey").collect();
    let mut statuses = Vec::new();
    for raw in query.all("status") {
        match IdentityStatus::parse(raw) {
            Some(status) => statuses.push(status),
            None => errors.add("status", "status must be Active, Grace, Expired or Revoked"),
        }
    }
    let mut token_ids = Vec::new();
    for raw in query.all("enrollmentTokenId") {
        match raw.parse::<Uuid>() {
            Ok(id) => token_ids.push(id),
            Err(_) => errors.add("enrollmentTokenId", "enrollmentTokenId must be a GUID"),
        }
    }
    let issuer = query.single("issuerThumbprint");
    let last_seen_from = query.date_time("lastSeenFrom", &mut errors);
    let last_seen_to = query.date_time("lastSeenTo", &mut errors);
    let search = query.single("search").map(str::to_lowercase);
    errors.finish()?;

    let state = app.state.lock().await;
    let now = app.now();
    let mut identities: Vec<&Identity> = state
        .identities
        .values()
        .filter(|identity| {
            (statuses.is_empty() || statuses.contains(&identity.status(now)))
                && (token_ids.is_empty() || token_ids.contains(&identity.token_id))
                && issuer.is_none_or(|issuer| identity.current_cert().is_some_and(|cert| cert.issuer == issuer))
                && last_seen_from.is_none_or(|from| from <= nanos(last_seen_on(identity)))
                && last_seen_to.is_none_or(|to| nanos(last_seen_on(identity)) <= to)
                && search
                    .as_deref()
                    .is_none_or(|search| identity.friendly_name.to_lowercase().contains(search))
        })
        .collect();
    identities.sort_by_key(|identity| identity.created_seq);
    if !paging.ascending {
        identities.reverse();
    }
    let views = identities
        .into_iter()
        .map(|identity| {
            if full {
                identity_full(&state, identity, now)
            } else {
                identity_summary(&state, identity, now, &metadata_keys)
            }
        })
        .collect();
    Ok(Json(paging.page(views)?).into_response())
}

/// `AgentIdentityPublicApi_GetAgentIdentity`.
async fn get_identity(AxumState(app): AxumState<Arc<App>>, Path(id): Path<String>) -> ManagementResult {
    app.tick().await;
    let id = parse_id(&id, IDENTITY_NOT_FOUND)?;
    let state = app.state.lock().await;
    let identity = state
        .identities
        .get(&id)
        .ok_or_else(|| ManagementError::not_found(IDENTITY_NOT_FOUND))?;
    Ok(Json(identity_full(&state, identity, app.now())).into_response())
}

/// Checks `AgentIdentityPatchDTO.friendlyName`: 1 to 255 Unicode scalar values that do not start or end with white
/// space.
fn is_valid_friendly_name(name: &str) -> bool {
    (1..=crate::name_eval::MAX_FRIENDLY_NAME_CHARS).contains(&name.chars().count())
        && !name.starts_with(char::is_whitespace)
        && !name.ends_with(char::is_whitespace)
}

/// `AgentIdentityPublicApi_PatchAgentIdentity`.
async fn patch_identity(AxumState(app): AxumState<Arc<App>>, Path(id): Path<String>, body: Bytes) -> ManagementResult {
    app.tick().await;
    let body = parse_body(&body, &["friendlyName"])?;
    let mut errors = FieldErrors::default();
    let friendly_name = string_member(&body, "friendlyName", &mut errors);
    if friendly_name.is_some_and(|name| !is_valid_friendly_name(name)) {
        errors.add(
            "friendlyName",
            "friendlyName must be 1 to 255 Unicode scalar values that do not start or end with white space",
        );
    }
    errors.finish()?;
    let id = parse_id(&id, IDENTITY_NOT_FOUND)?;

    let mut state = app.state.lock().await;
    let identity = state
        .identities
        .get_mut(&id)
        .ok_or_else(|| ManagementError::not_found(IDENTITY_NOT_FOUND))?;
    if let Some(name) = friendly_name {
        name.clone_into(&mut identity.friendly_name);
    }
    let identity = &state.identities[&id];
    Ok(Json(identity_full(&state, identity, app.now())).into_response())
}

/// `AgentIdentityPublicApi_RevokeAgentIdentity`; revocation closes live streams with `identity_revoked`.
async fn revoke_identity(AxumState(app): AxumState<Arc<App>>, Path(id): Path<String>) -> ManagementResult {
    app.tick().await;
    let id = parse_id(&id, IDENTITY_NOT_FOUND)?;
    let now = app.now();
    app.state.lock().await.revoke(id, now)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `AgentIdentityPublicApi_DeleteAgentIdentity`.
async fn delete_identity(AxumState(app): AxumState<Arc<App>>, Path(id): Path<String>) -> ManagementResult {
    app.tick().await;
    let id = parse_id(&id, IDENTITY_NOT_FOUND)?;
    let now = app.now();
    app.state.lock().await.delete_identity(id, now)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `AgentIdentityPublicApi_RequestAgentIdentityRenewal`.
async fn request_renewal(AxumState(app): AxumState<Arc<App>>, Path(id): Path<String>) -> ManagementResult {
    app.tick().await;
    let id = parse_id(&id, IDENTITY_NOT_FOUND)?;
    app.state.lock().await.request_renewal(id)?;
    Ok(StatusCode::ACCEPTED.into_response())
}

// ==== Rotation ====

/// Returns an `AgentIdentityRotation`.
fn rotation_view(state: &State, now: i64) -> Value {
    let Some(rotation) = &state.rotation else {
        return json!({ "phase": "Idle", "oldRootActiveIdentityCount": 0 });
    };
    let root_view = |thumbprint: &str| {
        state
            .roots
            .iter()
            .find(|root| root.thumbprint == thumbprint)
            .map(|root| {
                json!({
                    "thumbprint": root.thumbprint,
                    "validFrom": rfc3339(root.not_before),
                    "validUntil": rfc3339(root.not_after),
                })
            })
    };
    json!({
        "phase": "Rotating",
        "startedOn": rfc3339(rotation.started_at),
        "deadlineOn": rfc3339_nanos(rotation.deadline_ns),
        "oldRoot": root_view(&rotation.old_root),
        "newRoot": root_view(&rotation.new_root),
        "oldRootActiveIdentityCount": state.active_identities_on_old_root(now),
    })
}

/// `AgentIdentityPublicApi_StartAgentIdentityRotation`.
async fn start_rotation(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> ManagementResult {
    app.tick().await;
    let body = parse_body(&body, &["deadlineOn"])?;
    let mut errors = FieldErrors::default();
    let deadline = date_time_member(&body, "deadlineOn", &mut errors);
    errors.finish()?;

    let now = app.now();
    let mut state = app.state.lock().await;
    state.start_rotation(deadline, now)?;
    Ok((StatusCode::ACCEPTED, Json(rotation_view(&state, now))).into_response())
}

/// `AgentIdentityPublicApi_GetAgentIdentityRotation`.
async fn get_rotation(AxumState(app): AxumState<Arc<App>>) -> ManagementResult {
    app.tick().await;
    let state = app.state.lock().await;
    Ok(Json(rotation_view(&state, app.now())).into_response())
}

// ==== Settings ====

/// Returns `AgentIdentitySettings`.
fn settings_view(app: &App, state: &State) -> Value {
    json!({
        "authorityId": app.authority_id,
        "isAgentChannelEnabled": state.settings.agent_channel_enabled,
        "isAgentChannelAvailable": state.channel_offered(),
        "certificateLifetimeDays": state.settings.certificate_lifetime_days,
        "rotationNotificationsPerSecond": state.settings.rotation_notifications_per_second,
    })
}

/// `AgentIdentityPublicApi_GetAgentIdentitySettings`.
async fn get_settings(AxumState(app): AxumState<Arc<App>>) -> ManagementResult {
    app.tick().await;
    let state = app.state.lock().await;
    Ok(Json(settings_view(&app, &state)).into_response())
}

/// `AgentIdentityPublicApi_PatchAgentIdentitySettings`.
async fn patch_settings(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> ManagementResult {
    app.tick().await;
    let body = parse_body(
        &body,
        &[
            "isAgentChannelEnabled",
            "certificateLifetimeDays",
            "rotationNotificationsPerSecond",
        ],
    )?;
    let mut errors = FieldErrors::default();
    let channel_enabled = bool_member(&body, "isAgentChannelEnabled", &mut errors);
    let lifetime_days = integer_member(
        &body,
        "certificateLifetimeDays",
        1,
        MAX_CERTIFICATE_LIFETIME_DAYS,
        &mut errors,
    );
    let notifications_per_second = integer_member(
        &body,
        "rotationNotificationsPerSecond",
        1,
        MAX_ROTATION_NOTIFICATIONS_PER_SECOND,
        &mut errors,
    );
    errors.finish()?;

    let mut state = app.state.lock().await;
    if let Some(enabled) = channel_enabled {
        state.update_agent_channel_enabled(enabled, &app.base_url);
    }
    if let Some(days) = lifetime_days {
        state.settings.certificate_lifetime_days = u32::try_from(days).expect("certificateLifetimeDays is in range");
    }
    if let Some(rate) = notifications_per_second {
        state.settings.rotation_notifications_per_second =
            u32::try_from(rate).expect("rotationNotificationsPerSecond is in range");
    }
    Ok(Json(settings_view(&app, &state)).into_response())
}

#[cfg(test)]
mod tests;
