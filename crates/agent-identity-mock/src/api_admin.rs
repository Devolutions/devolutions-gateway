//! Admin API (CONTRACT.md §9), under `<prefix>/api/v3/agent-identity`.
//!
//! Follows DVLS conventions: camelCase keys, DVLS paging, `Authorization: Bearer`, and
//! `{ "error", "message" }` error bodies.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State as AxumState};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::app::{App, parse_rfc3339, rfc3339};
use crate::httpsig::CertStatus;
use crate::state::{ApiError, Device, State, Token};

const MAX_PAGE_SIZE: u64 = 100;
const DEFAULT_PAGE_SIZE: u64 = 25;
const MAX_TOKEN_LIFETIME_SECS: i64 = 365 * 24 * 3600;

pub fn router(app: Arc<App>) -> Router {
    let authed = Router::new()
        .route("/enrollment-tokens", post(create_token).get(list_tokens))
        .route("/enrollment-tokens/{id}", get(get_token).delete(delete_token))
        .route("/devices", get(list_devices))
        .route(
            "/devices/{id}",
            get(get_device).patch(patch_device).delete(delete_device),
        )
        .route("/devices/{id}/revoke", post(revoke_device))
        .route("/devices/{id}/request-renewal", post(request_renewal))
        .route("/ca/rotation", post(start_rotation).get(get_rotation))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&app), admin_auth));
    Router::new().nest("/api/v3/agent-identity", authed).with_state(app)
}

async fn admin_auth(AxumState(app): AxumState<Arc<App>>, request: Request, next: Next) -> Response {
    let expected = format!("Bearer {}", app.admin_token);
    let ok = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == expected);
    let unprivileged = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == format!("Bearer {}", app.unprivileged_token));
    if unprivileged {
        return admin_error(&ApiError::new(
            403,
            "forbidden",
            "missing Agent identity management permission",
        ));
    }
    if !ok {
        return admin_error(&ApiError::new(401, "unauthorized", "missing or invalid bearer token"));
    }
    next.run(request).await
}

fn admin_error(err: &ApiError) -> Response {
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

// ==== §9.1 enrollment tokens ====

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenRequest {
    name: String,
    max_uses: u64,
    expires_at: String,
    friendly_name_format: Option<String>,
    config: Option<Value>,
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
    let request: CreateTokenRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return admin_error(&ApiError::invalid_request("malformed JSON body")),
    };
    let now = app.now();
    if !(1..=1_000_000).contains(&request.max_uses) {
        return admin_error(&ApiError::invalid_request("maxUses must be between 1 and 1000000"));
    }
    let Some(expires_at) = parse_rfc3339(&request.expires_at) else {
        return admin_error(&ApiError::invalid_request("expiresAt must be RFC 3339"));
    };
    if expires_at > now + MAX_TOKEN_LIFETIME_SECS {
        return admin_error(&ApiError::invalid_request("expiresAt is more than 365 days out"));
    }
    if let Some(format) = &request.friendly_name_format
        && let Err(message) = crate::name_eval::validate_friendly_name_format(format)
    {
        return admin_error(&ApiError::invalid_request(message));
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

    // §2: dvaet1.<base64url JSON bag>.<base64url 32-byte secret>.
    let bag = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json!({ "u": app.base_url }).to_string());
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
    let full_token = format!("dvaet1.{bag}.{secret}");
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
        Err(err) => return admin_error(&err),
    };
    let state = app.state.lock().await;
    let now = app.now();
    let mut tokens: Vec<&Token> = state.tokens.values().collect();
    tokens.sort_by_key(|t| (t.created_at, t.id));
    let records: Vec<Value> = tokens.into_iter().map(|t| token_record(t, now)).collect();
    Json(paginate(records, page_number, page_size)).into_response()
}

async fn get_token(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let state = app.state.lock().await;
    match state.tokens.get(&id) {
        Some(token) => Json(token_record(token, app.now())).into_response(),
        None => admin_error(&ApiError::not_found("unknown token")),
    }
}

async fn delete_token(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let mut state = app.state.lock().await;
    if state.tokens.remove(&id).is_none() {
        return admin_error(&ApiError::not_found("unknown token"));
    }
    state.token_hashes.retain(|_, v| *v != id);
    StatusCode::NO_CONTENT.into_response()
}

// ==== §9.2 devices ====

fn device_summary(app: &App, state: &State, device: &Device, metadata_keys: Option<&[String]>) -> Value {
    let now = app.now();
    let mut view = json!({
        "id": device.id,
        "friendlyName": device.friendly_name,
        "status": device.status(now),
        "connected": state.is_connected(device.id),
    });
    if let Some(last_seen_at) = device.last_seen_at {
        view["lastSeenAt"] = json!(rfc3339(last_seen_at));
    }
    if let Some(current) = device.current_cert() {
        view["certificate"] = json!({
            "notAfter": rfc3339(current.not_after),
            "issuer": current.issuer,
        });
    }
    if let Some(keys) = metadata_keys {
        view["metadata"] = metadata_subset(device, keys);
    }
    view
}

fn metadata_subset(device: &Device, keys: &[String]) -> Value {
    let mut map = serde_json::Map::new();
    for key in keys {
        if let Some(value) = device.metadata.get(key) {
            map.insert(key.clone(), value.clone());
        }
    }
    Value::Object(map)
}

fn device_full(app: &App, state: &State, device: &Device) -> Value {
    let mut view = device_summary(app, state, device, None);
    view["metadata"] = Value::Object(device.metadata.clone());
    view["certificates"] = Value::Array(
        device
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
    view["enrollmentToken"] = json!({ "id": device.token_id, "name": device.token_name });
    view["createdAt"] = json!(rfc3339(device.created_at));
    if let Some(revoked_at) = device.revoked_at {
        view["revokedAt"] = json!(rfc3339(revoked_at));
    }
    view["renewalRequested"] = json!(device.renewal_requested.is_some());
    view
}

struct DeviceQuery {
    view_full: bool,
    metadata_keys: Option<Vec<String>>,
    status: Option<String>,
    enrollment_token_id: Option<Uuid>,
    issuer: Option<String>,
    last_seen_before: Option<i64>,
    last_seen_after: Option<i64>,
    q: Option<String>,
    page_number: u64,
    page_size: u64,
}

fn parse_device_query(query: &HashMap<String, String>) -> Result<DeviceQuery, ApiError> {
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
        Some(s) if matches!(s.as_str(), "active" | "revoked" | "expired") => Some(s.clone()),
        Some(_) => return Err(ApiError::invalid_request("status must be active, revoked or expired")),
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
    Ok(DeviceQuery {
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

async fn list_devices(AxumState(app): AxumState<Arc<App>>, Query(query): Query<HashMap<String, String>>) -> Response {
    app.tick().await;
    let query = match parse_device_query(&query) {
        Ok(q) => q,
        Err(err) => return admin_error(&err),
    };
    let state = app.state.lock().await;
    let now = app.now();

    let mut devices: Vec<&Device> = state
        .devices
        .values()
        .filter(|d| {
            query.status.as_ref().is_none_or(|s| d.status(now) == s)
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
    devices.sort_by_key(|device| device.created_seq);

    let views: Vec<Value> = devices
        .into_iter()
        .map(|d| {
            if query.view_full {
                device_full(&app, &state, d)
            } else {
                device_summary(&app, &state, d, query.metadata_keys.as_deref())
            }
        })
        .collect();
    Json(paginate(views, query.page_number, query.page_size)).into_response()
}

async fn get_device(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let state = app.state.lock().await;
    match state.devices.get(&id) {
        Some(device) => Json(device_full(&app, &state, device)).into_response(),
        None => admin_error(&ApiError::not_found("unknown device")),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchDeviceRequest {
    friendly_name: String,
}

async fn patch_device(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>, body: Bytes) -> Response {
    app.tick().await;
    let request: PatchDeviceRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return admin_error(&ApiError::invalid_request("malformed JSON body")),
    };
    let len = request.friendly_name.chars().count();
    if !(1..=crate::name_eval::MAX_FRIENDLY_NAME_CHARS).contains(&len) {
        return admin_error(&ApiError::invalid_request("friendlyName must be 1..255 characters"));
    }
    let mut state = app.state.lock().await;
    let Some(device) = state.devices.get_mut(&id) else {
        return admin_error(&ApiError::not_found("unknown device"));
    };
    device.friendly_name = request.friendly_name;
    let device = state.devices.get(&id).expect("device exists");
    Json(device_full(&app, &state, device)).into_response()
}

async fn revoke_device(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let now = app.now();
    let mut state = app.state.lock().await;
    match state.revoke(id, now) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => admin_error(&err),
    }
}

async fn delete_device(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let mut state = app.state.lock().await;
    match state.delete_device(id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => admin_error(&err),
    }
}

async fn request_renewal(AxumState(app): AxumState<Arc<App>>, Path(id): Path<Uuid>) -> Response {
    app.tick().await;
    let mut state = app.state.lock().await;
    match state.request_renewal(id) {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(err) => admin_error(&err),
    }
}

// ==== §9.3 rotation ====

#[derive(Deserialize)]
struct StartRotationRequest {
    deadline: Option<String>,
}

fn rotation_view(state: &State, now: i64) -> Value {
    match &state.rotation {
        None => json!({ "phase": "idle", "activeDevicesOnOldRoot": 0 }),
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
                "activeDevicesOnOldRoot": state.active_devices_on_old_root(now),
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
        let request: StartRotationRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return admin_error(&ApiError::invalid_request("malformed JSON body")),
        };
        match request.deadline.as_deref() {
            None => None,
            Some("now") => Some(now),
            Some(raw) => match parse_rfc3339(raw) {
                Some(d) => Some(d),
                None => return admin_error(&ApiError::invalid_request("deadline must be RFC 3339 or \"now\"")),
            },
        }
    };
    let mut state = app.state.lock().await;
    match state.start_rotation(deadline, now) {
        Ok(()) => (StatusCode::ACCEPTED, Json(rotation_view(&state, now))).into_response(),
        Err(err) => admin_error(&err),
    }
}

async fn get_rotation(AxumState(app): AxumState<Arc<App>>) -> Response {
    app.tick().await;
    let state = app.state.lock().await;
    Json(rotation_view(&state, app.now())).into_response()
}
