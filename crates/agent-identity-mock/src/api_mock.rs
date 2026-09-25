//! Mock-only control API (CONTRACT.md §11), under `<prefix>/__mock__`. No auth.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State as AxumState};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::app::{App, rfc3339};
use crate::state::{ApiError, DropTarget, FailNextResponse, Faults, PushKind};

pub(crate) fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/__mock__/faults", post(faults))
        .route("/__mock__/config", post(update_config))
        .route("/__mock__/config/stale", post(stale_config))
        .route("/__mock__/reset", post(reset))
        .route("/__mock__/time/advance", post(time_advance))
        .route("/__mock__/time/freeze", post(time_freeze))
        .route("/__mock__/events", get(events))
        .route("/__mock__/handshake", post(handshake).get(handshake_state))
        .route("/__mock__/retry-barrier", post(retry_barrier))
        .route("/__mock__/requests", get(requests))
        .route("/__mock__/redirect-target", get(redirect_target).post(redirect_target))
        .route("/__mock__/reconnect", post(reconnect))
        .with_state(app)
}

#[derive(Deserialize)]
struct RequestQuery {
    token_id: Option<Uuid>,
}

async fn requests(AxumState(app): AxumState<Arc<App>>, Query(query): Query<RequestQuery>) -> Json<Value> {
    let state = app.state.lock().await;
    let enroll = query.token_id.map_or_else(
        || state.requests.enroll_by_token.values().sum(),
        |id| state.requests.enroll_by_token.get(&id).copied().unwrap_or(0),
    );
    let enroll_device_revoked = query.token_id.map_or_else(
        || state.requests.enroll_revoked_by_token.values().sum(),
        |id| state.requests.enroll_revoked_by_token.get(&id).copied().unwrap_or(0),
    );
    Json(json!({
        "enroll": enroll,
        "enroll_device_revoked": enroll_device_revoked,
        "enroll_total": state.requests.enroll_total,
        "enroll_retry_503": state.requests.enroll_retry_503,
        "renew": state.requests.renew,
        "renew_attempt_keyids": state.requests.renew_attempt_keyids,
        "renew_retry_503": state.requests.renew_retry_503,
        "confirm": state.requests.confirm,
        "confirm_retry_503": state.requests.confirm_retry_503,
        "check_in": state.requests.check_in,
        "connect": state.requests.connect,
        "redirect_hits": state.requests.redirect_hits,
        "request_sequence": state.requests.request_sequence,
        "authenticated_connects": state.requests.authenticated_connects,
        "correlated_acks": state.requests.correlated_acks,
        "overlap_open": state.requests.overlap_open,
        "active_streams": state.streams.len(),
        "paused_hellos": state.paused_hellos.len(),
    }))
}

async fn redirect_target(AxumState(app): AxumState<Arc<App>>) -> StatusCode {
    app.state.lock().await.requests.redirect_hits += 1;
    StatusCode::IM_A_TEAPOT
}

#[derive(Deserialize)]
struct EventQuery {
    device_id: Uuid,
}

async fn events(AxumState(app): AxumState<Arc<App>>, Query(query): Query<EventQuery>) -> Json<Value> {
    let state = app.state.lock().await;
    Json(json!({
        "events": state.events.iter()
            .filter(|event| event.device_id == query.device_id)
            .map(|event| &event.body)
            .collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct HandshakeRequest {
    pause: bool,
}

async fn handshake(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    let request: HandshakeRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return control_error(&ApiError::invalid_request("body requires a boolean pause field")),
    };
    app.handshake_gate.send_replace(!request.pause);
    handshake_view(&app).await.into_response()
}

async fn handshake_state(AxumState(app): AxumState<Arc<App>>) -> Json<Value> {
    handshake_view(&app).await
}

async fn handshake_view(app: &App) -> Json<Value> {
    let gate = app.handshake_gate.subscribe();
    let paused = !*gate.borrow();
    let state = app.state.lock().await;
    let mut paused_stream_ids = state.paused_hellos.iter().copied().collect::<Vec<_>>();
    paused_stream_ids.sort_unstable();
    Json(json!({ "paused": paused, "paused_stream_ids": paused_stream_ids }))
}

#[derive(Deserialize)]
struct RetryBarrierRequest {
    endpoint: String,
    pause: bool,
}

async fn retry_barrier(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    let request: RetryBarrierRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return control_error(&ApiError::invalid_request("body requires endpoint and boolean pause")),
    };
    let endpoint = match request.endpoint.as_str() {
        "enroll" => DropTarget::Enroll,
        "renew" => DropTarget::Renew,
        "confirm" => DropTarget::Confirm,
        _ => return control_error(&ApiError::invalid_request("endpoint must be enroll, renew or confirm")),
    };
    let mut state = app.state.lock().await;
    if request.pause {
        state.retry_barrier = Some(endpoint);
        state.barrier_triggered = None;
    } else if state.retry_barrier == Some(endpoint) {
        state.retry_barrier = None;
    }
    Json(json!({ "paused": state.retry_barrier == Some(endpoint) })).into_response()
}

#[derive(Deserialize)]
struct ReconnectRequest {
    device_id: Uuid,
}

async fn reconnect(AxumState(app): AxumState<Arc<App>>, Json(request): Json<ReconnectRequest>) -> Response {
    let mut state = app.state.lock().await;
    if !state.devices.contains_key(&request.device_id) {
        return control_error(&ApiError::not_found("unknown device"));
    }
    state.push_to_device(request.device_id, &PushKind::Reconnect("mock"));
    StatusCode::ACCEPTED.into_response()
}

async fn update_config(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return control_error(&ApiError::invalid_request("malformed JSON body")),
    };
    let Some(fields) = value.get("fields").and_then(Value::as_object) else {
        return control_error(&ApiError::invalid_request("fields must be a JSON object"));
    };
    if fields
        .keys()
        .any(|name| matches!(name.as_str(), "version" | "revision" | "agent_channel_url"))
    {
        return control_error(&ApiError::invalid_request("config fields cannot replace reserved keys"));
    }
    let mut state = app.state.lock().await;
    let updated = state.merge_config_fields(fields);
    Json(json!({ "updatedDevices": updated })).into_response()
}

#[derive(Deserialize)]
struct StaleConfigRequest {
    device_id: Uuid,
    revision: u64,
}

async fn stale_config(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    let request: StaleConfigRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return control_error(&ApiError::invalid_request("body requires device_id and revision")),
    };
    let mut state = app.state.lock().await;
    match state.replay_stale_config(request.device_id, request.revision) {
        Ok(sent) => Json(json!({ "sent": sent })).into_response(),
        Err(error) => control_error(&error),
    }
}

fn control_error(err: &ApiError) -> Response {
    (
        StatusCode::from_u16(err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(json!({ "error": err.code, "message": err.message })),
    )
        .into_response()
}

fn faults_view(faults: &Faults) -> Value {
    json!({
        "drop_next_response": faults.drop_next_response.map(|t| match t {
            DropTarget::Enroll => "enroll",
            DropTarget::Renew => "renew",
            DropTarget::Confirm => "confirm",
            DropTarget::CheckIn => "check-in",
        }),
        "fail_next_response": faults.fail_next_response.map(|fault| json!({
            "endpoint": match fault.endpoint {
                DropTarget::Enroll => "enroll",
                DropTarget::Renew => "renew",
                DropTarget::Confirm => "confirm",
                DropTarget::CheckIn => "check-in",
            },
            "status": fault.status,
            "error": fault.error,
            "retry_after_secs": fault.retry_after_secs,
        })),
        "clock_skew_secs": faults.clock_skew_secs,
        "leaf_lifetime_secs": faults.leaf_lifetime_secs,
        "channel_available": faults.channel_available,
        "channel_broken": faults.channel_broken,
        "malformed_channel_url": faults.malformed_channel_url,
        "rotation_rate_limit_per_sec": faults.rotation_rate_limit_per_sec,
    })
}

/// `POST faults` merges fields (§11): absent keys are unchanged, `null` clears an
/// optional field.
async fn faults(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    app.tick().await;
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return control_error(&ApiError::invalid_request("malformed JSON body")),
    };
    let Some(patch) = value.as_object() else {
        return control_error(&ApiError::invalid_request("body must be a JSON object"));
    };

    let invalid = |msg: &str| control_error(&ApiError::invalid_request(msg));
    let mut state = app.state.lock().await;
    for (key, value) in patch {
        match key.as_str() {
            "fail_next_response" => match value {
                Value::Null => state.faults.fail_next_response = None,
                Value::Object(fields) => {
                    let endpoint = match fields.get("endpoint").and_then(Value::as_str) {
                        Some("enroll") => DropTarget::Enroll,
                        Some("renew") => DropTarget::Renew,
                        Some("confirm") => DropTarget::Confirm,
                        Some("check-in") => DropTarget::CheckIn,
                        _ => return invalid("fail_next_response.endpoint must be enroll, renew, confirm or check-in"),
                    };
                    let Some(status) = fields
                        .get("status")
                        .and_then(Value::as_u64)
                        .and_then(|status| u16::try_from(status).ok())
                        .filter(|status| (300..=599).contains(status))
                    else {
                        return invalid("fail_next_response.status must be 300..599");
                    };
                    let retry_after_secs = match fields.get("retry_after_secs") {
                        None => None,
                        Some(Value::Number(value)) => match value.as_u64() {
                            Some(secs) => Some(secs),
                            None => return invalid("fail_next_response.retry_after_secs must be nonnegative"),
                        },
                        Some(_) => return invalid("fail_next_response.retry_after_secs must be nonnegative"),
                    };
                    let error = match fields.get("error") {
                        None => None,
                        Some(Value::String(value)) => Some(match value.as_str() {
                            "token_invalid" => "token_invalid",
                            "token_exhausted" => "token_exhausted",
                            "token_expired" => "token_expired",
                            "device_revoked" => "device_revoked",
                            "device_unknown" => "device_unknown",
                            "certificate_expired" => "certificate_expired",
                            "signature_invalid" => "signature_invalid",
                            "clock_skew" => "clock_skew",
                            "invalid_request" => "invalid_request",
                            _ => return invalid("fail_next_response.error must be a §5.4 error code"),
                        }),
                        Some(_) => return invalid("fail_next_response.error must be a §5.4 error code"),
                    };
                    state.faults.fail_next_response = Some(FailNextResponse {
                        endpoint,
                        status,
                        error,
                        retry_after_secs,
                    });
                }
                _ => return invalid("fail_next_response must be an object or null"),
            },
            "drop_next_response" => match value {
                Value::Null => state.faults.drop_next_response = None,
                Value::String(s) if s == "enroll" => state.faults.drop_next_response = Some(DropTarget::Enroll),
                Value::String(s) if s == "renew" => state.faults.drop_next_response = Some(DropTarget::Renew),
                Value::String(s) if s == "confirm" => state.faults.drop_next_response = Some(DropTarget::Confirm),
                Value::String(s) if s == "check-in" => state.faults.drop_next_response = Some(DropTarget::CheckIn),
                _ => return invalid("drop_next_response must be enroll, renew, confirm, check-in or null"),
            },
            "clock_skew_secs" => match value {
                Value::Null => state.faults.clock_skew_secs = None,
                Value::Number(n) => match n.as_i64() {
                    Some(secs) => state.faults.clock_skew_secs = Some(secs),
                    None => return invalid("clock_skew_secs must be an integer or null"),
                },
                _ => return invalid("clock_skew_secs must be an integer or null"),
            },
            "leaf_lifetime_secs" => match value {
                Value::Null => state.faults.leaf_lifetime_secs = None,
                Value::Number(n) => match n.as_i64() {
                    Some(secs) if secs > 0 => state.faults.leaf_lifetime_secs = Some(secs),
                    _ => return invalid("leaf_lifetime_secs must be a positive integer or null"),
                },
                _ => return invalid("leaf_lifetime_secs must be a positive integer or null"),
            },
            "channel_available" => match value {
                Value::Bool(b) => state.update_channel_available(*b, &app.base_url),
                _ => return invalid("channel_available must be a boolean"),
            },
            "channel_broken" => match value {
                Value::Bool(b) => state.faults.channel_broken = *b,
                _ => return invalid("channel_broken must be a boolean"),
            },
            "malformed_channel_url" => match value {
                Value::Bool(b) => state.faults.malformed_channel_url = *b,
                _ => return invalid("malformed_channel_url must be a boolean"),
            },
            "rotation_rate_limit_per_sec" => match value {
                Value::Null => state.faults.rotation_rate_limit_per_sec = None,
                Value::Number(n) => match n.as_u64().and_then(|v| u32::try_from(v).ok()) {
                    Some(rate) if rate > 0 => state.faults.rotation_rate_limit_per_sec = Some(rate),
                    _ => return invalid("rotation_rate_limit_per_sec must be a positive integer or null"),
                },
                _ => return invalid("rotation_rate_limit_per_sec must be a positive integer or null"),
            },
            _ => return invalid("unknown fault field"),
        }
    }
    app.clock.set_skew(state.faults.clock_skew_secs);
    state.tick(app.now());
    Json(faults_view(&state.faults)).into_response()
}

/// `POST reset` (§11): clears tokens, devices, nonces, faults, rotation and the clock
/// offset; creates a fresh root; keeps `authority_id`, the TLS certificate and the
/// admin token.
async fn reset(AxumState(app): AxumState<Arc<App>>) -> Response {
    let mut state = app.state.lock().await;
    app.clock.reset();
    app.handshake_gate.send_replace(true);
    match state.reset(app.now()) {
        Ok(()) => Json(json!({ "authority_id": app.authority_id })).into_response(),
        Err(err) => control_error(&ApiError::internal(format!("reset failed: {err:#}"))),
    }
}

/// `POST time/advance { secs }`: advances the mock clock.
async fn time_advance(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return control_error(&ApiError::invalid_request("malformed JSON body")),
    };
    let secs = value
        .as_object()
        .and_then(|o: &Map<String, Value>| o.get("secs"))
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::invalid_request("`secs` must be an integer"));
    let secs = match secs {
        Ok(secs) => secs,
        Err(err) => return control_error(&err),
    };
    let mut state = app.state.lock().await;
    app.clock.advance_by(secs);
    let now = app.now();
    state.tick(now);
    Json(json!({ "now": now, "server_time": rfc3339(now) })).into_response()
}

async fn time_freeze(AxumState(app): AxumState<Arc<App>>, body: Bytes) -> Response {
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return control_error(&ApiError::invalid_request("malformed JSON body")),
    };
    let Some(now) = value.get("now").and_then(Value::as_i64).filter(|now| *now != i64::MIN) else {
        return control_error(&ApiError::invalid_request("`now` must be a Unix second"));
    };
    let mut state = app.state.lock().await;
    app.clock.freeze_at(now);
    state.tick(now);
    let published_roots = state
        .roots
        .iter()
        .filter(|root| root.published)
        .map(|root| &root.thumbprint)
        .collect::<Vec<_>>();
    Json(json!({ "now": now, "published_roots": published_roots })).into_response()
}
