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

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/__mock__/faults", post(faults))
        .route("/__mock__/reset", post(reset))
        .route("/__mock__/time/advance", post(time_advance))
        .route("/__mock__/events", get(events))
        .route("/__mock__/handshake", post(handshake))
        .route("/__mock__/requests", get(requests))
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
    Json(json!({
        "enroll": enroll,
        "enroll_total": state.requests.enroll_total,
        "renew": state.requests.renew,
        "connect": state.requests.connect,
        "authenticated_connects": state.requests.authenticated_connects,
        "correlated_acks": state.requests.correlated_acks,
        "overlap_open": state.requests.overlap_open,
        "active_streams": state.streams.len(),
        "paused_hellos": state.paused_hellos.len(),
    }))
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
    Json(json!({ "paused": request.pause })).into_response()
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
        }),
        "fail_next_response": faults.fail_next_response.map(|fault| json!({
            "endpoint": match fault.endpoint {
                DropTarget::Enroll => "enroll",
                DropTarget::Renew => "renew",
            },
            "status": fault.status,
            "error": fault.error,
        })),
        "clock_skew_secs": faults.clock_skew_secs,
        "leaf_lifetime_secs": faults.leaf_lifetime_secs,
        "channel_available": faults.channel_available,
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
                        _ => return invalid("fail_next_response.endpoint must be enroll or renew"),
                    };
                    let Some(status) = fields
                        .get("status")
                        .and_then(Value::as_u64)
                        .and_then(|status| u16::try_from(status).ok())
                        .filter(|status| (400..=599).contains(status))
                    else {
                        return invalid("fail_next_response.status must be 400..599");
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
                    });
                }
                _ => return invalid("fail_next_response must be an object or null"),
            },
            "drop_next_response" => match value {
                Value::Null => state.faults.drop_next_response = None,
                Value::String(s) if s == "enroll" => state.faults.drop_next_response = Some(DropTarget::Enroll),
                Value::String(s) if s == "renew" => state.faults.drop_next_response = Some(DropTarget::Renew),
                _ => return invalid("drop_next_response must be \"enroll\", \"renew\" or null"),
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
                Value::Bool(b) => state.faults.channel_available = *b,
                _ => return invalid("channel_available must be a boolean"),
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
    app.clock.advance_by(secs);
    app.tick().await;
    let now = app.now();
    Json(json!({ "now": now, "server_time": rfc3339(now) })).into_response()
}
