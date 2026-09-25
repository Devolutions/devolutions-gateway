//! Agent-facing API (CONTRACT.md §5), under `<prefix>/api/agent-identity/v1`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State as AxumState};
use axum::http::header::{AUTHORIZATION, LOCATION, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde_json::{Map, Value, json};

use crate::app::{App, rfc3339};
use crate::oracle::{AuthenticatedDevice, Endpoint, Rejection, verify_request};
use crate::state::{ApiError, DropTarget, FailNextResponse, State};

/// Header set on a success response when `faults.drop_next_response` fires; the
/// dispatcher turns it into a connection abort without a response (§11).
pub(crate) const DROP_HEADER: &str = "x-mock-drop";
pub(crate) const INJECTED_HEADER: &str = "x-mock-injected";

pub(crate) fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/agent-identity/v1/trust-anchor", get(trust_anchor))
        .route("/api/agent-identity/v1/enroll", post(enroll))
        .route("/api/agent-identity/v1/renew", post(renew))
        .route("/api/agent-identity/v1/confirm", post(confirm))
        .route("/api/agent-identity/v1/check-in", post(check_in))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(app)
}

/// §5.4 error body: `{ "error", "message", "server_time" }` on every non-2xx
/// agent-facing response.
pub(crate) fn agent_error(app: &App, status: u16, code: &str, message: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(json!({
            "error": code,
            "message": message,
            "server_time": rfc3339(app.now()),
        })),
    )
        .into_response()
}

pub(crate) fn api_error_response(app: &App, err: &ApiError) -> Response {
    agent_error(app, err.status, err.code, &err.message)
}

pub(crate) fn rejection_response(app: &App, rejection: Rejection) -> Response {
    agent_error(app, rejection.http_status(), rejection.code(), rejection.code())
}

fn injected_response(app: &App, fault: FailNextResponse) -> Response {
    let mut response = if let Some(code) = fault.error {
        agent_error(app, fault.status, code, "injected mock response")
    } else {
        StatusCode::from_u16(fault.status)
            .expect("validated mock fault status")
            .into_response()
    };
    response
        .headers_mut()
        .insert(INJECTED_HEADER, "1".parse().expect("static value"));
    if (300..400).contains(&fault.status) {
        let target = format!("{}/__mock__/redirect-target", app.base_url);
        response.headers_mut().insert(
            LOCATION,
            HeaderValue::from_str(&target).expect("mock base URL is a valid header"),
        );
    }
    if let Some(secs) = fault.retry_after_secs {
        response.headers_mut().insert(
            RETRY_AFTER,
            HeaderValue::from_str(&secs.to_string()).expect("Retry-After seconds are valid"),
        );
    }
    response
}

async fn trust_anchor(AxumState(app): AxumState<Arc<App>>) -> Response {
    app.tick().await;
    let state = app.state.lock().await;
    let roots: Vec<Value> = state
        .roots
        .iter()
        .filter(|r| r.published)
        .map(|r| {
            json!({
                "certificate": crate::ca::base64_der(&r.cert_der),
                "thumbprint": r.thumbprint,
                "not_before": rfc3339(r.not_before),
                "not_after": rfc3339(r.not_after),
            })
        })
        .collect();
    Json(json!({ "roots": roots })).into_response()
}

/// Parses `Authorization: Bearer <token>`; the token must be well-formed
/// (`dvaet1.<bag>.<secret>`, 32-byte secret) to even reach the lookup (§5.4
/// `token_invalid`).
fn parse_bearer(headers: &HeaderMap) -> Result<[u8; 32], ApiError> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::token_invalid)?;
    let parts: Vec<&str> = header.split('.').collect();
    if parts.len() != 3 || parts[0] != "dvaet1" {
        return Err(ApiError::token_invalid());
    }
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .ok()
        .and_then(|s| <[u8; 32]>::try_from(s).ok())
        .ok_or_else(ApiError::token_invalid)?;
    Ok(secret)
}

/// Parses an enroll/renew body: `{ "csr": "<base64 DER>", "metadata": {...} }`.
fn parse_csr_body(body: &[u8]) -> Result<(Vec<u8>, Map<String, Value>), ApiError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ApiError::invalid_request("malformed JSON body"))?;
    let object = value
        .as_object()
        .ok_or_else(|| ApiError::invalid_request("body must be a JSON object"))?;
    let csr = object
        .get("csr")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::invalid_request("missing `csr`"))?;
    let csr_der = base64::engine::general_purpose::STANDARD
        .decode(csr)
        .map_err(|_| ApiError::invalid_request("`csr` is not valid base64"))?;
    let metadata = object
        .get("metadata")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| ApiError::invalid_request("`metadata` must be an object"))?;
    Ok((csr_der, metadata))
}

async fn enroll(AxumState(app): AxumState<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    app.tick().await;
    {
        let mut state = app.state.lock().await;
        state.requests.enroll_total += 1;
        state.requests.request_sequence.push("enroll");
    }
    let secret = match parse_bearer(&headers) {
        Ok(secret) => secret,
        Err(err) => return api_error_response(&app, &err),
    };
    let mut state = app.state.lock().await;
    state.observe_enroll(&secret);
    let Some(token_id) = state.token_id(&secret) else {
        return api_error_response(&app, &ApiError::token_invalid());
    };
    if state.retry_barrier == Some(DropTarget::Enroll) && state.barrier_triggered == Some(DropTarget::Enroll) {
        state.requests.enroll_retry_503 += 1;
        return injected_response(
            &app,
            FailNextResponse {
                endpoint: DropTarget::Enroll,
                status: 503,
                error: None,
                retry_after_secs: None,
            },
        );
    }
    if let Some(fault) = state.fail_next_response(DropTarget::Enroll) {
        return injected_response(&app, fault);
    }
    drop(state);
    let (csr_der, metadata) = match parse_csr_body(&body) {
        Ok(parsed) => parsed,
        Err(err) => return api_error_response(&app, &err),
    };

    let mut state = app.state.lock().await;
    let now = app.now();
    let outcome = match state.enroll(&secret, &csr_der, metadata, now, &app.base_url) {
        Ok(outcome) => outcome,
        Err(err) => {
            if err.code == "device_revoked" {
                *state.requests.enroll_revoked_by_token.entry(token_id).or_default() += 1;
            }
            return api_error_response(&app, &err);
        }
    };
    let should_drop = state.faults.drop_next_response == Some(DropTarget::Enroll);
    if should_drop {
        // One-shot: process and commit, then abort without a response (§11).
        state.faults.drop_next_response = None;
        state.barrier_triggered = Some(DropTarget::Enroll);
    }
    let config = state
        .devices
        .get(&outcome.device_id)
        .expect("enrolled device exists")
        .config
        .clone();
    drop(state);

    let body = json!({
        "authority_id": app.authority_id,
        "device_id": outcome.device_id,
        "certificate_chain": outcome
            .certificate_chain
            .iter()
            .map(|c| crate::ca::base64_der(c))
            .collect::<Vec<_>>(),
        "config": config,
    });
    let mut response = Json(body).into_response();
    if should_drop {
        response
            .headers_mut()
            .insert(DROP_HEADER, "1".parse().expect("static value"));
    }
    response
}

async fn renew(AxumState(app): AxumState<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    app.tick().await;
    let now = app.now();
    let mut state = app.state.lock().await;
    state.requests.renew += 1;
    state.requests.request_sequence.push("renew");
    let keyid = headers
        .get("signature-input")
        .and_then(|value| value.to_str().ok())
        .and_then(|input| input.split_once(";keyid=\""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(keyid, _)| keyid.to_owned());
    state.requests.renew_attempt_keyids.push(keyid);
    if state.retry_barrier == Some(DropTarget::Renew) && state.barrier_triggered == Some(DropTarget::Renew) {
        state.requests.renew_retry_503 += 1;
        return injected_response(
            &app,
            FailNextResponse {
                endpoint: DropTarget::Renew,
                status: 503,
                error: None,
                retry_after_secs: None,
            },
        );
    }
    if let Some(fault) = state.fail_next_response(DropTarget::Renew) {
        return injected_response(&app, fault);
    }

    // §6 verification, checks in the contract's order.
    let auth = authenticate(&mut state, Endpoint::Renew, &headers, &body, now);
    let auth = match auth {
        Ok(auth) => auth,
        Err(rejection) => return rejection_response(&app, rejection),
    };
    state.record_event(
        auth.device_id(),
        "renew_received",
        json!({ "cert_thumbprint": auth.cert_thumbprint() }),
    );

    let (csr_der, metadata) = match parse_csr_body(&body) {
        Ok(parsed) => parsed,
        Err(err) => return api_error_response(&app, &err),
    };
    let chain = match state.renew(&auth, &csr_der, metadata, now) {
        Ok(chain) => chain,
        Err(err) => return api_error_response(&app, &err),
    };
    let should_drop = state.faults.drop_next_response == Some(DropTarget::Renew);
    if should_drop {
        state.faults.drop_next_response = None;
        state.barrier_triggered = Some(DropTarget::Renew);
    }
    drop(state);

    let mut response = Json(json!({
        "certificate_chain": chain.iter().map(|c| crate::ca::base64_der(c)).collect::<Vec<_>>(),
    }))
    .into_response();
    if should_drop {
        response
            .headers_mut()
            .insert(DROP_HEADER, "1".parse().expect("static value"));
    }
    response
}

async fn confirm(AxumState(app): AxumState<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    app.tick().await;
    let mut state = app.state.lock().await;
    let now = app.now();
    state.requests.confirm += 1;
    state.requests.request_sequence.push("confirm");
    if state.retry_barrier == Some(DropTarget::Confirm) && state.barrier_triggered == Some(DropTarget::Confirm) {
        state.requests.confirm_retry_503 += 1;
        return injected_response(
            &app,
            FailNextResponse {
                endpoint: DropTarget::Confirm,
                status: 503,
                error: None,
                retry_after_secs: None,
            },
        );
    }
    if let Some(fault) = state.fail_next_response(DropTarget::Confirm) {
        if state.retry_barrier == Some(DropTarget::Confirm) {
            state.barrier_triggered = Some(DropTarget::Confirm);
        }
        return injected_response(&app, fault);
    }
    let auth = match authenticate(&mut state, Endpoint::Confirm, &headers, &body, now) {
        Ok(auth) => auth,
        Err(rejection) => return rejection_response(&app, rejection),
    };
    if !body.is_empty() {
        return api_error_response(&app, &ApiError::invalid_request("confirm body must be empty"));
    }
    state.confirm(&auth, now);
    state.requests.request_sequence.push("confirm_204");
    let should_drop = state.faults.drop_next_response == Some(DropTarget::Confirm);
    if should_drop {
        state.faults.drop_next_response = None;
        state.barrier_triggered = Some(DropTarget::Confirm);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    if should_drop {
        response
            .headers_mut()
            .insert(DROP_HEADER, "1".parse().expect("static value"));
    }
    response
}

async fn check_in(AxumState(app): AxumState<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    app.tick().await;
    let mut state = app.state.lock().await;
    let now = app.now();
    state.requests.check_in += 1;
    state.requests.request_sequence.push("check-in");
    if let Some(fault) = state.fail_next_response(DropTarget::CheckIn) {
        return injected_response(&app, fault);
    }
    let auth = match authenticate(&mut state, Endpoint::CheckIn, &headers, &body, now) {
        Ok(auth) => auth,
        Err(rejection) => return rejection_response(&app, rejection),
    };
    let metadata = match parse_check_in_body(&body) {
        Ok(metadata) => metadata,
        Err(error) => return api_error_response(&app, &error),
    };
    let device = state
        .devices
        .get_mut(&auth.device_id())
        .expect("authenticated device exists");
    device.metadata = metadata;
    device.last_seen_at = Some(now);
    let renewal_requested = device.renewal_requested.is_some();
    let config = device.config.clone();
    let revision = device.config_revision();
    state.record_event(
        auth.device_id(),
        "check_in_received",
        json!({ "revision": revision, "renewal_requested": renewal_requested }),
    );
    let should_drop = state.faults.drop_next_response == Some(DropTarget::CheckIn);
    if should_drop {
        state.faults.drop_next_response = None;
    }
    let mut response = Json(json!({ "config": config, "renewal_requested": renewal_requested })).into_response();
    if should_drop {
        response
            .headers_mut()
            .insert(DROP_HEADER, "1".parse().expect("static value"));
    }
    response
}

fn parse_check_in_body(body: &[u8]) -> Result<Map<String, Value>, ApiError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ApiError::invalid_request("malformed JSON body"))?;
    let metadata = value
        .get("metadata")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| ApiError::invalid_request("`metadata` must be an object"))?;
    crate::name_eval::validate_metadata(&metadata).map_err(ApiError::invalid_request)?;
    Ok(metadata)
}

fn authenticate(
    state: &mut State,
    endpoint: Endpoint,
    headers: &HeaderMap,
    body: &[u8],
    now: i64,
) -> Result<AuthenticatedDevice, Rejection> {
    if headers.get_all("signature-input").iter().count() != 1
        || headers.get_all("signature").iter().count() != 1
        || matches!(endpoint, Endpoint::Renew | Endpoint::CheckIn)
            && headers.get_all("content-digest").iter().count() != 1
    {
        return Err(Rejection::SignatureInvalid);
    }
    let header_bytes = |name: &str| headers.get(name).map(|value| value.as_bytes().to_vec());
    let signature_input = header_bytes("signature-input");
    let signature = header_bytes("signature");
    let content_digest = header_bytes("content-digest");
    let State {
        devices,
        cert_index,
        nonces,
        ..
    } = state;
    let mut lookup = |keyid: &str| crate::state::lookup_cert(devices, cert_index, keyid);
    verify_request(
        endpoint,
        "POST",
        signature_input.as_deref(),
        signature.as_deref(),
        content_digest.as_deref(),
        body,
        now,
        &mut lookup,
        nonces,
    )
}
