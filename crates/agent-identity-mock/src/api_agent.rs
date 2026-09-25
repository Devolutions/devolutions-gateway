//! Agent-facing API (CONTRACT.md §5), under `<prefix>/api/agent-identity/v1`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State as AxumState};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde_json::{Map, Value, json};

use crate::app::{App, rfc3339};
use crate::httpsig::{Endpoint, Rejection, verify_request};
use crate::state::{ApiError, DropTarget, FailNextResponse};

/// Header set on a success response when `faults.drop_next_response` fires; the
/// dispatcher turns it into a connection abort without a response (§11).
pub const DROP_HEADER: &str = "x-mock-drop";
pub const INJECTED_HEADER: &str = "x-mock-injected";

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/agent-identity/v1/trust-anchor", get(trust_anchor))
        .route("/api/agent-identity/v1/enroll", post(enroll))
        .route("/api/agent-identity/v1/renew", post(renew))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(app)
}

/// §5.4 error body: `{ "error", "message", "server_time" }` on every non-2xx
/// agent-facing response.
pub fn agent_error(app: &App, status: u16, code: &str, message: &str) -> Response {
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

pub fn api_error_response(app: &App, err: &ApiError) -> Response {
    agent_error(app, err.status, err.code, &err.message)
}

pub fn rejection_response(app: &App, rejection: Rejection) -> Response {
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
    app.state.lock().await.requests.enroll_total += 1;
    let secret = match parse_bearer(&headers) {
        Ok(secret) => secret,
        Err(err) => return api_error_response(&app, &err),
    };
    let mut state = app.state.lock().await;
    state.observe_enroll(&secret);
    if state.token_id(&secret).is_none() {
        return api_error_response(&app, &ApiError::token_invalid());
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
    let outcome = match state.enroll(&secret, &csr_der, metadata, now) {
        Ok(outcome) => outcome,
        Err(err) => return api_error_response(&app, &err),
    };
    let should_drop = state.faults.drop_next_response == Some(DropTarget::Enroll);
    if should_drop {
        // One-shot: process and commit, then abort without a response (§11).
        state.faults.drop_next_response = None;
    }
    let channel_available = state.faults.channel_available;
    drop(state);

    let mut body = json!({
        "authority_id": app.authority_id,
        "device_id": outcome.device_id,
        "friendly_name": outcome.friendly_name,
        "certificate_chain": outcome
            .certificate_chain
            .iter()
            .map(|c| crate::ca::base64_der(c))
            .collect::<Vec<_>>(),
        "config": { "version": 1 },
    });
    if channel_available {
        // §5.2: absent when the server cannot host the channel.
        body["channel_url"] = json!(app.base_url);
    }
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
    if let Some(fault) = state.fail_next_response(DropTarget::Renew) {
        return injected_response(&app, fault);
    }

    // §6 verification, checks in the contract's order.
    let auth = {
        let header_bytes = |name: &str| headers.get(name).map(|v| v.as_bytes().to_vec());
        let signature_input = header_bytes("signature-input");
        let signature = header_bytes("signature");
        let content_digest = header_bytes("content-digest");
        let state = &mut *state;
        let crate::state::State {
            devices,
            cert_index,
            nonces,
            ..
        } = state;
        let mut lookup = |keyid: &str| crate::state::lookup_cert(devices, cert_index, keyid);
        verify_request(
            Endpoint::Renew,
            "POST",
            signature_input.as_deref(),
            signature.as_deref(),
            content_digest.as_deref(),
            &body,
            now,
            &mut lookup,
            nonces,
        )
    };
    let auth = match auth {
        Ok(auth) => auth,
        Err(rejection) => return rejection_response(&app, rejection),
    };

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
