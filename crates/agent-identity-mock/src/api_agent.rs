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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};

use crate::app::{App, rfc3339};
use crate::oracle::{AuthenticatedIdentity, Endpoint, Rejection, verify_request};
use crate::state::{ApiError, DropTarget, FailNextResponse, State};

/// Marks a processed mock fault; the dispatcher aborts the connection without responding.
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
/// (`dvaet1.<bag>.<secret>` with a 32-byte secret) to even reach the lookup, and a repeated header is `token_invalid`
/// ([CONTRACT.md][contract], "2.1 Authority behavior").
/// The token authenticates by its exact `secret` text alone and the `bag` is never checked (§2); the engine decodes only
/// the canonical encoding (§1), so another encoding of the same secret bytes is `token_invalid`.
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.md#21-authority-behavior
fn parse_bearer(headers: &HeaderMap) -> Result<[u8; 32], ApiError> {
    if headers.get_all(AUTHORIZATION).iter().count() != 1 {
        return Err(ApiError::token_invalid());
    }
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::token_invalid)?;
    token
        .strip_prefix("dvaet1.")
        .and_then(|rest| rest.rsplit_once('.'))
        .and_then(|(_bag, secret)| URL_SAFE_NO_PAD.decode(secret).ok())
        .and_then(|secret| <[u8; 32]>::try_from(secret).ok())
        .ok_or_else(ApiError::token_invalid)
}

/// Returns the enrollment token the mock issues for `secret`: `dvaet1.<bag>.<secret>` ([CONTRACT.md][contract], "2. Enrollment token").
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.md#2-enrollment-token
pub(crate) fn enrollment_token(base_url: &str, secret: &[u8; 32]) -> String {
    let bag = URL_SAFE_NO_PAD.encode(json!({ "u": base_url }).to_string());
    format!("dvaet1.{bag}.{}", URL_SAFE_NO_PAD.encode(secret))
}

/// Parses an enroll/renew body: `{ "csr": "<base64 DER>", "metadata": {...} }`.
fn parse_csr_body(body: &[u8]) -> Result<(Vec<u8>, Map<String, Value>), ApiError> {
    let value = crate::json::parse_unique_members(body)
        .map_err(|error| ApiError::invalid_request(format!("malformed JSON body: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| ApiError::invalid_request("body must be a JSON object"))?;
    let csr = object
        .get("csr")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::invalid_request("missing `csr`"))?;
    // The engine rejects anything but the canonical form (§1), such as missing padding or nonzero pad bits.
    let csr_der = base64::engine::general_purpose::STANDARD
        .decode(csr)
        .map_err(|_| ApiError::invalid_request("`csr` is not canonical base64"))?;
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
            if err.code == "identity_revoked" {
                *state.requests.enroll_revoked_by_token.entry(token_id).or_default() += 1;
            }
            return api_error_response(&app, &err);
        }
    };
    let should_drop = state.faults.drop_next_response == Some(DropTarget::Enroll);
    if should_drop {
        // The mock-only drop fault commits the request, then aborts without a response.
        state.faults.drop_next_response = None;
        state.barrier_triggered = Some(DropTarget::Enroll);
    }
    let config = state
        .identities
        .get(&outcome.identity_id)
        .expect("enrolled identity exists")
        .config
        .clone();
    drop(state);

    let body = json!({
        "authority_id": app.authority_id,
        "identity_id": outcome.identity_id,
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
        auth.identity_id(),
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
    let identity = state
        .identities
        .get_mut(&auth.identity_id())
        .expect("authenticated identity exists");
    identity.metadata = metadata;
    identity.last_seen_at = Some(now);
    let renewal_requested = identity.renewal_requested.is_some();
    let config = identity.config.clone();
    let revision = identity.config_revision();
    state.record_event(
        auth.identity_id(),
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
    let value = crate::json::parse_unique_members(body)
        .map_err(|error| ApiError::invalid_request(format!("malformed JSON body: {error}")))?;
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
) -> Result<AuthenticatedIdentity, Rejection> {
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
        identities,
        cert_index,
        nonces,
        ..
    } = state;
    let mut lookup = |keyid: &str| crate::state::lookup_cert(identities, cert_index, keyid);
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

#[cfg(test)]
mod tests {
    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderMap, HeaderValue};
    use rstest::rstest;

    use super::{enrollment_token, parse_bearer, parse_check_in_body, parse_csr_body};

    fn code<T>(result: Result<T, crate::state::ApiError>) -> Result<(), &'static str> {
        result.map(|_| ()).map_err(|error| error.code)
    }

    /// CONTRACT.md §1: "A JSON request body that repeats a member name at any depth [...] → `invalid_request`".
    #[rstest]
    #[case::csr(r#"{"csr":"AAEC","csr":"AAEC","metadata":{}}"#)]
    #[case::metadata(r#"{"csr":"AAEC","metadata":{},"metadata":{}}"#)]
    #[case::metadata_key(r#"{"csr":"AAEC","metadata":{"hostname":"a","hostname":"b"}}"#)]
    #[case::escaped_name(r#"{"csr":"AAEC","c\u0073r":"AAEC","metadata":{}}"#)]
    #[case::unknown_member(r#"{"csr":"AAEC","metadata":{},"x":1,"x":1}"#)]
    #[case::object_in_array(r#"{"csr":"AAEC","metadata":{},"x":[{"y":1,"y":1}]}"#)]
    fn csr_body_with_a_repeated_member_name_is_invalid_request(#[case] body: &str) {
        assert_eq!(code(parse_csr_body(body.as_bytes())), Err("invalid_request"));
    }

    #[rstest]
    #[case::metadata(r#"{"metadata":{},"metadata":{}}"#)]
    #[case::metadata_key(r#"{"metadata":{"hostname":"a","hostname":"b"}}"#)]
    fn check_in_body_with_a_repeated_member_name_is_invalid_request(#[case] body: &str) {
        assert_eq!(code(parse_check_in_body(body.as_bytes())), Err("invalid_request"));
    }

    /// One name in several objects is not a repetition, and receivers ignore unknown fields (CONTRACT.md §1).
    #[test]
    fn same_name_in_different_objects_is_accepted() {
        let body = r#"{"csr":"AAEC","metadata":{"csr":"a"},"x":{"csr":[1,true,null,{"csr":0.5}]}}"#;
        assert_eq!(code(parse_csr_body(body.as_bytes())), Ok(()));
    }

    /// CONTRACT.md §1: "a request body holding another form [than the canonical `base64`] → `invalid_request`".
    #[rstest]
    #[case::canonical("AAE=", Ok(()))]
    #[case::missing_padding("AAE", Err("invalid_request"))]
    #[case::nonzero_pad_bits("AAF=", Err("invalid_request"))]
    #[case::url_alphabet("-_8=", Err("invalid_request"))]
    #[case::line_break("AA\\nE=", Err("invalid_request"))]
    fn csr_must_be_canonical_base64(#[case] csr: &str, #[case] expected: Result<(), &'static str>) {
        let body = format!(r#"{{"csr":"{csr}","metadata":{{}}}}"#);
        assert_eq!(code(parse_csr_body(body.as_bytes())), expected);
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("valid header"),
        );
        headers
    }

    const BASE_URL: &str = "https://127.0.0.1:1/mock";

    fn with_bag(token: &str, bag: &str) -> String {
        let (prefix, rest) = token.split_once('.').expect("token prefix");
        let (_, secret) = rest.split_once('.').expect("token secret");
        format!("{prefix}.{bag}.{secret}")
    }

    /// CONTRACT.md §2: "The authority authenticates a token by its exact `secret` text alone and never checks the `bag`".
    #[rstest]
    #[case::issued_token(|token: &str| token.to_owned())]
    #[case::other_json_bag(|token: &str| with_bag(token, "e30"))]
    #[case::undecodable_bag(|token: &str| with_bag(token, "A"))]
    #[case::empty_bag(|token: &str| with_bag(token, ""))]
    fn token_authenticates_by_its_secret_text_alone(#[case] alter: fn(&str) -> String) {
        let token = alter(&enrollment_token(BASE_URL, &[0; 32]));
        assert_eq!(parse_bearer(&bearer(&token)).ok(), Some([0; 32]));
    }

    /// Any other secret text is another token, even a non-canonical `base64url` encoding of the same bytes (CONTRACT.md §1, §2).
    #[rstest]
    #[case::padded_secret(|token: &str| format!("{token}="))]
    #[case::nonzero_pad_bits(|token: &str| format!("{}B", &token[..token.len() - 1]))]
    #[case::standard_alphabet(|token: &str| format!("{}+", &token[..token.len() - 1]))]
    #[case::other_prefix(|token: &str| token.replacen("dvaet1", "dvaet2", 1))]
    fn token_with_other_secret_text_is_invalid(#[case] alter: fn(&str) -> String) {
        let token = alter(&enrollment_token(BASE_URL, &[0; 32]));
        assert_eq!(code(parse_bearer(&bearer(&token))), Err("token_invalid"));
    }
}
