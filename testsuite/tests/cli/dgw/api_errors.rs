//! Machine-readable error responses of the HTTP API, with token validation enabled.

use std::time::{Duration, SystemTime};

use rstest::rstest;
use serde_json::{Value, json};
use testsuite::cli::start_dgw;
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle};
use testsuite::token::{provisioner_key, provisioner_public_key_data, sign_token, untrusted_key};
use uuid::Uuid;

const GATEWAY_ID: Uuid = Uuid::from_u128(0x0b7b_8c8e_6e61_4a2c_9a3f_5d1e_7c2b_4f10);

const INVALID_TOKEN_CHALLENGE: &str = r#"Bearer error="invalid_token""#;

/// Gateway running with token validation enabled, trusting the provisioner key of the testsuite.
struct Gateway {
    config: DgwConfigHandle,
    process: tokio::process::Child,
}

impl Gateway {
    async fn start() -> Self {
        let config = DgwConfig::builder()
            .id(GATEWAY_ID)
            .provisioner_public_key_data(provisioner_public_key_data())
            .build()
            .init()
            .expect("init gateway config");
        let process = start_dgw(&config).await.expect("start gateway");

        Self { config, process }
    }

    async fn request(&self, method: reqwest::Method, path: &str, token: Option<&str>) -> Response {
        let url = format!("http://127.0.0.1:{}{path}", self.config.http_port());
        let mut request = reqwest::Client::new()
            .request(method, url)
            .timeout(Duration::from_secs(10));

        if let Some(token) = token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await.expect("send request");

        let header = |name| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().expect("header value is ASCII").to_owned())
        };

        Response {
            status: response.status().as_u16(),
            content_type: header(reqwest::header::CONTENT_TYPE),
            www_authenticate: header(reqwest::header::WWW_AUTHENTICATE),
            body: response.text().await.expect("read response body"),
        }
    }

    async fn get_heartbeat(&self, token: Option<&str>) -> Response {
        self.request(reqwest::Method::GET, "/jet/heartbeat", token).await
    }

    async fn stop(mut self) {
        let _ = self.process.start_kill();
        let _ = self.process.wait().await;
    }
}

#[derive(Debug)]
struct Response {
    status: u16,
    content_type: Option<String>,
    www_authenticate: Option<String>,
    body: String,
}

impl Response {
    /// Asserts that the response is a problem details error, and that the body carries nothing but the code.
    #[track_caller]
    fn assert_problem(&self, status: u16, title: &str, error: &str, challenge: Option<&str>) {
        assert_eq!(self.status, status, "{self:?}");
        assert_eq!(
            self.content_type.as_deref(),
            Some("application/problem+json"),
            "{self:?}"
        );
        assert_eq!(self.www_authenticate.as_deref(), challenge, "{self:?}");

        let body: Value = serde_json::from_str(&self.body).expect("JSON body");
        assert_eq!(
            body,
            json!({ "type": "about:blank", "title": title, "status": status, "error": error }),
        );
    }

    #[track_caller]
    fn assert_unauthorized(&self, error: &str) {
        self.assert_problem(401, "Unauthorized", error, Some(INVALID_TOKEN_CHALLENGE));
    }
}

fn now() -> i64 {
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time after UNIX epoch");
    i64::try_from(since_epoch.as_secs()).expect("timestamp fits in i64")
}

/// Claims of a scope token granting access to `GET /jet/heartbeat`.
fn heartbeat_claims() -> Value {
    let now = now();
    json!({
        "jti": Uuid::new_v4(),
        "nbf": now - 60,
        "exp": now + 3600,
        "scope": "gateway.heartbeat.read",
    })
}

fn with_claims(mut claims: Value, overrides: Value) -> Value {
    let claims_map = claims.as_object_mut().expect("claims object");
    for (name, value) in overrides.as_object().expect("overrides object") {
        claims_map.insert(name.clone(), value.clone());
    }
    claims
}

fn without_claim(mut claims: Value, name: &str) -> Value {
    claims.as_object_mut().expect("claims object").remove(name);
    claims
}

fn expired_claims() -> Value {
    with_claims(heartbeat_claims(), json!({ "nbf": now() - 7200, "exp": now() - 3600 }))
}

fn not_yet_valid_claims() -> Value {
    with_claims(heartbeat_claims(), json!({ "nbf": now() + 3600, "exp": now() + 7200 }))
}

fn other_gateway_claims() -> Value {
    with_claims(heartbeat_claims(), json!({ "jet_gw_id": Uuid::new_v4() }))
}

fn scope_token(claims: &Value) -> String {
    sign_token(&provisioner_key(), "SCOPE", None, claims)
}

fn jrl_token(iat: i64, jrl: Value) -> String {
    let claims = json!({ "jti": Uuid::new_v4(), "iat": iat, "jrl": jrl });
    sign_token(&provisioner_key(), "JRL", None, &claims)
}

// oracle: spec docs/API-spec.md §errors
#[tokio::test]
async fn missing_token() {
    let gateway = Gateway::start().await;

    let response = gateway.get_heartbeat(None).await;

    // Per RFC 6750, the challenge carries no error code when the request has no token at all.
    response.assert_problem(401, "Unauthorized", "missing_token", Some("Bearer"));

    gateway.stop().await;
}

// oracle: spec docs/API-spec.md §errors
#[rstest]
#[case::malformed_token("not-a-token".to_owned(), "malformed_token")]
#[case::malformed_claims(scope_token(&without_claim(heartbeat_claims(), "scope")), "malformed_token")]
#[case::bad_signature(sign_token(&untrusted_key(), "SCOPE", None, &heartbeat_claims()), "bad_signature")]
#[case::unknown_subkey(sign_token(&provisioner_key(), "SCOPE", Some("unknown"), &heartbeat_claims()), "unknown_subkey")]
#[case::expired(scope_token(&expired_claims()), "expired")]
#[case::not_yet_valid(scope_token(&not_yet_valid_claims()), "not_yet_valid")]
#[case::gateway_id_mismatch(scope_token(&other_gateway_claims()), "gateway_id_mismatch")]
#[tokio::test]
async fn rejected_token(#[case] token: String, #[case] expected_error: &str) {
    let gateway = Gateway::start().await;

    let response = gateway.get_heartbeat(Some(&token)).await;

    response.assert_unauthorized(expected_error);

    gateway.stop().await;
}

/// The signature is verified before any claim: without a token signed by a trusted key,
/// a caller learns nothing about the claims the Gateway expects.
// oracle: spec docs/API-spec.md §errors
#[rstest]
#[case::expired(expired_claims())]
#[case::not_yet_valid(not_yet_valid_claims())]
#[case::gateway_id_mismatch(other_gateway_claims())]
#[case::malformed_claims(without_claim(heartbeat_claims(), "scope"))]
#[tokio::test]
async fn claims_are_not_disclosed_without_a_valid_signature(#[case] claims: Value) {
    let gateway = Gateway::start().await;

    let token = sign_token(&untrusted_key(), "SCOPE", None, &claims);
    let response = gateway.get_heartbeat(Some(&token)).await;

    response.assert_unauthorized("bad_signature");

    gateway.stop().await;
}

// oracle: spec docs/API-spec.md §errors
// oracle: spec docs/API-spec.md §SCOPE
#[tokio::test]
async fn unexpected_replay() {
    let gateway = Gateway::start().await;

    let token = scope_token(&heartbeat_claims());

    let first = gateway.get_heartbeat(Some(&token)).await;
    assert_eq!(first.status, 200, "{first:?}");

    // A SCOPE token is valid for a single request.
    let second = gateway.get_heartbeat(Some(&token)).await;
    second.assert_unauthorized("unexpected_replay");

    gateway.stop().await;
}

// oracle: spec docs/API-spec.md §errors
// oracle: spec docs/API-spec.md §JRL (JWT Revocation List)
#[tokio::test]
async fn revoked() {
    let gateway = Gateway::start().await;

    let claims = heartbeat_claims();

    let jrl_update = gateway
        .request(
            reqwest::Method::POST,
            "/jet/jrl",
            Some(&jrl_token(now(), json!({ "jti": [claims["jti"]] }))),
        )
        .await;
    assert_eq!(jrl_update.status, 200, "{jrl_update:?}");

    let response = gateway.get_heartbeat(Some(&scope_token(&claims))).await;

    response.assert_unauthorized("revoked");

    gateway.stop().await;
}

// oracle: spec docs/API-spec.md §errors
// oracle: spec docs/API-spec.md §JRL (JWT Revocation List)
#[tokio::test]
async fn outdated_revocation_list() {
    let gateway = Gateway::start().await;

    let now = now();

    let jrl_update = gateway
        .request(reqwest::Method::POST, "/jet/jrl", Some(&jrl_token(now, json!({}))))
        .await;
    assert_eq!(jrl_update.status, 200, "{jrl_update:?}");

    // The Gateway only accepts a revocation list newer than its current one.
    let response = gateway
        .request(
            reqwest::Method::POST,
            "/jet/jrl",
            Some(&jrl_token(now - 3600, json!({}))),
        )
        .await;

    response.assert_unauthorized("invalid_token");

    gateway.stop().await;
}

// oracle: spec docs/API-spec.md §errors
// oracle: spec docs/API-spec.md §About scopes
#[tokio::test]
async fn wrong_token_type() {
    let gateway = Gateway::start().await;

    // A valid token, but the route expects a SCOPE token.
    let response = gateway.get_heartbeat(Some(&jrl_token(now(), json!({})))).await;

    response.assert_problem(403, "Forbidden", "wrong_token_type", None);

    gateway.stop().await;
}

// oracle: spec docs/API-spec.md §errors
// oracle: spec docs/API-spec.md §About scopes
#[tokio::test]
async fn insufficient_scope() {
    let gateway = Gateway::start().await;

    let claims = with_claims(heartbeat_claims(), json!({ "scope": "gateway.sessions.read" }));
    let response = gateway.get_heartbeat(Some(&scope_token(&claims))).await;

    response.assert_problem(
        403,
        "Forbidden",
        "insufficient_scope",
        Some(r#"Bearer error="insufficient_scope""#),
    );

    gateway.stop().await;
}

// oracle: spec docs/API-spec.md §errors
// oracle: spec docs/API-spec.md §OpenAPI
#[tokio::test]
async fn generic_code_derived_from_status() {
    let gateway = Gateway::start().await;

    let claims = with_claims(heartbeat_claims(), json!({ "scope": "gateway.session.terminate" }));
    let path = format!("/jet/session/{}/terminate", Uuid::new_v4());
    let response = gateway
        .request(reqwest::Method::POST, &path, Some(&scope_token(&claims)))
        .await;

    response.assert_problem(404, "Not Found", "not_found", None);

    gateway.stop().await;
}

/// The KDC proxy reads its token from the path, and validates it outside of the authentication middleware.
// oracle: spec docs/API-spec.md §errors
#[tokio::test]
async fn rejected_kdc_token() {
    let gateway = Gateway::start().await;

    let now = now();
    let claims = json!({
        "krb_realm": "example.com",
        "krb_kdc": "tcp://127.0.0.1:88",
        "jti": Uuid::new_v4(),
        "nbf": now - 60,
        "exp": now + 3600,
    });
    let token = sign_token(&untrusted_key(), "KDC", None, &claims);
    let response = gateway
        .request(reqwest::Method::POST, &format!("/jet/KdcProxy/{token}"), None)
        .await;

    response.assert_unauthorized("bad_signature");

    gateway.stop().await;
}
