//! The HTTPS server serves REST (axum) and gRPC (tonic) on one port with ALPN `h2` and `http/1.1`.
//! The dispatcher strips the path prefix defined by [CONTRACT.agent-identity.md][contract] ("7.2 URL and path prefix")
//! and the [mock intent][mock-intent] ("Mock-only control").
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#72-url-and-path-prefix
//! [mock-intent]: ../INTENT.md#mock-only-control

use std::convert::Infallible;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Bytes;
use axum::response::IntoResponse as _;
use axum::{Json, Router, http};
use futures::FutureExt as _;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt as _};

use crate::api_agent::{DROP_HEADER, INJECTED_HEADER};
use crate::app::App;
use crate::channel::ChannelService;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;
type OutResponse = http::Response<OutBody>;

/// Aborts the connection for the mock's `faults.drop_next_response` control.
#[derive(Debug)]
pub struct ConnectionAborted;

impl fmt::Display for ConnectionAborted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connection aborted by mock fault")
    }
}

impl std::error::Error for ConnectionAborted {}

/// Top-level dispatcher: strips the path prefix, routes the gRPC path to the tonic
/// service and everything else to the axum router.
#[derive(Clone)]
pub struct Dispatcher {
    prefix: Arc<String>,
    app: Arc<App>,
    channel: ChannelService,
    rest: Router,
}

impl Dispatcher {
    pub fn new(app: Arc<App>) -> Self {
        let app_for_404 = Arc::clone(&app);
        let rest = Router::new()
            .merge(crate::api_agent::router(Arc::clone(&app)))
            .merge(crate::api_admin::router(Arc::clone(&app)))
            .merge(crate::api_mock::router(Arc::clone(&app)))
            .fallback(move || {
                let app = Arc::clone(&app_for_404);
                async move {
                    // 404s inside the prefix carry the §5.4 body shape.
                    let body = json!({
                        "error": "not_found",
                        "message": "unknown path",
                        "server_time": crate::app::rfc3339(app.now()),
                    });
                    (http::StatusCode::NOT_FOUND, Json(body)).into_response()
                }
            });
        Self {
            prefix: Arc::new(app.prefix.clone()),
            app: Arc::clone(&app),
            channel: ChannelService { app },
            rest,
        }
    }

    pub(crate) async fn handle<B>(self, request: http::Request<B>) -> Result<OutResponse, ConnectionAborted>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError> + Send + 'static,
    {
        if request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .is_some_and(|value| value.as_bytes().starts_with(b"application/grpc"))
        {
            self.app.state.lock().await.requests.channel_attempts += 1;
        }
        let path = request.uri().path().to_owned();
        let stripped = match strip_prefix(&self.prefix, &path) {
            Some(stripped) => stripped.to_owned(),
            None => return Ok(outside_prefix_response()),
        };

        // Rewrite the URI to the stripped path (query preserved).
        let (mut parts, body) = request.into_parts();
        let path_and_query = match parts.uri.query() {
            Some(query) => format!("{stripped}?{query}"),
            None => stripped.clone(),
        };
        parts.uri = http::Uri::builder()
            .path_and_query(path_and_query)
            .build()
            .map_err(|_| ConnectionAborted)?;
        let request = http::Request::from_parts(parts, body);

        let grpc_path = format!("/{}/Connect", agent_channel_proto::SERVICE_NAME);
        if stripped == *grpc_path {
            let channel = self.channel;
            let connect = tower::service_fn(move |request| channel.clone().connect(request));
            let response = crate::channel::grpc().streaming(connect, request).await;
            return Ok(response.map(|body| body.map_err(|e| -> BoxError { Box::new(e) }).boxed_unsync()));
        }

        // UNTESTED: a panicking agent-facing handler is answered with `500 unavailable` (§5.4) instead of a dropped connection.
        // No handler panics on demand, so no test reaches this path.
        // When changing this call, keep the panic mapped to a 500 that the agent-facing rewrite below covers.
        let mut response = match AssertUnwindSafe(self.rest.oneshot(request)).catch_unwind().await {
            Ok(response) => response.unwrap_or_else(|never: Infallible| match never {}),
            Err(_) => http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if response.headers_mut().remove(DROP_HEADER).is_some() {
            // The mock drop fault committed the request, so abort without responding.
            return Err(ConnectionAborted);
        }
        let injected = response.headers_mut().remove(INJECTED_HEADER).is_some();
        let status = response.status().as_u16();
        if !injected
            && (stripped == "/api/agent-identity/v1" || stripped.starts_with("/api/agent-identity/v1/"))
            && (matches!(status, 400 | 404 | 405 | 413) || status >= 500)
        {
            let (status, code, message) = match status {
                404 => (status, "invalid_request", "unknown agent-identity route"),
                405 => (status, "invalid_request", "method not allowed"),
                413 => (status, "invalid_request", "agent-identity request body is too large"),
                400 => (status, "invalid_request", "invalid agent-identity request"),
                _ => (500, "unavailable", "unexpected agent-identity server failure"),
            };
            response = crate::api_agent::agent_error(&self.app, status, code, message);
        }
        Ok(response.map(|body| body.map_err(|e| -> BoxError { Box::new(e) }).boxed_unsync()))
    }
}

impl Service<http::Request<Incoming>> for Dispatcher {
    type Response = OutResponse;
    type Error = ConnectionAborted;
    type Future = Pin<Box<dyn Future<Output = Result<OutResponse, ConnectionAborted>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(this.handle(request))
    }
}

/// Strips `prefix` from `path`: `/mock/api/...` → `/api/...`; `/mock` → `/`.
/// Returns `None` when the path is outside the prefix; the caller responds with 404.
fn strip_prefix<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if path == prefix {
        return Some("/");
    }
    path.strip_prefix(prefix).filter(|rest| rest.starts_with('/'))
}

fn outside_prefix_response() -> OutResponse {
    map_response(http::StatusCode::NOT_FOUND.into_response())
}

fn map_response<B>(response: http::Response<B>) -> OutResponse
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    response.map(|body| body.map_err(Into::into).boxed_unsync())
}

/// Accept loop: TLS (ALPN h2 + http/1.1), then hyper's auto protocol detection.
pub async fn serve(listener: TcpListener, acceptor: TlsAcceptor, dispatcher: Dispatcher) -> anyhow::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                tracing::debug!("TLS handshake failed");
                return;
            };
            let io = TokioIo::new(tls);
            let service = hyper_util::service::TowerToHyperService::new(dispatcher);
            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            if let Err(error) = builder.serve_connection(io, service).await {
                tracing::debug!(%error, "Connection ended with an error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Bytes;
    use axum::http;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use http_body_util::{BodyExt as _, Full};
    use p256::ecdsa::VerifyingKey;
    use rstest::rstest;
    use serde_json::{Map, Value, json};

    use super::Dispatcher;
    use crate::api_agent::enrollment_token;
    use crate::app::App;
    use crate::oracle::NonceStore;
    use crate::state::State;

    /// CONTRACT.agent-identity.md §5.4: servers accept agent-facing request bodies up to 64 KiB.
    const BODY_LIMIT: usize = 64 * 1024;

    const FAULTS: &str = "/__mock__/faults";

    /// Posts to an agent-facing endpoint and returns the status and the §5.4 error code.
    async fn post(app: &Arc<App>, endpoint: &str, authorization: &[&str], body: Vec<u8>) -> (u16, String) {
        let mut request = http::Request::post(format!("/mock/api/agent-identity/v1/{endpoint}"));
        for value in authorization {
            request = request.header(http::header::AUTHORIZATION, *value);
        }
        let request = request.body(Full::new(Bytes::from(body))).expect("valid request");
        let response = Dispatcher::new(Arc::clone(app))
            .handle(request)
            .await
            .expect("the mock answers");
        let status = response.status().as_u16();
        let body = response.into_body().collect().await.expect("readable body").to_bytes();
        let body: Value = serde_json::from_slice(&body).expect("JSON error body");
        (status, body["error"].as_str().expect("error code").to_owned())
    }

    #[rstest]
    #[case::enroll("enroll")]
    #[case::renew("renew")]
    #[case::confirm("confirm")]
    #[case::check_in("check-in")]
    #[tokio::test]
    async fn oversized_body_is_413_before_authentication(#[case] endpoint: &str) -> anyhow::Result<()> {
        let response = post(&App::for_test()?, endpoint, &[], vec![b' '; BODY_LIMIT + 1]).await;
        assert_eq!(response, (413, "invalid_request".to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn body_at_the_limit_reaches_authentication() -> anyhow::Result<()> {
        let response = post(&App::for_test()?, "enroll", &[], vec![b' '; BODY_LIMIT]).await;
        assert_eq!(response, (401, "token_invalid".to_owned()));
        Ok(())
    }

    #[rstest]
    #[case::enroll("enroll", "token_invalid")]
    #[case::renew("renew", "signature_invalid")]
    #[case::confirm("confirm", "signature_invalid")]
    #[case::check_in("check-in", "signature_invalid")]
    #[tokio::test]
    async fn authentication_error_wins_over_invalid_body(
        #[case] endpoint: &str,
        #[case] code: &str,
    ) -> anyhow::Result<()> {
        let response = post(&App::for_test()?, endpoint, &[], b"not json".to_vec()).await;
        assert_eq!(response, (401, code.to_owned()));
        Ok(())
    }

    #[rstest]
    #[case::single_header(1, (400, "invalid_request"))]
    #[case::repeated_header(2, (401, "token_invalid"))]
    #[tokio::test]
    async fn enrollment_token_is_checked_before_the_body(
        #[case] header_count: usize,
        #[case] expected: (u16, &str),
    ) -> anyhow::Result<()> {
        let app = App::for_test()?;
        let now = app.now();
        let (_, secret) =
            app.state
                .lock()
                .await
                .create_token("test".to_owned(), 1, crate::app::nanos(now + 3600), None, None, now);
        let authorization = format!("Bearer {}", enrollment_token(&app.base_url, &secret));
        let headers = vec![authorization.as_str(); header_count];
        let response = post(&app, "enroll", &headers, b"not json".to_vec()).await;
        assert_eq!(response, (expected.0, expected.1.to_owned()));
        Ok(())
    }

    /// CONTRACT.agent-identity.md §1: "A JSON request body with more than 64 nested objects and arrays, counting the
    /// top-level object, [...] → `invalid_request`", even when its CSR and metadata are valid.
    /// The refusal precedes enrollment, so it creates no identity.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §1
    #[tokio::test]
    async fn enrollment_body_nested_past_64_levels_creates_no_identity() -> anyhow::Result<()> {
        let app = App::for_test()?;
        let now = app.now();
        let (_, secret) =
            app.state
                .lock()
                .await
                .create_token("test".to_owned(), 1, crate::app::nanos(now + 3600), None, None, now);
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let authorization = format!("Bearer {}", enrollment_token(&app.base_url, &secret));
        let headers = [(http::header::AUTHORIZATION.as_str(), authorization.as_str())];
        let csr = &vectors["csr"]["valid"]["csr"];
        let nested = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        let body = format!(r#"{{"csr":{csr},"metadata":{{}},"x":{nested}}}"#);
        let (status, refused) = post_json(&app, "/api/agent-identity/v1/enroll", &headers, body).await;
        assert_eq!((status, &refused["error"]), (400, &json!("invalid_request")));
        assert!(app.state.lock().await.identities.is_empty());
        Ok(())
    }

    /// CONTRACT.agent-identity.md §5.4: "an unexpected server failure → `500 unavailable`".
    /// Issuing from a root that has expired is such a failure.
    #[tokio::test]
    async fn unexpected_failure_is_500_unavailable() -> anyhow::Result<()> {
        let app = App::for_test()?;
        let secret = {
            let mut state = app.state.lock().await;
            let root_not_after = state.issuing_root().not_after;
            app.clock.freeze_at(root_not_after);
            let (_, secret) = state.create_token(
                "test".to_owned(),
                1,
                crate::app::nanos(root_not_after + 60),
                None,
                None,
                root_not_after,
            );
            secret
        };
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let authorization = format!("Bearer {}", enrollment_token(&app.base_url, &secret));
        let body = json!({ "csr": vectors["csr"]["valid"]["csr"], "metadata": {} }).to_string();
        let response = post(&app, "enroll", &[authorization.as_str()], body.into_bytes()).await;
        assert_eq!(response, (500, "unavailable".to_owned()));
        Ok(())
    }

    /// The `fail_next_response` fault takes any §5.4 code, so tests can inject `unavailable` with a 5xx status.
    #[tokio::test]
    async fn injected_failure_can_carry_unavailable() -> anyhow::Result<()> {
        let app = App::for_test()?;
        let fault = json!({ "fail_next_response": { "endpoint": "check-in", "status": 503, "error": "unavailable" } });
        let (status, _) = post_json(&app, FAULTS, &[], fault.to_string()).await;
        assert_eq!(status, 200);
        let response = post(&app, "check-in", &[], Vec::new()).await;
        assert_eq!(response, (503, "unavailable".to_owned()));
        Ok(())
    }

    async fn post_json(app: &Arc<App>, path: &str, headers: &[(&str, &str)], body: impl Into<Bytes>) -> (u16, Value) {
        let mut request = http::Request::post(format!("/mock{path}"));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request.body(Full::new(body.into())).expect("valid request");
        let response = Dispatcher::new(Arc::clone(app))
            .handle(request)
            .await
            .expect("the mock answers");
        let status = response.status().as_u16();
        let body = response.into_body().collect().await.expect("readable body").to_bytes();
        (status, serde_json::from_slice(&body).expect("JSON body"))
    }

    /// Logs the application identity of [`App::for_test`] in under the path prefix and returns the `tokenId`.
    async fn login(app: &Arc<App>) -> String {
        let credentials = json!({ "appKey": "admin", "appSecret": "secret" }).to_string();
        let (status, result) = post_json(app, "/api/v1/login", &[], credentials).await;
        assert_eq!(status, 200);
        result["tokenId"]
            .as_str()
            .expect("LoginResult has a tokenId")
            .to_owned()
    }

    /// The control must reach the enrollment response, not only configs stored before it was set.
    #[tokio::test]
    async fn config_version_fault_overrides_the_enrollment_config() -> anyhow::Result<()> {
        let app = App::for_test()?;
        let now = app.now();
        let (_, secret) =
            app.state
                .lock()
                .await
                .create_token("test".to_owned(), 1, crate::app::nanos(now + 3600), None, None, now);
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;

        let (status, faults) = post_json(&app, FAULTS, &[], json!({ "config_version": 7 }).to_string()).await;
        assert_eq!((status, &faults["config_version"]), (200, &json!(7)));

        let authorization = format!("Bearer {}", enrollment_token(&app.base_url, &secret));
        let body = json!({ "csr": vectors["csr"]["valid"]["csr"], "metadata": {} }).to_string();
        let headers = [(http::header::AUTHORIZATION.as_str(), authorization.as_str())];
        let (status, enrolled) = post_json(&app, "/api/agent-identity/v1/enroll", &headers, body).await;
        assert_eq!((status, &enrolled["config"]["version"]), (200, &json!(7)));

        let (status, faults) = post_json(&app, FAULTS, &[], json!({ "config_version": null }).to_string()).await;
        assert_eq!((status, &faults["config_version"]), (200, &Value::Null));
        Ok(())
    }

    /// Check-in must deliver the override, and clearing it must deliver version 1 at a higher revision.
    #[tokio::test]
    async fn config_version_fault_reaches_the_check_in_response() -> anyhow::Result<()> {
        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let case = vectors["http_signature"]["cases"]
            .as_array()
            .and_then(|cases| cases.iter().find(|case| case["name"] == "valid_check_in"))
            .expect("valid check-in vector");
        let device = vectors["keys"]
            .as_array()
            .and_then(|keys| keys.iter().find(|key| key["name"] == "device-a"))
            .expect("device A key");
        let now = case["now"].as_i64().expect("vector time");
        let app = App::for_test()?;
        app.clock.freeze_at(now);
        let mut stored_revision = {
            let mut state = app.state.lock().await;
            *state = State::with_root(now)?;
            let (_, secret) = state.create_token("test".to_owned(), 1, crate::app::nanos(now + 3600), None, None, now);
            let csr = STANDARD.decode(vectors["csr"]["valid"]["csr"].as_str().expect("valid CSR vector"))?;
            let identity_id = state
                .enroll(&secret, &csr, Map::new(), now, &app.base_url)
                .expect("enrollment succeeds")
                .identity_id;
            // The vector is signed by device A, so its key replaces the enrolled one.
            let keyid = device["thumbprint"].as_str().expect("device A thumbprint").to_owned();
            let public_key = STANDARD.decode(device["public_key_sec1"].as_str().expect("device A public key"))?;
            let identity = state.identities.get_mut(&identity_id).expect("enrolled identity");
            let cert = identity.certs.first_mut().expect("issued certificate");
            let enrolled_keyid = std::mem::replace(&mut cert.thumbprint, keyid.clone());
            cert.public_key = VerifyingKey::from_sec1_bytes(&public_key)?;
            let revision = identity.config_revision();
            state.cert_index.remove(&enrolled_keyid);
            state.cert_index.insert(keyid, identity_id);
            revision
        };
        let headers = ["content-digest", "signature-input", "signature"]
            .map(|name| (name, case["headers"][name].as_str().expect("vector header")));
        let body = case["body"].as_str().expect("vector body").to_owned();

        for (control, expected_version) in [(json!(7), 7), (Value::Null, 1)] {
            let (status, _) = post_json(&app, FAULTS, &[], json!({ "config_version": control }).to_string()).await;
            assert_eq!(status, 200);
            // The vector request is replayed, so its nonce must be accepted again.
            app.state.lock().await.nonces = NonceStore::default();

            let (status, checked_in) = post_json(&app, "/api/agent-identity/v1/check-in", &headers, body.clone()).await;
            assert_eq!(
                (status, &checked_in["config"]["version"]),
                (200, &json!(expected_version))
            );
            let revision = checked_in["config"]["revision"]
                .as_u64()
                .expect("revision is an unsigned integer");
            assert!(stored_revision < revision, "revision increases for {control}");
            stored_revision = revision;
        }
        Ok(())
    }

    fn with_bag(token: &str, bag: &str) -> String {
        let (prefix, rest) = token.split_once('.').expect("token prefix");
        let (_, secret) = rest.split_once('.').expect("token secret");
        format!("{prefix}.{bag}.{secret}")
    }

    /// CONTRACT.agent-identity.md §2: "The authority authenticates a token by its exact `secret` text alone and never checks the `bag`".
    #[rstest]
    #[case::issued_token(|token: &str| token.to_owned(), 200, Value::Null)]
    #[case::other_json_bag(|token: &str| with_bag(token, "e30"), 200, Value::Null)]
    #[case::undecodable_bag(|token: &str| with_bag(token, "A"), 200, Value::Null)]
    #[case::padded_secret(|token: &str| format!("{token}="), 401, json!("token_invalid"))]
    #[tokio::test]
    async fn enrollment_authenticates_the_token_by_its_secret_text(
        #[case] alter: fn(&str) -> String,
        #[case] expected_status: u16,
        #[case] expected_error: Value,
    ) -> anyhow::Result<()> {
        let app = App::for_test()?;
        let expires_at = crate::app::rfc3339(app.now() + 3600);
        let created = json!({ "name": "t", "maxUses": 1, "expiresOn": expires_at }).to_string();
        let token_id = login(&app).await;
        let admin = [("tokenId", token_id.as_str())];
        let (status, created) = post_json(&app, "/api/v1/agent-identity/enrollment-token", &admin, created).await;
        assert_eq!(status, 201);
        let token = alter(created["token"].as_str().expect("issued token"));

        let vectors: Value = serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let authorization = format!("Bearer {token}");
        let headers = [(http::header::AUTHORIZATION.as_str(), authorization.as_str())];
        let body = json!({ "csr": vectors["csr"]["valid"]["csr"], "metadata": {} }).to_string();
        let (status, enrolled) = post_json(&app, "/api/agent-identity/v1/enroll", &headers, body).await;
        assert_eq!((status, &enrolled["error"]), (expected_status, &expected_error));
        Ok(())
    }

    #[rstest]
    #[case::negative(json!(-1))]
    #[case::fractional(json!(1.5))]
    #[case::string(json!("2"))]
    #[tokio::test]
    async fn config_version_fault_rejects_a_non_unsigned_integer(#[case] value: Value) -> anyhow::Result<()> {
        let app = App::for_test()?;
        let (status, body) = post_json(&app, FAULTS, &[], json!({ "config_version": value }).to_string()).await;
        assert_eq!((status, &body["error"]), (400, &json!("invalid_request")));
        Ok(())
    }

    /// A reset `without_root` stands for a DVLS that never created a token: no root is published until the first
    /// enrollment token creates one ([DVLS intent][dvls], "Root CA").
    ///
    /// [dvls]: ../../../docs/agent-identity/INTENT.DVLS.md#root-ca
    #[tokio::test]
    async fn reset_without_root_publishes_a_root_only_after_the_first_token() -> anyhow::Result<()> {
        let app = App::for_test()?;
        let published_roots = || async {
            let request = http::Request::get("/mock/api/agent-identity/v1/trust-anchor")
                .body(Full::new(Bytes::new()))
                .expect("valid request");
            let response = Dispatcher::new(Arc::clone(&app))
                .handle(request)
                .await
                .expect("the mock answers");
            let body = response.into_body().collect().await.expect("readable body").to_bytes();
            let body: Value = serde_json::from_slice(&body).expect("JSON body");
            body["roots"].as_array().expect("roots").len()
        };
        let (status, _) = post_json(
            &app,
            "/__mock__/reset",
            &[],
            json!({ "without_root": true }).to_string(),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(published_roots().await, 0);

        let token = json!({ "name": "t", "maxUses": 1 }).to_string();
        let token_id = login(&app).await;
        let admin = [("tokenId", token_id.as_str())];
        let (status, _) = post_json(&app, "/api/v1/agent-identity/enrollment-token", &admin, token).await;
        assert_eq!(status, 201);
        assert_eq!(published_roots().await, 1);
        Ok(())
    }

    /// A reset keeps the management API sessions, so that a tester stays logged in across the resets between its tests.
    #[tokio::test]
    async fn reset_keeps_management_sessions() -> anyhow::Result<()> {
        let app = App::for_test()?;
        let token_id = login(&app).await;
        let (status, _) = post_json(&app, "/__mock__/reset", &[], Bytes::new()).await;
        assert_eq!(status, 200);

        let token = json!({ "name": "t", "maxUses": 1 }).to_string();
        let admin = [("tokenId", token_id.as_str())];
        let (status, _) = post_json(&app, "/api/v1/agent-identity/enrollment-token", &admin, token).await;
        assert_eq!(status, 201);
        Ok(())
    }
}
