use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use now_package_broker::server::test_utils;
use now_policy::{
    PackageBrokerPolicy, PolicyDocument, PolicyEnforcement, PolicyMetadata, PolicySchemaUri, ResourceId,
    RulePrecedence, SemanticVersion,
};
use now_policy_api::{self as api, ErrorCode, ErrorResponse, PolicyResponse, PolicyResponseKind, Transport};
use tower_service::Service as _;

fn permissive_policy() -> PolicyDocument {
    PolicyDocument {
        _schema: PolicySchemaUri,
        policy_version: SemanticVersion::from("1.0.0"),
        policy_type: PackageBrokerPolicy,
        metadata: PolicyMetadata {
            id: ResourceId::from("test-policy"),
            publisher: "Test".to_owned(),
            revision: 1,
            published_at: Utc::now(),
            valid_from: None,
            valid_until: None,
            description: None,
            support_url: None,
        },
        enforcement: PolicyEnforcement {
            default_decision: now_policy::Decision::Allow,
            rule_precedence: RulePrecedence::PriorityThenDeny,
            audit_mode: Some(true),
        },
        rules: Vec::new(),
    }
}

async fn route_request(policy: Option<PolicyDocument>, method: Method, uri: &str) -> axum::response::Response {
    let mut router = test_utils::router(policy).expect("build package broker test router");
    router
        .call(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .expect("valid test request"),
        )
        .await
        .expect("router is infallible")
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    serde_json::from_slice(&body).expect("response is valid JSON")
}

#[tokio::test]
async fn policy_route_serializes_active_policy_with_empty_rules() {
    let expected = permissive_policy();
    let response = route_request(Some(expected.clone()), Method::GET, "/v1/policy").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json");

    let response: PolicyResponse =
        serde_json::from_value(response_json(response).await).expect("deserialize policy response");
    assert_eq!(response.response_kind, PolicyResponseKind);
    assert_eq!(&*response.response_version, api::API_VERSION_STR);
    assert_eq!(response.server.transport, Transport::HttpNamedPipe);
    assert_eq!(
        serde_json::to_value(response.policy).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[tokio::test]
async fn policy_route_serializes_full_policy_matches_and_constraints() {
    let expected = now_policy::schema::parse_policy_json(include_str!(
        "../../../crates/now-package-broker/src/assets/samples/corporate-allowlist.policy.json"
    ))
    .expect("sample policy is valid");
    let response = route_request(Some(expected.clone()), Method::GET, "/v1/policy").await;

    assert_eq!(response.status(), StatusCode::OK);

    let response: PolicyResponse =
        serde_json::from_value(response_json(response).await).expect("deserialize policy response");
    assert_eq!(
        serde_json::to_value(response.policy).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[tokio::test]
async fn policy_route_returns_structured_service_unavailable_without_active_policy() {
    let response = route_request(None, Method::GET, "/v1/policy").await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = response_json(response).await;
    let error: ErrorResponse = serde_json::from_value(body.clone()).expect("deserialize error response");
    assert_eq!(error.code, ErrorCode::BrokerPaused);
    assert_eq!(error.message, "active policy is unavailable");
    assert!(error.details.is_empty());
    assert!(body.get("Policy").is_none());
}

#[tokio::test]
async fn policy_route_preserves_existing_routes_and_method_restrictions() {
    for uri in ["/v1/health", "/v1/capabilities"] {
        let response = route_request(Some(permissive_policy()), Method::GET, uri).await;
        assert_eq!(response.status(), StatusCode::OK, "unexpected status for {uri}");
    }

    let response = route_request(Some(permissive_policy()), Method::HEAD, "/v1/policy").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read HEAD response")
            .is_empty()
    );

    for method in [
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
        Method::TRACE,
        Method::CONNECT,
    ] {
        let response = route_request(Some(permissive_policy()), method.clone(), "/v1/policy").await;
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "unexpected status for {method}"
        );
    }

    let response = route_request(Some(permissive_policy()), Method::GET, "/v1/not-a-route").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
