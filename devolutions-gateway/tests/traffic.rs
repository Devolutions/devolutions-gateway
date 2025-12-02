#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::cast_possible_truncation, reason = "test code with known safe ranges")]

//! Integration tests for the **traffic audit** HTTP endpoints.
//!
//! ## Scope
//!
//! These tests validate the behavior of:
//! - `POST /jet/traffic/claim`
//! - `POST /jet/traffic/ack`
//!
//! against the live `TrafficAuditManagerTask` and `TrafficAuditHandle` running
//! in-process with an in-memory database.
//!
//! ## Key properties verified
//!
//! - **Shape & Auth:** Endpoints are reachable under `/jet/traffic/*` with the
//!   standard DGW auth layer (disabled token validation in test config).
//! - **FIFO & Limits:** Claims are returned in ascending `id` order and respect
//!   `max`.
//! - **Leases:** Active leases prevent re-claim; after expiry, events are re-claimable.
//! - **Ack semantics:** `ack` removes claimed items; subsequent claims return empty.
//! - **Serialization:** Unicode hostnames and IPv6 addresses round-trip correctly.
//! - **Concurrency (stress):** Concurrent claimers make forward progress without panics.

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{self, Request, StatusCode};
use devolutions_gateway::traffic_audit::TrafficAuditManagerTask;
use devolutions_gateway::{DgwState, MockHandles};
use devolutions_gateway_task::{ChildTask, Task};
use http_body_util::BodyExt as _;
use serde_json::json;
use tower::ServiceExt as _;
use tracing_subscriber::util::SubscriberInitExt;
use traffic_audit::{EventOutcome, TrafficEvent, TransportProtocol};
use uuid::Uuid;

/// Test app configuration:
/// - Two listeners (tcp & http)
/// - Token validation disabled (so tests can use a static bearer)
const CONFIG: &str = r#"{
    "ProvisionerPublicKeyData": {
        "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
    },
    "Listeners": [
        { "InternalUrl": "tcp://*:8080",  "ExternalUrl": "tcp://*:8080"  },
        { "InternalUrl": "http://*:7171", "ExternalUrl": "https://*:7171" }
    ],
    "__debug__": { "disable_token_validation": true }
}"#;

/// Bearer token with wildcard scope for testing (validation disabled).
const BEARER_TOKEN: &str = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlNDT1BFIn0.eyJqdGkiOiI5YTdkZWRhOC1jNmM2LTQ1YzAtODZlYi01MGJiMzI4YWFjMjMiLCJleHAiOjAsInNjb3BlIjoiKiJ9.dTazZemDS08Fy13Hx7wxDoOxQ2oNFaaEYMSFDQHCWiUdlYv4NMQh6N_GQok3wdiSJf384fvLKccYe1fipRepLlinUAqcEum68ngvGuUVP78xYb_vC3ZDqFi6nvd1BLp621XgzsCbOyBZHhLXHgzwVNTpnbt9laTTaHh8_rSYLaujBOpidWS6vKIZqOE66beqygSprPt3y0LYFTQWGYq21jJ73uW6htdWrmXbDUUjdvG7ymnKb-7Scs5y03jjSTr4QB1rH_3Z8DsfuuxFCIBd8V2yu192PrWooAdMKboLSjvmdFiD509lljoaNoGLBv9hmmQyiLQr-rsUllXBD6UpTQ";

/// Signals shutdown on drop.
struct HandlesGuard {
    handles: MockHandles,
}

impl Drop for HandlesGuard {
    fn drop(&mut self) {
        self.handles.shutdown_handle.signal();
    }
}

/// Build a Router with a live TrafficAuditManagerTask and real handle,
/// similar to tests/preflight.rs harness.
async fn make_router() -> anyhow::Result<(Router, DgwState, HandlesGuard)> {
    let (mut state, handles) = DgwState::mock(CONFIG)?;

    // Start the manager with an in-memory DB.
    let manager = TrafficAuditManagerTask::init(":memory:").await?;
    state.traffic_audit_handle = manager.handle();

    // Run the task (graceful shutdown ensured via HandlesGuard).
    ChildTask::spawn({
        let shutdown_signal = state.shutdown_signal.clone();
        async move { manager.run(shutdown_signal).await }
    })
    .detach();

    let app = devolutions_gateway::make_http_service(state.clone())
        .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))));

    let guard = HandlesGuard { handles };

    Ok((app, state, guard))
}

/// Initialize test logging to the test output.
fn init_logger() -> tracing::subscriber::DefaultGuard {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .set_default()
}

/// Construct a minimal traffic event for seeding tests.
fn create_test_traffic_event(n: u32) -> TrafficEvent {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    TrafficEvent {
        session_id: Uuid::new_v4(),
        outcome: EventOutcome::NormalTermination,
        protocol: TransportProtocol::Tcp,
        target_host: format!("host{n}.example.com"),
        target_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, (n % 250) as u8)),
        target_port: 80,
        connect_at_ms: now_ms - 1000,
        disconnect_at_ms: now_ms,
        active_duration_ms: 1000,
        bytes_tx: 100,
        bytes_rx: 200,
    }
}

/// Build a request to claim events.
fn claim_request(lease_ms: Option<u32>, max: Option<usize>) -> anyhow::Result<Request<Body>> {
    let uri = match (lease_ms, max) {
        (None, None) => "/jet/traffic/claim".to_owned(),
        (None, Some(max)) => format!("/jet/traffic/claim?max={max}"),
        (Some(lease_ms), None) => format!("/jet/traffic/claim?lease_ms={lease_ms}"),
        (Some(lease_ms), Some(max)) => format!("/jet/traffic/claim?lease_ms={lease_ms}&max={max}"),
    };

    Ok(Request::builder()
        .method("POST")
        .uri(uri)
        .header(http::header::AUTHORIZATION, BEARER_TOKEN)
        .body(Body::empty())?)
}

/// Build a request to ack (delete) events by ids.
fn ack_request(ids: Vec<ulid::Ulid>) -> anyhow::Result<Request<Body>> {
    let payload = json!({ "ids": ids });
    Ok(Request::builder()
        .method("POST")
        .uri("/jet/traffic/ack")
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::AUTHORIZATION, BEARER_TOKEN)
        .body(Body::from(serde_json::to_vec(&payload)?))?)
}

/* -------------------------------------------------------------------------- */
/*                                   TESTS                                    */
/* -------------------------------------------------------------------------- */

/// Intent: verify the **shape** of the claim endpoint.
///
/// Expectation:
/// - `POST /jet/traffic/claim` returns `200 OK` and a JSON array.
/// - With an empty DB, the array is empty.
///
/// Success criteria: status is 200; body is `[]`.
#[tokio::test(flavor = "current_thread")]
async fn claim_shape_ok() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, _state, _handles) = make_router().await?;

    let response = app.oneshot(claim_request(Some(1000), Some(10))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body)?;
    assert!(v.is_array());
    assert!(v.as_array().unwrap().is_empty());

    Ok(())
}

/// Intent: verify the **shape** of the ack endpoint.
///
/// Expectation:
/// - `POST /jet/traffic/ack` returns `200 OK` and `{ "deleted_count": <u64> }`.
/// - Acknowledging non-existent ids deletes nothing (count = 0).
///
/// Success criteria: status is 200; `deleted_count == 0`.
#[tokio::test(flavor = "current_thread")]
async fn ack_shape_ok() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, _state, _handles) = make_router().await?;

    // Use valid ULID strings (these don't exist in DB, but format is valid)
    let fake_ids = vec![ulid::Ulid::new(), ulid::Ulid::new(), ulid::Ulid::new()];
    let response = app.oneshot(ack_request(fake_ids)?).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body)?;

    // The database is empty, and nothing was claimed, so ack should do nothing.
    assert_eq!(v["deleted_count"], 0);

    Ok(())
}

/// Intent: verify **FIFO** ordering and the **max** bound on claim.
///
/// Expectation:
/// - After pushing 10 events, claiming with `max=5` returns exactly 5 items.
/// - Returned `id`s are strictly increasing (ascending).
///
/// Success criteria: len == 5; ids[i] < ids[i+1].
#[tokio::test(flavor = "current_thread")]
async fn claim_fifo_and_limits() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, state, _handles) = make_router().await?;

    for i in 0..10 {
        state.traffic_audit_handle.push(create_test_traffic_event(i)).await?;
    }

    let response = app.oneshot(claim_request(None, Some(5))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    let arr: serde_json::Value = serde_json::from_slice(&body)?;
    let events = arr.as_array().unwrap();
    assert_eq!(events.len(), 5);

    for i in 1..events.len() {
        let prev = events[i - 1]["id"].as_str().unwrap();
        let curr = events[i]["id"].as_str().unwrap();
        assert!(prev < curr, "ids are not strictly increasing: {prev} !< {curr}");
    }

    Ok(())
}

/// Intent: verify **lease expiry** allows re-claim of the same items.
///
/// Expectation:
/// - Claim with a short lease yields items.
/// - After sleeping long enough (lease + buffer), the same items can be claimed again.
///
/// Success criteria: both claims return 1 item with the **same** `id`.
#[tokio::test(flavor = "current_thread")]
async fn lease_expiry_reclaim() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, state, _handles) = make_router().await?;

    state.traffic_audit_handle.push(create_test_traffic_event(1)).await?;

    let r1 = app.clone().oneshot(claim_request(Some(1_000), None)?).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let b1 = r1.into_body().collect().await?.to_bytes();
    let v1: serde_json::Value = serde_json::from_slice(&b1)?;
    let e1 = v1.as_array().unwrap();
    assert_eq!(e1.len(), 1, "first claim should return one item");

    // Wait for lease to expire (1s + buffer)
    tokio::time::sleep(tokio::time::Duration::from_millis(1_100)).await;

    let r2 = app.oneshot(claim_request(None, None)?).await.unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let b2 = r2.into_body().collect().await?.to_bytes();
    let v2: serde_json::Value = serde_json::from_slice(&b2)?;
    let e2 = v2.as_array().unwrap();
    assert_eq!(e2.len(), 1, "second claim should also return one item");

    assert_eq!(e1[0]["id"], e2[0]["id"], "reclaimed id should match");

    Ok(())
}

/// Intent: verify **active leases prevent** re-claim before expiry.
///
/// Expectation:
/// - After an initial claim with a long lease, a second immediate claim returns no items.
///
/// Success criteria: first claim len==1; second claim len==0.
#[tokio::test(flavor = "current_thread")]
async fn active_lease_protection() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, state, _handles) = make_router().await?;

    state.traffic_audit_handle.push(create_test_traffic_event(42)).await?;

    let r1 = app.clone().oneshot(claim_request(None, None)?).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let b1 = r1.into_body().collect().await?.to_bytes();
    let v1: serde_json::Value = serde_json::from_slice(&b1)?;
    let e1 = v1.as_array().unwrap();
    assert_eq!(e1.len(), 1, "first claim should return one item");

    let r2 = app.oneshot(claim_request(None, None)?).await.unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let b2 = r2.into_body().collect().await?.to_bytes();
    let v2: serde_json::Value = serde_json::from_slice(&b2)?;
    let e2 = v2.as_array().unwrap();
    assert_eq!(e2.len(), 0, "second claim should return no items while lease active");

    Ok(())
}

/// Intent: verify **ack deletes** items so they cannot be claimed again.
///
/// Expectation:
/// - Claim → `ack(ids)` → subsequent claim returns empty.
/// - `deleted_count` equals the number of acknowledged ids.
///
/// Success criteria: `deleted_count == ids.len()` and next claim `len==0`.
#[tokio::test(flavor = "current_thread")]
async fn ack_deletes() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, state, _handle) = make_router().await?;

    for i in 0..5 {
        state.traffic_audit_handle.push(create_test_traffic_event(i)).await?;
    }

    let claim = app.clone().oneshot(claim_request(None, None)?).await.unwrap();
    assert_eq!(claim.status(), StatusCode::OK);
    let cbody = claim.into_body().collect().await?.to_bytes();
    let carr: serde_json::Value = serde_json::from_slice(&cbody)?;
    let items = carr.as_array().unwrap();
    assert_eq!(items.len(), 5);

    let ids: Vec<ulid::Ulid> = items
        .iter()
        .map(|e| e["id"].as_str().unwrap().parse().unwrap())
        .collect();

    let ack = app.clone().oneshot(ack_request(ids.clone())?).await.unwrap();
    assert_eq!(ack.status(), StatusCode::OK);
    let abody = ack.into_body().collect().await?.to_bytes();
    let ajson: serde_json::Value = serde_json::from_slice(&abody)?;
    assert_eq!(ajson["deleted_count"].as_u64().unwrap(), ids.len() as u64);

    // Next claim should be empty
    let again = app.oneshot(claim_request(None, None)?).await.unwrap();
    assert_eq!(again.status(), StatusCode::OK);
    let body = again.into_body().collect().await?.to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body)?;
    assert!(v.as_array().unwrap().is_empty());

    Ok(())
}

/// Intent: verify **serialization** of Unicode hostnames and IPv6 addresses.
///
/// Expectation:
/// - Pushed event with non-ASCII host and IPv6 IP is returned exactly as sent.
///
/// Success criteria: `target_host` and `target_ip` match the original values.
#[tokio::test(flavor = "current_thread")]
async fn unicode_ipv6_roundtrip() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, state, _handles) = make_router().await?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let ev = TrafficEvent {
        session_id: Uuid::new_v4(),
        outcome: EventOutcome::NormalTermination,
        protocol: TransportProtocol::Tcp,
        target_host: "测试主机.example.com".to_owned(),
        target_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
        target_port: 443,
        connect_at_ms: now_ms - 1000,
        disconnect_at_ms: now_ms,
        active_duration_ms: 1000,
        bytes_tx: 100,
        bytes_rx: 200,
    };
    state.traffic_audit_handle.push(ev).await?;

    let response = app.oneshot(claim_request(None, None)?).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    let arr: serde_json::Value = serde_json::from_slice(&body)?;
    let events = arr.as_array().unwrap();
    assert_eq!(events.len(), 1);

    assert_eq!(events[0]["target_host"], "测试主机.example.com");
    assert_eq!(events[0]["target_ip"], "2001:db8::1");
    assert_eq!(events[0]["target_port"], 443);

    Ok(())
}

/// Intent: coarse **concurrency stress** to ensure no panics and forward progress.
///
/// Expectation:
/// - With 20 events and 10 concurrent claim requests, total claimed = 20.
/// - Precise distribution is not asserted here; just liveness/safety.
///
/// Success criteria: sum(claimed sizes) = 20; all tasks complete without panic.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_stress() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, state, _handles) = make_router().await?;

    for i in 0..20 {
        state.traffic_audit_handle.push(create_test_traffic_event(i)).await?;
    }

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let app = app.clone();
            tokio::spawn(async move {
                let response = app.oneshot(claim_request(None, Some(3)).unwrap()).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let body = response.into_body().collect().await.unwrap().to_bytes();
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                v.as_array().unwrap().len()
            })
        })
        .collect();

    let mut total = 0;
    for h in handles {
        total += h.await?;
    }
    assert_eq!(total, 20);

    Ok(())
}

/// Tests boundary validation for max parameter
#[tokio::test(flavor = "current_thread")]
async fn max_validation_boundaries() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, _state, _handles) = make_router().await?;

    // Test max = 0 (invalid, should be rejected)
    let response = app.clone().oneshot(claim_request(Some(60000), Some(0))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test max = 1 (valid, boundary)
    let response = app.clone().oneshot(claim_request(Some(60000), Some(1))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test max = 1000 (valid, boundary)
    let response = app
        .clone()
        .oneshot(claim_request(Some(60000), Some(1000))?)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test max = 1001 (invalid, should be rejected)
    let response = app.oneshot(claim_request(Some(60000), Some(1001))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Tests boundary validation for lease_ms parameter
#[tokio::test(flavor = "current_thread")]
async fn lease_ms_validation_boundaries() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, _state, _handles) = make_router().await?;

    // Test lease_ms = 999 (invalid, should be rejected)
    let response = app.clone().oneshot(claim_request(Some(999), Some(10))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test lease_ms = 1000 (valid, boundary)
    let response = app.clone().oneshot(claim_request(Some(1000), Some(10))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test lease_ms = 3600000 (valid, boundary)
    let response = app
        .clone()
        .oneshot(claim_request(Some(3600000), Some(10))?)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test lease_ms = 3600001 (invalid, should be rejected)
    let response = app.oneshot(claim_request(Some(3600001), Some(10))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Tests that validation uses OR logic (both conditions must be checked)
#[tokio::test(flavor = "current_thread")]
async fn validation_logical_operators() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, _state, _handles) = make_router().await?;

    // Test invalid max with valid lease_ms - should be rejected (tests || in max validation)
    let response = app.clone().oneshot(claim_request(Some(60000), Some(0))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test valid max with invalid lease_ms - should be rejected (tests || in lease_ms validation)
    let response = app.oneshot(claim_request(Some(999), Some(10))?).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Tests boundary validation for ack ids array length
#[tokio::test(flavor = "current_thread")]
async fn ack_ids_length_validation() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, _state, _handles) = make_router().await?;

    // Test empty ids array (invalid, should be rejected)
    let response = app.clone().oneshot(ack_request(vec![])?).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test single id (valid)
    let response = app
        .clone()
        .oneshot(ack_request(vec![ulid::Ulid::new()])?)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test exactly 10,000 ids (valid, boundary)
    let ids: Vec<ulid::Ulid> = (0..10_000).map(|_| ulid::Ulid::new()).collect();
    let response = app.clone().oneshot(ack_request(ids)?).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test 10,001 ids (invalid, should be rejected)
    let ids: Vec<ulid::Ulid> = (0..10_001).map(|_| ulid::Ulid::new()).collect();
    let response = app.oneshot(ack_request(ids)?).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    Ok(())
}

/// Tests that requests without Bearer token are rejected with 401 Unauthorized
#[tokio::test(flavor = "current_thread")]
async fn unauthorized_without_token() -> anyhow::Result<()> {
    let _guard = init_logger();
    let (app, _state, _handles) = make_router().await?;

    // Test claim request without authorization header
    let claim_req = Request::builder()
        .method("POST")
        .uri("/jet/traffic/claim?lease_ms=60000&max=10")
        .body(Body::empty())?;
    let response = app.clone().oneshot(claim_req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test ack request without authorization header
    let payload = json!({ "ids": [1, 2, 3] });
    let ack_req = Request::builder()
        .method("POST")
        .uri("/jet/traffic/ack")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload)?))?;
    let response = app.oneshot(ack_req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}
