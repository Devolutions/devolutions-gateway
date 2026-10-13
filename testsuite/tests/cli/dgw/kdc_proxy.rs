//! `/jet/KdcProxy` tests for KDC tokens pinned to an explicit agent.

use std::time::Duration;

use base64::Engine as _;
use testsuite::cli::start_dgw;
use testsuite::dgw_config::{AgentTunnelConfig, DgwConfig};
use tokio::net::TcpListener;
use uuid::Uuid;

/// A DER-encoded `KDC-PROXY-MESSAGE` (MS-KKDCP) carrying a dummy Kerberos message for the `example.com` realm.
const KDC_PROXY_REQUEST: &[u8] = &[
    0x30, 0x1B, // SEQUENCE
    0xA0, 0x0A, 0x04, 0x08, 0, 0, 0, 4, b't', b'e', b's', b't', // [0] kerb-message
    0xA1, 0x0D, 0x1B, 0x0B, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // [1] target-domain
];

/// An unsigned KDC token; the Gateway under test runs with token validation disabled.
fn kdc_token(krb_kdc: &str, jet_agent_id: Uuid) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let claims = serde_json::json!({
        "krb_realm": "example.com",
        "krb_kdc": krb_kdc,
        "jti": Uuid::new_v4(),
        "jet_agent_id": jet_agent_id,
        "nbf": 1_733_669_999i64,
        "exp": 3_331_553_599i64,
    });

    let header = engine.encode(r#"{"alg":"RS256","cty":"KDC"}"#);
    let payload = engine.encode(serde_json::to_vec(&claims).expect("serialize KDC claims"));
    let signature = engine.encode(b"signature");
    format!("{header}.{payload}.{signature}")
}

#[tokio::test]
async fn kdc_proxy_never_dials_the_kdc_directly_for_a_missing_explicit_agent() {
    let config = DgwConfig::builder()
        .disable_token_validation(true)
        .agent_tunnel(AgentTunnelConfig::builder().build())
        .build()
        .init()
        .expect("init gateway config");
    let mut gateway = start_dgw(&config).await.expect("start gateway");
    let kdc = TcpListener::bind("127.0.0.1:0").await.expect("bind fake kdc");
    let kdc_addr = kdc.local_addr().expect("read fake kdc address");

    let token = kdc_token(&format!("tcp://{kdc_addr}"), Uuid::new_v4());
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/jet/KdcProxy/{token}", config.http_port()))
        .body(KDC_PROXY_REQUEST)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("send KDC proxy request");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), kdc.accept())
            .await
            .is_err(),
        "a token with an explicit agent must never reach the KDC directly"
    );

    let _ = gateway.start_kill();
    let _ = gateway.wait().await;
}
