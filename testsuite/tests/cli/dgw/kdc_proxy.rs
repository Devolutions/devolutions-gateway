//! `/jet/KdcProxy` tests for KDC traffic routed through the agent tunnel.

use std::time::Duration;

use serde_json::json;
use testsuite::cli::start_dgw;
use testsuite::dgw_config::{AgentTunnelConfig, DgwConfig};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};
use uuid::Uuid;

use super::fake_agent::{FAR_FUTURE_EXP, FakeAgent, accept_and_echo, start_gateway_with_agent_tunnel, unsigned_token};

/// A DER-encoded `KDC-PROXY-MESSAGE` (MS-KKDCP) carrying a dummy Kerberos message for the `example.com` realm.
const KDC_PROXY_REQUEST: &[u8] = &[
    0x30, 0x1B, // SEQUENCE
    0xA0, 0x0A, 0x04, 0x08, 0, 0, 0, 4, b't', b'e', b's', b't', // [0] kerb-message
    0xA1, 0x0D, 0x1B, 0x0B, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // [1] target-domain
];

/// The TCP-framed Kerberos message inside `KDC_PROXY_REQUEST`.
const KERB_REQUEST: &[u8] = b"\0\0\0\x04test";

/// A TCP-framed Kerberos reply.
const KERB_REPLY: &[u8] = b"\0\0\0\x04data";

/// An unsigned KDC token and its `jti`, which `/jet/KdcProxy` uses as the agent tunnel session ID.
fn kdc_token(krb_kdc: &str, jet_agent_id: Option<Uuid>) -> (Uuid, String) {
    let jti = Uuid::new_v4();
    let claims = json!({
        "krb_realm": "example.com",
        "krb_kdc": krb_kdc,
        "jti": jti,
        "jet_agent_id": jet_agent_id,
        "nbf": 1_733_669_999i64,
        "exp": FAR_FUTURE_EXP,
    });
    (jti, unsigned_token("KDC", &claims))
}

async fn post_kdc_proxy(http_port: u16, token: String) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{http_port}/jet/KdcProxy/{token}"))
        .body(KDC_PROXY_REQUEST)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("send KDC proxy request")
}

async fn assert_no_datagram(kdc: &UdpSocket, reason: &str) {
    let mut buf = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), kdc.recv_from(&mut buf))
            .await
            .is_err(),
        "{reason}"
    );
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

    let (_, token) = kdc_token(&format!("tcp://{kdc_addr}"), Some(Uuid::new_v4()));
    let response = post_kdc_proxy(config.http_port(), token).await;

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

#[tokio::test]
async fn kdc_proxy_relays_tcp_through_a_matching_agent() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "kdc-agent").await;
    agent.advertise(&["127.0.0.0/8"], &[]).await;

    let (jti, token) = kdc_token("tcp://127.0.0.1:88", None);
    let response = tokio::spawn(post_kdc_proxy(config.http_port(), token));
    let mut session = agent.accept_session(jti, "127.0.0.1:88").await;
    session
        .send_response(&agent_tunnel_proto::ConnectResponse::success())
        .await
        .expect("send connection success");
    let (mut send, mut recv) = session.into_inner();
    let mut request = vec![0; KERB_REQUEST.len()];
    recv.read_exact(&mut request).await.expect("read kdc request");
    assert_eq!(request, KERB_REQUEST);
    send.write_all(KERB_REPLY).await.expect("write kdc reply");

    let response = response.await.expect("KDC proxy request task panicked");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.bytes().await.expect("read KDC proxy reply");
    assert!(
        body.windows(KERB_REPLY.len()).any(|window| window == KERB_REPLY),
        "KDC proxy reply must carry the agent's Kerberos reply: {body:x?}"
    );
}

#[tokio::test]
async fn kdc_proxy_falls_back_to_direct_tcp_without_a_matching_route() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "unmatched-kdc-agent").await;
    agent.advertise(&[], &["unused.example"]).await;
    let kdc = TcpListener::bind("127.0.0.1:0").await.expect("bind fake kdc");
    let kdc_addr = kdc.local_addr().expect("read fake kdc address");
    let kdc_task = tokio::spawn(async move {
        let (mut stream, _) = kdc.accept().await.expect("accept kdc connection");
        let mut request = vec![0; KERB_REQUEST.len()];
        stream.read_exact(&mut request).await.expect("read kdc request");
        assert_eq!(request, KERB_REQUEST);
        stream.write_all(KERB_REPLY).await.expect("write kdc reply");
    });

    let (_, token) = kdc_token(&format!("tcp://{kdc_addr}"), None);
    let response = post_kdc_proxy(config.http_port(), token).await;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    kdc_task.await.expect("kdc task panicked");
    agent
        .assert_no_session("a KDC outside every advertised route must not go through the agent")
        .await;
}

#[tokio::test]
async fn kdc_proxy_rejects_udp_selected_for_an_agent_route() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "udp-kdc-agent").await;
    agent.advertise(&["127.0.0.0/8"], &[]).await;
    let kdc = UdpSocket::bind("127.0.0.1:0").await.expect("bind fake kdc");
    let kdc_addr = kdc.local_addr().expect("read fake kdc address");

    let (jti, token) = kdc_token(&format!("udp://{kdc_addr}"), None);
    let response = tokio::spawn(post_kdc_proxy(config.http_port(), token));
    let session = agent.accept_session(jti, &kdc_addr.to_string()).await;
    let _echo = accept_and_echo(session);

    let response = response.await.expect("KDC proxy request task panicked");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_no_datagram(
        &kdc,
        "a udp:// KDC matched by an agent route must not fall back to direct UDP",
    )
    .await;
}

#[tokio::test]
async fn kdc_proxy_rejects_udp_for_an_explicit_agent_before_dialing() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "udp-pinned-kdc-agent").await;
    agent.advertise(&["127.0.0.0/8"], &[]).await;
    let kdc = UdpSocket::bind("127.0.0.1:0").await.expect("bind fake kdc");
    let kdc_addr = kdc.local_addr().expect("read fake kdc address");

    let (_, token) = kdc_token(&format!("udp://{kdc_addr}"), Some(agent.id));
    let response = post_kdc_proxy(config.http_port(), token).await;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    agent
        .assert_no_session("the explicit agent must not be asked to dial the KDC for a udp:// target")
        .await;
    assert_no_datagram(&kdc, "a udp:// KDC pinned to an agent must not be reached directly").await;
}
