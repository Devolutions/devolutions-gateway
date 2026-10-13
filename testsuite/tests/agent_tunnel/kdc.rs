use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{ConnectResponse, ControlStream};
use base64::Engine as _;
use devolutions_gateway::kdc_connector::KdcConnector;
use devolutions_gateway::target_addr::TargetAddr;
use devolutions_gateway::{DgwState, MockHandles};
use picky_asn1::restricted_string::Ia5String;
use picky_asn1::wrapper::{ExplicitContextTag1, GeneralStringAsn1, Optional};
use picky_krb::messages::KdcProxyMessage;
use testsuite::dgw_config::DgwConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use super::common::{accept_session_request, advertise_routes, bind_test_listener};

const KDC_REQUEST: &[u8] = b"\0\0\0\x04test";
const KDC_REPLY: &[u8] = b"\0\0\0\x04data";
const KDC_REALM: &str = "example.com";

fn target(scheme: &str, port: u16) -> TargetAddr {
    TargetAddr::from_components(scheme, "127.0.0.1", port).expect("build kdc target")
}

async fn advertise_loopback(
    connection: &quinn::Connection,
    listener: &super::common::TestListener,
    agent_id: Uuid,
) -> ControlStream<quinn::SendStream, quinn::RecvStream> {
    advertise_routes(
        connection,
        listener.handle.registry(),
        agent_id,
        1,
        vec!["127.0.0.0/8".parse().expect("parse test subnet")],
        vec![],
    )
    .await
}

#[tokio::test]
async fn kdc_connector_relays_tcp_through_a_matching_agent() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("kdc-agent").await;
    let _ctrl = advertise_loopback(&connection, &listener, agent_id).await;
    let session_id = Uuid::new_v4();
    let kdc_target = target("tcp", 88);
    let connector = KdcConnector::new(session_id, None, Some(Arc::new(listener.handle.clone())));
    let send_task = tokio::spawn(async move { connector.send(&kdc_target, KDC_REQUEST).await });

    let mut session = accept_session_request(&connection, session_id, "127.0.0.1:88").await;
    session
        .send_response(&ConnectResponse::success())
        .await
        .expect("send connection success");
    let (mut send, mut recv) = session.into_inner();
    let mut request = vec![0; KDC_REQUEST.len()];
    recv.read_exact(&mut request).await.expect("read kdc request");
    assert_eq!(request, KDC_REQUEST);
    send.write_all(KDC_REPLY).await.expect("write kdc reply");

    let reply = match send_task.await.expect("kdc task panicked") {
        Ok(reply) => reply,
        Err(error) => panic!("relay kdc request through agent: {error}"),
    };
    assert_eq!(reply, KDC_REPLY);

    connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}

#[tokio::test]
async fn kdc_connector_falls_back_to_direct_tcp_without_a_matching_route() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("unmatched-kdc-agent").await;
    let _ctrl = advertise_routes(&connection, listener.handle.registry(), agent_id, 1, vec![], vec![]).await;
    let kdc = TcpListener::bind("127.0.0.1:0").await.expect("bind fake kdc");
    let port = kdc.local_addr().expect("read fake kdc address").port();
    let kdc_task = tokio::spawn(async move {
        let (mut stream, _) = kdc.accept().await.expect("accept kdc connection");
        let mut request = vec![0; KDC_REQUEST.len()];
        stream.read_exact(&mut request).await.expect("read kdc request");
        assert_eq!(request, KDC_REQUEST);
        stream.write_all(KDC_REPLY).await.expect("write kdc reply");
    });
    let connector = KdcConnector::new(Uuid::new_v4(), None, Some(Arc::new(listener.handle.clone())));

    let reply = match connector.send(&target("tcp", port), KDC_REQUEST).await {
        Ok(reply) => reply,
        Err(error) => panic!("send directly to kdc: {error}"),
    };
    assert_eq!(reply, KDC_REPLY);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), connection.accept_bi())
            .await
            .is_err()
    );

    kdc_task.await.expect("kdc task panicked");
    connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}

#[tokio::test]
async fn kdc_connector_rejects_udp_selected_for_an_agent_route() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("udp-kdc-agent").await;
    let _ctrl = advertise_loopback(&connection, &listener, agent_id).await;
    let session_id = Uuid::new_v4();
    let connector = KdcConnector::new(session_id, None, Some(Arc::new(listener.handle.clone())));
    let send_task = tokio::spawn(async move { connector.send(&target("udp", 88), KDC_REQUEST).await });

    let mut session = accept_session_request(&connection, session_id, "127.0.0.1:88").await;
    session
        .send_response(&ConnectResponse::success())
        .await
        .expect("send connection success");
    let error = send_task
        .await
        .expect("kdc task panicked")
        .expect_err("udp agent route should be rejected");
    assert!(format!("{error}").contains("does not yet support UDP"));

    connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}

#[tokio::test]
async fn kdc_connector_rejects_an_explicit_missing_agent() {
    let listener = bind_test_listener().await;
    let missing_agent_id = Uuid::new_v4();
    let connector = KdcConnector::new(
        Uuid::new_v4(),
        Some(missing_agent_id),
        Some(Arc::new(listener.handle.clone())),
    );

    let error = connector
        .send(&target("tcp", 88), KDC_REQUEST)
        .await
        .expect_err("missing explicit agent should be rejected");
    assert!(format!("{error}").contains(&format!("agent {missing_agent_id} specified in token not found")));

    listener.shutdown().await;
}

/// A Gateway HTTP service served on a loopback port, with or without an Agent Tunnel.
struct GatewayHttp {
    base_url: String,
    _handles: MockHandles,
    task: tokio::task::JoinHandle<()>,
}

impl GatewayHttp {
    async fn start(agent_tunnel: Option<&super::common::TestListener>) -> Self {
        let config_handle = DgwConfig::builder()
            .disable_token_validation(true)
            .build()
            .init()
            .expect("write gateway config");
        let config =
            std::fs::read_to_string(config_handle.config_dir().join("gateway.json")).expect("read gateway config");
        let (mut state, handles) = DgwState::mock(&config).expect("mock gateway state");
        state.agent_tunnel_handle = agent_tunnel.map(|listener| Arc::new(listener.handle.clone()));

        let app = devolutions_gateway::make_http_service(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway http listener");
        let addr = listener.local_addr().expect("read gateway http address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("serve gateway http");
        });

        Self {
            base_url: format!("http://{addr}"),
            _handles: handles,
            task,
        }
    }

    async fn post_kdc_proxy(&self, token: &str, body: Vec<u8>) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/jet/KdcProxy/{token}", self.base_url))
            .body(body)
            .send()
            .await
            .expect("send KDC proxy request")
    }

    fn stop(self) {
        self.task.abort();
    }
}

/// An unsigned KDC token; the Gateway under test runs with token validation disabled.
fn kdc_token(jti: Uuid, krb_kdc: &str, jet_agent_id: Option<Uuid>) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs(),
    )
    .expect("timestamp fits in i64");

    let mut claims = serde_json::json!({
        "krb_realm": KDC_REALM,
        "krb_kdc": krb_kdc,
        "jti": jti,
        "nbf": now,
        "exp": now + 3600,
    });
    if let Some(agent_id) = jet_agent_id {
        claims["jet_agent_id"] = serde_json::json!(agent_id);
    }

    let header = engine.encode(r#"{"alg":"RS256","cty":"KDC"}"#);
    let payload = engine.encode(serde_json::to_vec(&claims).expect("serialize KDC claims"));
    let signature = engine.encode(b"signature");
    format!("{header}.{payload}.{signature}")
}

/// A DER-encoded `KDC-PROXY-MESSAGE` (MS-KKDCP) carrying [`KDC_REQUEST`] for [`KDC_REALM`].
fn kdc_proxy_request() -> Vec<u8> {
    let realm: Ia5String = KDC_REALM.parse().expect("realm is IA5");
    let mut message = KdcProxyMessage::from_raw_kerb_message(KDC_REQUEST).expect("build KDC proxy message");
    message.target_domain = Optional::from(Some(ExplicitContextTag1::from(GeneralStringAsn1::from(realm))));
    message.to_vec().expect("encode KDC proxy message")
}

#[tokio::test]
async fn kdc_proxy_routes_through_the_explicit_agent_of_the_token() {
    let listener = bind_test_listener().await;
    let (pinned_agent_id, pinned_connection) = listener.connect_agent("pinned-kdc-agent").await;
    let _pinned_ctrl = advertise_routes(
        &pinned_connection,
        listener.handle.registry(),
        pinned_agent_id,
        1,
        vec![],
        vec![],
    )
    .await;
    // A second agent advertises the KDC address, so route matching alone would pick it.
    let (matching_agent_id, matching_connection) = listener.connect_agent("route-matching-kdc-agent").await;
    let _matching_ctrl = advertise_loopback(&matching_connection, &listener, matching_agent_id).await;
    let gateway = GatewayHttp::start(Some(&listener)).await;

    let token_jti = Uuid::new_v4();
    let token = kdc_token(token_jti, "tcp://127.0.0.1:88", Some(pinned_agent_id));

    let pinned_agent = async {
        let mut session = accept_session_request(&pinned_connection, token_jti, "127.0.0.1:88").await;
        session
            .send_response(&ConnectResponse::success())
            .await
            .expect("send connection success");
        let (mut send, mut recv) = session.into_inner();
        let mut kdc_request = vec![0; KDC_REQUEST.len()];
        recv.read_exact(&mut kdc_request).await.expect("read kdc request");
        assert_eq!(kdc_request, KDC_REQUEST);
        send.write_all(KDC_REPLY).await.expect("write kdc reply");
        // Keep the stream open until the Gateway has read the reply.
        (send, recv)
    };
    let (response, _pinned_stream) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(gateway.post_kdc_proxy(&token, kdc_proxy_request()), pinned_agent)
    })
    .await
    .expect("KDC traffic should reach the explicit agent");

    assert!(
        response.status().is_success(),
        "KDC proxy failed: {}",
        response.status()
    );
    let body = response.bytes().await.expect("read KDC proxy reply");
    let reply = KdcProxyMessage::from_raw(&body).expect("decode KDC proxy reply");
    assert_eq!(reply.kerb_message.0.0, KDC_REPLY);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), matching_connection.accept_bi())
            .await
            .is_err(),
        "the route-matching agent must not receive KDC traffic for a token with an explicit agent"
    );

    gateway.stop();
    pinned_connection.close(0u32.into(), b"test done");
    matching_connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}

#[tokio::test]
async fn kdc_proxy_rejects_a_missing_explicit_agent_without_direct_fallback() {
    let listener = bind_test_listener().await;
    let gateway = GatewayHttp::start(Some(&listener)).await;
    let kdc = TcpListener::bind("127.0.0.1:0").await.expect("bind fake kdc");
    let kdc_addr = kdc.local_addr().expect("read fake kdc address");

    let token = kdc_token(Uuid::new_v4(), &format!("tcp://{kdc_addr}"), Some(Uuid::new_v4()));
    let response = gateway.post_kdc_proxy(&token, kdc_proxy_request()).await;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), kdc.accept())
            .await
            .is_err(),
        "a token with an explicit agent must never reach the KDC directly"
    );

    gateway.stop();
    listener.shutdown().await;
}

#[tokio::test]
async fn kdc_proxy_rejects_an_explicit_agent_when_agent_tunnel_is_disabled() {
    let gateway = GatewayHttp::start(None).await;
    let kdc = TcpListener::bind("127.0.0.1:0").await.expect("bind fake kdc");
    let kdc_addr = kdc.local_addr().expect("read fake kdc address");

    let token = kdc_token(Uuid::new_v4(), &format!("tcp://{kdc_addr}"), Some(Uuid::new_v4()));
    let response = gateway.post_kdc_proxy(&token, kdc_proxy_request()).await;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), kdc.accept())
            .await
            .is_err(),
        "a token with an explicit agent must never reach the KDC directly"
    );

    gateway.stop();
}

#[tokio::test]
async fn kdc_connector_rejects_udp_for_an_explicit_agent_before_dialing() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("udp-pinned-kdc-agent").await;
    let _ctrl = advertise_loopback(&connection, &listener, agent_id).await;
    let connector = KdcConnector::new(Uuid::new_v4(), Some(agent_id), Some(Arc::new(listener.handle.clone())));

    let error = connector
        .send(&target("udp", 88), KDC_REQUEST)
        .await
        .expect_err("udp with an explicit agent should be rejected");
    assert!(format!("{error}").contains("does not yet support UDP"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), connection.accept_bi())
            .await
            .is_err(),
        "the explicit agent must not be asked to dial the KDC for a udp:// target"
    );

    connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}
