//! `/jet/fwd/tcp` tests for upstream connections routed through the agent tunnel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use super::fake_agent::{
    DirectTarget, FAR_FUTURE_EXP, FakeAgent, accept_and_echo, refuse, start_gateway_with_agent_tunnel, unsigned_token,
};

type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Opens a `/jet/fwd/tcp` session to `target` and returns the session ID with the client socket.
async fn open_forwarding(http_port: u16, target: &str, jet_agent_id: Option<Uuid>) -> (Uuid, ClientSocket) {
    let session_id = Uuid::new_v4();
    let token = unsigned_token(
        "ASSOCIATION",
        &json!({
            "jet_aid": session_id,
            "jet_ap": "unknown",
            "jet_cm": "fwd",
            "dst_hst": target,
            "jet_agent_id": jet_agent_id,
            "exp": FAR_FUTURE_EXP,
            "jti": Uuid::new_v4(),
        }),
    );
    let url = format!("ws://127.0.0.1:{http_port}/jet/fwd/tcp/{session_id}?token={token}");
    let (socket, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("open forwarding socket");
    (session_id, socket)
}

async fn assert_round_trip(socket: &mut ClientSocket, payload: &[u8]) {
    socket
        .send(Message::Binary(payload.to_vec().into()))
        .await
        .expect("send forwarding payload");
    let mut response = Vec::new();
    while response.len() < payload.len() {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("forwarding response timed out")
            .expect("forwarding socket closed")
            .expect("read forwarding response");
        match message {
            Message::Binary(data) => response.extend_from_slice(&data),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected forwarding message: {other:?}"),
        }
    }
    assert_eq!(response, payload);
}

/// Waits for the Gateway to close the session.
///
/// The Gateway closes a failed upstream connection with code 1014 (Bad Gateway).
/// tungstenite treats 1014 as reserved and reports it as 1002, so only the close itself is checked.
async fn assert_closed(socket: &mut ClientSocket) {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("forwarding close timed out")
            .expect("forwarding socket ended without a close frame")
            .expect("read forwarding close");
        match message {
            Message::Close(_) => return,
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("expected a close frame, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn fwd_routes_wildcard_domain_without_subnets() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "wildcard-agent").await;
    agent.advertise(&[], &["*.echo.test"]).await;

    let (session_id, mut socket) = open_forwarding(config.http_port(), "tcp://service.echo.test:443", None).await;
    let session = agent.accept_session(session_id, "service.echo.test:443").await;
    let _echo = accept_and_echo(session);

    assert_round_trip(&mut socket, b"agent tunnel payload").await;
}

#[tokio::test]
async fn fwd_falls_back_to_direct_tcp_without_a_route() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "unmatched-agent").await;
    agent.advertise(&[], &["unused.example"]).await;
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo server");
    let echo_port = echo.local_addr().expect("read echo server address").port();
    let echo_task = tokio::spawn(async move {
        let (stream, _) = echo.accept().await.expect("accept echo connection");
        let (mut read, mut write) = stream.into_split();
        let _ = tokio::io::copy(&mut read, &mut write).await;
    });

    let (_, mut socket) = open_forwarding(config.http_port(), &format!("tcp://127.0.0.1:{echo_port}"), None).await;

    assert_round_trip(&mut socket, b"direct payload").await;
    agent
        .assert_no_session("a target outside every advertised route must not go through the agent")
        .await;
    echo_task.abort();
}

#[tokio::test]
async fn fwd_uses_explicit_agent_without_a_matching_route() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "explicit-agent").await;
    agent.advertise(&[], &["unused.example"]).await;
    let direct = DirectTarget::bind().await;
    let target = direct.addr();

    let (session_id, mut socket) =
        open_forwarding(config.http_port(), &format!("tcp://{target}"), Some(agent.id)).await;
    let session = agent.accept_session(session_id, &target).await;
    let _echo = accept_and_echo(session);

    assert_round_trip(&mut socket, b"explicit payload").await;
    direct
        .assert_not_connected("an explicit agent must not fall back to direct TCP")
        .await;
}

#[tokio::test]
async fn fwd_tries_the_next_matching_agent() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut first = FakeAgent::enroll(config.http_port(), "first-agent").await;
    first.advertise(&[], &["service.example"]).await;
    let mut second = FakeAgent::enroll(config.http_port(), "second-agent").await;
    second.advertise(&[], &["service.example"]).await;

    let (session_id, mut socket) = open_forwarding(config.http_port(), "tcp://service.example:443", None).await;
    // Whichever agent the Gateway asks first refuses, so the session succeeds only through the other one.
    let refused = AtomicBool::new(false);
    let answer = async |agent: &FakeAgent| {
        let session = agent.accept_session(session_id, "service.example:443").await;
        if refused.swap(true, Ordering::SeqCst) {
            accept_and_echo(session);
        } else {
            refuse(session).await;
        }
    };
    tokio::join!(answer(&first), answer(&second));

    assert_round_trip(&mut socket, b"fallback payload").await;
}

#[tokio::test]
async fn fwd_does_not_bypass_failed_agent_routes() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut first = FakeAgent::enroll(config.http_port(), "first-agent").await;
    first.advertise(&["127.0.0.0/8"], &[]).await;
    let mut second = FakeAgent::enroll(config.http_port(), "second-agent").await;
    second.advertise(&["127.0.0.0/8"], &[]).await;
    let direct = DirectTarget::bind().await;
    let target = direct.addr();

    let (session_id, mut socket) = open_forwarding(config.http_port(), &format!("tcp://{target}"), None).await;
    tokio::join!(
        async { refuse(first.accept_session(session_id, &target).await).await },
        async { refuse(second.accept_session(session_id, &target).await).await },
    );

    assert_closed(&mut socket).await;
    direct
        .assert_not_connected("failed agent routes must not fall back to direct TCP")
        .await;
}
