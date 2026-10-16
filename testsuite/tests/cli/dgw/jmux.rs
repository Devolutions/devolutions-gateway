//! `/jet/jmux` tests for JMUX channels routed through the agent tunnel.

use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use jmux_proto::{Bytes, BytesMut, DestinationUrl, DistantChannelId, Header, LocalChannelId, Message, ReasonCode};
use serde_json::json;
use testsuite::cli::start_dgw;
use testsuite::dgw_config::DgwConfig;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use super::fake_agent::{
    DirectTarget, FAR_FUTURE_EXP, FakeAgent, refuse, start_gateway_with_agent_tunnel, unsigned_token,
};

/// A JMUX peer speaking to the Gateway over `/jet/jmux`.
struct JmuxClient {
    session_id: Uuid,
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    received: BytesMut,
}

impl JmuxClient {
    /// Opens a JMUX session whose token authorizes `target` only.
    async fn connect(http_port: u16, target: &DirectTarget, jet_agent_id: Option<Uuid>) -> Self {
        let session_id = Uuid::new_v4();
        let token = unsigned_token(
            "JMUX",
            &json!({
                "jet_aid": session_id,
                "jet_ap": "unknown",
                "dst_hst": format!("tcp://{}", target.addr()),
                "jet_agent_id": jet_agent_id,
                "exp": FAR_FUTURE_EXP,
                "jti": Uuid::new_v4(),
            }),
        );
        let url = format!("ws://127.0.0.1:{http_port}/jet/jmux?token={token}");
        let (socket, _) = tokio_tungstenite::connect_async(url).await.expect("open JMUX socket");

        Self {
            session_id,
            socket,
            received: BytesMut::new(),
        }
    }

    async fn send(&mut self, message: Message) {
        let mut bytes = BytesMut::new();
        message.encode(&mut bytes).expect("encode JMUX message");
        self.socket
            .send(WsMessage::Binary(bytes.freeze()))
            .await
            .expect("send JMUX message");
    }

    async fn open(&mut self, channel_id: u32, target: &DirectTarget) {
        self.send(Message::open(
            LocalChannelId::from(channel_id),
            4096,
            DestinationUrl::new("tcp", "127.0.0.1", target.port),
        ))
        .await;
    }

    async fn recv(&mut self) -> Message {
        loop {
            if self.received.len() >= Header::SIZE {
                let header =
                    Header::decode(Bytes::copy_from_slice(&self.received[..Header::SIZE])).expect("decode JMUX header");
                let size = usize::from(header.size);
                if self.received.len() >= size {
                    return Message::decode(self.received.split_to(size).freeze()).expect("decode JMUX message");
                }
            }

            let message = tokio::time::timeout(Duration::from_secs(5), self.socket.next())
                .await
                .expect("JMUX response timed out")
                .expect("JMUX socket closed")
                .expect("read JMUX socket");
            match message {
                WsMessage::Binary(data) => self.received.extend_from_slice(&data),
                WsMessage::Ping(_) | WsMessage::Pong(_) => {}
                other => panic!("unexpected JMUX socket message: {other:?}"),
            }
        }
    }

    async fn assert_closed_with(&mut self, expected_code: u16) {
        loop {
            let message = tokio::time::timeout(Duration::from_secs(5), self.socket.next())
                .await
                .expect("JMUX close timed out")
                .expect("JMUX socket ended without a close frame")
                .expect("read JMUX close");
            match message {
                WsMessage::Close(Some(frame)) => {
                    assert_eq!(u16::from(frame.code), expected_code);
                    return;
                }
                WsMessage::Ping(_) | WsMessage::Pong(_) => {}
                other => panic!("expected a close frame, got {other:?}"),
            }
        }
    }
}

#[tokio::test]
async fn jmux_uses_agent_route_without_direct_fallback() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "jmux-agent").await;
    agent.advertise(&["127.0.0.0/8"], &[]).await;
    let direct = DirectTarget::bind().await;
    let mut jmux = JmuxClient::connect(config.http_port(), &direct, None).await;

    jmux.open(20, &direct).await;
    let mut routed_session = agent.accept_session(jmux.session_id, &direct.addr()).await;
    routed_session
        .send_response(&agent_tunnel_proto::ConnectResponse::success())
        .await
        .expect("accept routed JMUX request");
    let Message::OpenSuccess(success) = jmux.recv().await else {
        panic!("expected OPEN SUCCESS");
    };
    assert_eq!(success.recipient_channel_id, 20);

    let local_id = DistantChannelId::from(success.sender_channel_id);
    jmux.send(Message::data(local_id, Bytes::from_static(b"ping"))).await;
    let (mut routed_send, mut routed_recv) = routed_session.into_inner();
    let mut request = [0; 4];
    routed_recv
        .read_exact(&mut request)
        .await
        .expect("read routed JMUX payload");
    assert_eq!(&request, b"ping");
    routed_send
        .write_all(b"pong")
        .await
        .expect("write routed JMUX response");
    let Message::Data(response) = jmux.recv().await else {
        panic!("expected CHANNEL DATA");
    };
    assert_eq!(response.recipient_channel_id, 20);
    assert_eq!(response.transfer_data, b"pong"[..]);

    jmux.open(21, &direct).await;
    refuse(agent.accept_session(jmux.session_id, &direct.addr()).await).await;
    let Message::OpenFailure(failure) = jmux.recv().await else {
        panic!("expected OPEN FAILURE");
    };
    assert_eq!(failure.recipient_channel_id, 21);
    assert_eq!(failure.reason_code, ReasonCode::GENERAL_FAILURE);
    direct
        .assert_not_connected("a matched agent route must not fall back to direct TCP")
        .await;
}

#[tokio::test]
async fn jmux_routes_explicit_agent_without_a_matching_route() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let mut agent = FakeAgent::enroll(config.http_port(), "jmux-explicit-agent").await;
    agent.advertise(&[], &["unused.example"]).await;
    let direct = DirectTarget::bind().await;
    let mut jmux = JmuxClient::connect(config.http_port(), &direct, Some(agent.id)).await;

    jmux.open(30, &direct).await;
    let mut routed_session = agent.accept_session(jmux.session_id, &direct.addr()).await;
    routed_session
        .send_response(&agent_tunnel_proto::ConnectResponse::success())
        .await
        .expect("accept routed JMUX request");
    let Message::OpenSuccess(success) = jmux.recv().await else {
        panic!("expected OPEN SUCCESS");
    };
    assert_eq!(success.recipient_channel_id, 30);
    direct
        .assert_not_connected("an explicit agent must not fall back to direct TCP")
        .await;
}

#[tokio::test]
async fn jmux_rejects_unknown_explicit_agent_without_direct_fallback() {
    let (config, _gateway) = start_gateway_with_agent_tunnel().await;
    let direct = DirectTarget::bind().await;
    let mut jmux = JmuxClient::connect(config.http_port(), &direct, Some(Uuid::new_v4())).await;

    jmux.open(31, &direct).await;
    let Message::OpenFailure(failure) = jmux.recv().await else {
        panic!("expected OPEN FAILURE");
    };
    assert_eq!(failure.recipient_channel_id, 31);
    assert_eq!(failure.reason_code, ReasonCode::GENERAL_FAILURE);
    direct
        .assert_not_connected("an unknown explicit agent must not fall back to direct TCP")
        .await;
}

#[tokio::test]
async fn jmux_rejects_explicit_agent_when_agent_tunnel_is_disabled() {
    let config = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .expect("init gateway config");
    let _gateway = start_dgw(&config).await.expect("start gateway");
    let direct = DirectTarget::bind().await;
    let mut jmux = JmuxClient::connect(config.http_port(), &direct, Some(Uuid::new_v4())).await;

    jmux.assert_closed_with(1011).await;
    direct
        .assert_not_connected("an explicit agent must not connect directly when the agent tunnel is disabled")
        .await;
}
