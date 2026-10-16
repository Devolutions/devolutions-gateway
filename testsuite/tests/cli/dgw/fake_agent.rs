//! A stand-in Agent that enrolls with a Gateway process and speaks the agent tunnel protocol directly.
//!
//! Tests control when it advertises routes and how it answers each connect request, which a real Agent does not allow.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use agent_tunnel_proto::{
    ConnectResponse, ControlMessage, ControlStream, DomainAdvertisement, DomainName, SessionStream,
};
use base64::Engine as _;
use ipnetwork::Ipv4Network;
use serde_json::json;
use testsuite::cli::start_dgw;
use testsuite::dgw_config::{AgentTunnelConfig, DgwConfig, DgwConfigHandle};
use tokio::net::TcpListener;
use tokio::process::Child;
use uuid::Uuid;

use crate::agent_tunnel::common::{connect_quinn_client, generate_csr_with_cn};

pub(crate) type AgentSession = SessionStream<quinn::SendStream, quinn::RecvStream>;

pub(crate) const FAR_FUTURE_EXP: i64 = 3_331_553_599;

/// Builds an unsigned JWT for a Gateway running with token validation disabled.
pub(crate) fn unsigned_token(content_type: &str, claims: &serde_json::Value) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(json!({ "alg": "RS256", "cty": content_type }).to_string());
    let payload = engine.encode(claims.to_string());
    let signature = engine.encode(b"signature");
    format!("{header}.{payload}.{signature}")
}

/// Starts a Gateway with the agent tunnel enabled and token validation disabled.
pub(crate) async fn start_gateway_with_agent_tunnel() -> (DgwConfigHandle, Child) {
    let config = DgwConfig::builder()
        .hostname("localhost".to_owned())
        .disable_token_validation(true)
        .agent_tunnel(AgentTunnelConfig::builder().build())
        .build()
        .init()
        .expect("init gateway config");
    let gateway = start_dgw(&config).await.expect("start gateway");
    (config, gateway)
}

pub(crate) struct FakeAgent {
    pub(crate) id: Uuid,
    connection: quinn::Connection,
    control: ControlStream<quinn::SendStream, quinn::RecvStream>,
    http_port: u16,
    epoch: u64,
}

impl FakeAgent {
    /// Enrolls through `/jet/tunnel/enroll` and connects to the QUIC endpoint the Gateway returns.
    pub(crate) async fn enroll(http_port: u16, name: &str) -> Self {
        let id = Uuid::new_v4();
        let (key_pair, csr_pem) = generate_csr_with_cn(name);
        let enrollment_token = unsigned_token(
            "ENROLLMENT",
            &json!({
                "exp": FAR_FUTURE_EXP,
                "jti": Uuid::new_v4(),
                "jet_gw_url": format!("http://127.0.0.1:{http_port}"),
                "jet_agent_name": name,
            }),
        );
        let response: serde_json::Value = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{http_port}/jet/tunnel/enroll"))
            .bearer_auth(enrollment_token)
            .json(&json!({ "agent_id": id, "csr_pem": csr_pem }))
            .send()
            .await
            .expect("send enrollment request")
            .error_for_status()
            .expect("enroll fake agent")
            .json()
            .await
            .expect("decode enrollment response");
        let field = |name: &str| {
            response[name]
                .as_str()
                .unwrap_or_else(|| panic!("enrollment response lacks {name}: {response}"))
        };
        let quic_port = field("quic_endpoint")
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .expect("parse QUIC endpoint port");
        let connection = connect_quinn_client(
            field("gateway_ca_cert_pem"),
            field("client_cert_pem"),
            &key_pair.serialize_pem(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, quic_port)),
        )
        .await;
        let control = connection.open_bi().await.expect("open control stream").into();

        Self {
            id,
            connection,
            control,
            http_port,
            epoch: 0,
        }
    }

    /// Replaces the advertised routes and waits until the Gateway reports them.
    pub(crate) async fn advertise(&mut self, subnets: &[&str], domains: &[&str]) {
        self.epoch += 1;
        let advertised_subnets = subnets
            .iter()
            .map(|subnet| subnet.parse::<Ipv4Network>().expect("parse test subnet"))
            .collect();
        let advertised_domains = domains
            .iter()
            .map(|domain| DomainAdvertisement {
                domain: DomainName::new(*domain),
                auto_detected: false,
            })
            .collect();
        self.control
            .send(&ControlMessage::route_advertise(
                self.epoch,
                advertised_subnets,
                advertised_domains,
            ))
            .await
            .expect("send route advertisement");

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let info = self.info().await;
            let reported_subnets: Vec<&str> = info["subnets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .collect();
            let reported_domains: Vec<&str> = info["domains"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|domain| domain["domain"].as_str())
                .collect();
            if info["status"] == "online" && reported_subnets == subnets && reported_domains == domains {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Gateway did not report the advertised routes: {info}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn info(&self) -> serde_json::Value {
        let token = unsigned_token(
            "SCOPE",
            &json!({ "scope": "gateway.agent.read", "exp": FAR_FUTURE_EXP, "jti": Uuid::new_v4() }),
        );
        let response = reqwest::Client::new()
            .get(format!(
                "http://127.0.0.1:{}/jet/tunnel/agents/{}",
                self.http_port, self.id
            ))
            .bearer_auth(token)
            .send()
            .await
            .expect("query agent");
        if !response.status().is_success() {
            return serde_json::Value::Null;
        }
        response.json().await.expect("decode agent")
    }

    /// Accepts the next connect request from the Gateway and checks its session and target.
    pub(crate) async fn accept_session(&self, session_id: Uuid, target: &str) -> AgentSession {
        let (send, recv) = tokio::time::timeout(Duration::from_secs(5), self.connection.accept_bi())
            .await
            .expect("connect request timed out")
            .expect("accept session stream");
        let mut session = AgentSession::from((send, recv));
        let request = session.recv_request().await.expect("receive connect request");
        assert_eq!(request.session_id(), session_id);
        assert_eq!(request.target(), target);
        session
    }

    pub(crate) async fn assert_no_session(&self, reason: &str) {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), self.connection.accept_bi())
                .await
                .is_err(),
            "{reason}"
        );
    }
}

/// Accepts a connect request and echoes everything the Gateway sends on it.
pub(crate) fn accept_and_echo(mut session: AgentSession) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        session
            .send_response(&ConnectResponse::success())
            .await
            .expect("send connection success");
        let (mut send, mut recv) = session.into_inner();
        let _ = tokio::io::copy(&mut recv, &mut send).await;
    })
}

pub(crate) async fn refuse(mut session: AgentSession) {
    session
        .send_response(&ConnectResponse::error("connection refused"))
        .await
        .expect("send connection error");
}

/// A listening TCP target that detects any direct connection from the Gateway.
pub(crate) struct DirectTarget {
    listener: TcpListener,
    pub(crate) port: u16,
}

impl DirectTarget {
    pub(crate) async fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind direct target");
        let port = listener.local_addr().expect("read direct target address").port();
        Self { listener, port }
    }

    pub(crate) fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub(crate) async fn assert_not_connected(&self, reason: &str) {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), self.listener.accept())
                .await
                .is_err(),
            "{reason}"
        );
    }
}
