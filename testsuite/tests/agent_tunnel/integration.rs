use std::time::Duration;

use agent_tunnel::AgentTunnelHandle;
use agent_tunnel::cert::extract_agent_id_from_pem;
use agent_tunnel::registry::AgentRegistry;
use agent_tunnel_proto::{
    CertRenewalResult, ConnectResponse, ControlMessage, ControlStream, DomainAdvertisement, DomainName,
};
use devolutions_gateway::target_addr::TargetAddr;
use devolutions_gateway::upstream::{ConnectedUpstream, UpstreamLeg, connect_upstream};
use nonempty::NonEmpty;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use super::common::{
    accept_session_request, advertise_routes, bind_test_listener, generate_csr_with_cn, start_echo_server,
    wait_for_route_advertised,
};

fn target(host: &str, port: u16) -> TargetAddr {
    TargetAddr::from_components("tcp", host, port).expect("build target address")
}

async fn advertise_domain(
    connection: &quinn::Connection,
    registry: &AgentRegistry,
    agent_id: Uuid,
    epoch: u64,
    domain: &str,
) -> ControlStream<quinn::SendStream, quinn::RecvStream> {
    advertise_routes(
        connection,
        registry,
        agent_id,
        epoch,
        vec![],
        vec![DomainAdvertisement {
            domain: DomainName::new(domain),
            auto_detected: false,
        }],
    )
    .await
}

async fn set_route_order(registry: &AgentRegistry, older: Uuid, newer: Uuid) {
    registry
        .get(&older)
        .await
        .expect("find older agent")
        .set_received_at_for_test(std::time::UNIX_EPOCH + Duration::from_secs(1));
    registry
        .get(&newer)
        .await
        .expect("find newer agent")
        .set_received_at_for_test(std::time::UNIX_EPOCH + Duration::from_secs(2));
}

async fn connect(
    handle: AgentTunnelHandle,
    target: TargetAddr,
    explicit_agent_id: Option<Uuid>,
    session_id: Uuid,
) -> anyhow::Result<ConnectedUpstream> {
    connect_upstream(&NonEmpty::new(target), explicit_agent_id, session_id, Some(&handle)).await
}

async fn assert_round_trip(mut upstream: UpstreamLeg, payload: &[u8]) {
    upstream.write_all(payload).await.expect("write upstream payload");
    let mut response = vec![0; payload.len()];
    upstream
        .read_exact(&mut response)
        .await
        .expect("read upstream response");
    assert_eq!(response, payload);
}

#[tokio::test]
async fn gateway_connect_upstream_routes_wildcard_domain_without_subnets() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("test-agent").await;
    let (echo_addr, echo_task) = start_echo_server().await;
    let _ctrl = advertise_domain(&connection, listener.handle.registry(), agent_id, 1, "*.echo.test").await;

    let session_id = Uuid::new_v4();
    let expected_target = format!("service.echo.test:{}", echo_addr.port());
    let handle = listener.handle.clone();
    let connect_task = tokio::spawn(connect(
        handle,
        target("service.echo.test", echo_addr.port()),
        None,
        session_id,
    ));

    let mut session = accept_session_request(&connection, session_id, &expected_target).await;

    let mut tcp_stream = TcpStream::connect(echo_addr).await.expect("connect to echo server");
    session
        .send_response(&ConnectResponse::success())
        .await
        .expect("send connection success");

    let connected = tokio::time::timeout(Duration::from_secs(5), connect_task)
        .await
        .expect("upstream connection timed out")
        .expect("upstream task panicked")
        .expect("connect through agent");
    assert!(matches!(connected.leg, UpstreamLeg::Tunnel(_)));

    let payload = b"agent tunnel payload";
    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(connected.leg);
    tunnel_write.write_all(payload).await.expect("write tunnel payload");

    let (mut session_send, mut session_recv) = session.into_inner();
    let mut relay = vec![0; payload.len()];
    session_recv.read_exact(&mut relay).await.expect("read agent payload");
    tcp_stream.write_all(&relay).await.expect("write echo payload");
    tcp_stream.read_exact(&mut relay).await.expect("read echo payload");
    session_send.write_all(&relay).await.expect("write agent response");

    let mut response = vec![0; payload.len()];
    tunnel_read
        .read_exact(&mut response)
        .await
        .expect("read tunnel response");
    assert_eq!(response, payload);

    connection.close(0u32.into(), b"test done");
    echo_task.abort();
    listener.shutdown().await;
}

#[tokio::test]
async fn gateway_connect_upstream_falls_back_to_direct_tcp_without_a_route() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("unmatched-agent").await;
    let _ctrl = advertise_domain(&connection, listener.handle.registry(), agent_id, 1, "unused.example").await;
    let (echo_addr, echo_task) = start_echo_server().await;

    let connected = connect(
        listener.handle.clone(),
        target("127.0.0.1", echo_addr.port()),
        None,
        Uuid::new_v4(),
    )
    .await
    .expect("connect directly");
    assert!(matches!(connected.leg, UpstreamLeg::Tcp(_)));
    assert_round_trip(connected.leg, b"direct payload").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), connection.accept_bi())
            .await
            .is_err()
    );

    connection.close(0u32.into(), b"test done");
    echo_task.abort();
    listener.shutdown().await;
}

#[tokio::test]
async fn gateway_connect_upstream_uses_explicit_agent_without_a_matching_route() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("explicit-agent").await;
    let _ctrl = advertise_domain(&connection, listener.handle.registry(), agent_id, 1, "unused.example").await;
    let (echo_addr, echo_task) = start_echo_server().await;
    let session_id = Uuid::new_v4();
    let target_addr = format!("127.0.0.1:{}", echo_addr.port());
    let connect_task = tokio::spawn(connect(
        listener.handle.clone(),
        target("127.0.0.1", echo_addr.port()),
        Some(agent_id),
        session_id,
    ));

    let mut session = accept_session_request(&connection, session_id, &target_addr).await;
    let tcp_stream = TcpStream::connect(echo_addr).await.expect("connect to echo server");
    session
        .send_response(&ConnectResponse::success())
        .await
        .expect("send connection success");
    let connected = connect_task
        .await
        .expect("upstream task panicked")
        .expect("connect through explicit agent");
    let relay_task = tokio::spawn(async move {
        let (mut send, mut recv) = session.into_inner();
        let (mut read, mut write) = tcp_stream.into_split();
        tokio::try_join!(
            tokio::io::copy(&mut recv, &mut write),
            tokio::io::copy(&mut read, &mut send)
        )
    });
    assert_round_trip(connected.leg, b"explicit payload").await;

    relay_task.abort();
    connection.close(0u32.into(), b"test done");
    echo_task.abort();
    listener.shutdown().await;
}

#[tokio::test]
async fn gateway_connect_upstream_tries_the_next_matching_agent() {
    let listener = bind_test_listener().await;
    let (fallback_id, fallback_connection) = listener.connect_agent("fallback-agent").await;
    let _fallback_ctrl = advertise_domain(
        &fallback_connection,
        listener.handle.registry(),
        fallback_id,
        1,
        "service.example",
    )
    .await;
    let (first_id, first_connection) = listener.connect_agent("first-agent").await;
    let _first_ctrl = advertise_domain(
        &first_connection,
        listener.handle.registry(),
        first_id,
        1,
        "service.example",
    )
    .await;
    set_route_order(listener.handle.registry(), fallback_id, first_id).await;
    let session_id = Uuid::new_v4();
    let target_addr = "service.example:443";
    let connect_task = tokio::spawn(connect(
        listener.handle.clone(),
        target("service.example", 443),
        None,
        session_id,
    ));

    let mut first_session = accept_session_request(&first_connection, session_id, target_addr).await;
    first_session
        .send_response(&ConnectResponse::error("connection refused"))
        .await
        .expect("send connection error");
    let mut fallback_session = accept_session_request(&fallback_connection, session_id, target_addr).await;
    fallback_session
        .send_response(&ConnectResponse::success())
        .await
        .expect("send connection success");
    let connected = connect_task
        .await
        .expect("upstream task panicked")
        .expect("connect through fallback agent");
    assert!(matches!(connected.leg, UpstreamLeg::Tunnel(_)));

    first_connection.close(0u32.into(), b"test done");
    fallback_connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}

#[tokio::test]
async fn gateway_connect_upstream_does_not_bypass_failed_agent_routes() {
    let listener = bind_test_listener().await;
    let (first_id, first_connection) = listener.connect_agent("first-agent").await;
    let _first_ctrl = advertise_routes(
        &first_connection,
        listener.handle.registry(),
        first_id,
        1,
        vec!["127.0.0.0/8".parse().expect("parse test subnet")],
        vec![],
    )
    .await;
    let (second_id, second_connection) = listener.connect_agent("second-agent").await;
    let _second_ctrl = advertise_routes(
        &second_connection,
        listener.handle.registry(),
        second_id,
        1,
        vec!["127.0.0.0/8".parse().expect("parse test subnet")],
        vec![],
    )
    .await;
    set_route_order(listener.handle.registry(), first_id, second_id).await;
    let direct_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind direct target");
    let target_port = direct_listener.local_addr().expect("read direct target address").port();
    let session_id = Uuid::new_v4();
    let target_addr = format!("127.0.0.1:{target_port}");
    let connect_task = tokio::spawn(connect(
        listener.handle.clone(),
        target("127.0.0.1", target_port),
        None,
        session_id,
    ));

    let mut second_session = accept_session_request(&second_connection, session_id, &target_addr).await;
    second_session
        .send_response(&ConnectResponse::error("connection refused"))
        .await
        .expect("send connection error");
    let mut first_session = accept_session_request(&first_connection, session_id, &target_addr).await;
    first_session
        .send_response(&ConnectResponse::error("connection refused"))
        .await
        .expect("send connection error");
    let error = match connect_task.await.expect("upstream task panicked") {
        Ok(_) => panic!("all routed connections should fail"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("connection refused"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), direct_listener.accept())
            .await
            .is_err()
    );

    first_connection.close(0u32.into(), b"test done");
    second_connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}

#[tokio::test]
async fn gateway_listener_renews_authenticated_agent_identity() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("renewal-agent").await;
    let expected_ca = listener.handle.ca_manager().ca_cert_pem().to_owned();
    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.expect("open control stream").into();

    ctrl.send(&ControlMessage::route_advertise(1, vec![], vec![]))
        .await
        .expect("send route advertisement");
    wait_for_route_advertised(listener.handle.registry(), agent_id, 1).await;

    let (_, csr_pem) = generate_csr_with_cn("evil-impersonator");
    ctrl.send(&ControlMessage::cert_renewal_request(csr_pem))
        .await
        .expect("send renewal request");

    let response = tokio::time::timeout(Duration::from_secs(5), ctrl.recv())
        .await
        .expect("renewal response timed out")
        .expect("receive renewal response");
    let renewed_pem = match response {
        ControlMessage::CertRenewalResponse {
            result:
                CertRenewalResult::Success {
                    client_cert_pem,
                    gateway_ca_cert_pem,
                },
            ..
        } => {
            assert_eq!(gateway_ca_cert_pem, expected_ca);
            client_cert_pem
        }
        other => panic!("expected successful renewal, got {other:?}"),
    };

    assert_eq!(
        extract_agent_id_from_pem(&renewed_pem).expect("read renewed agent identity"),
        agent_id
    );

    connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}
