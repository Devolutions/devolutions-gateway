use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{ConnectResponse, ControlStream};
use devolutions_gateway::kdc_connector::KdcConnector;
use devolutions_gateway::target_addr::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use super::common::{accept_session_request, advertise_routes, bind_test_listener};

const KDC_REQUEST: &[u8] = b"\0\0\0\x04test";
const KDC_REPLY: &[u8] = b"\0\0\0\x04data";

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
