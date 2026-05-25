//! Full-stack integration test for the QUIC agent tunnel (Quinn).
//!
//! Verifies the full data path:
//!   TCP echo server ← Agent (Quinn client) ← QUIC mTLS ← Gateway listener ← TunnelStream
//!
//! This test runs entirely in-process with real UDP sockets on localhost.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agent_tunnel::AgentTunnelListener;
use agent_tunnel::cert::{CaManager, extract_agent_id_from_pem};
use agent_tunnel_proto::{
    CertRenewalResult, ConnectResponse, ControlMessage, ControlStream, DomainAdvertisement, SessionStream,
};
use camino::Utf8PathBuf;
use ipnetwork::Ipv4Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

use super::common::{connect_quinn_client, generate_csr_with_cn, generate_test_key_and_csr, start_echo_server};

/// Full E2E integration test.
///
/// 1. Start TCP echo server
/// 2. Start QUIC listener (gateway, in-process)
/// 3. Connect a simulated agent (Quinn client) with mTLS
/// 4. Agent sends RouteAdvertise on control stream
/// 5. Gateway opens a proxy stream via connect_via_agent
/// 6. Agent reads ConnectRequest, connects to echo server, sends ConnectResponse::Success
/// 7. Bidirectional data flows through the full tunnel
/// 8. Verify echo response matches
#[tokio::test]
async fn quic_agent_tunnel_e2e() {
    // ── 1. Setup certificates ──

    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("UTF-8 temp path");

    let ca_manager = CaManager::load_or_generate(&data_dir).expect("CA generation");

    let agent_id = Uuid::new_v4();
    let (key_pair, csr_pem) = generate_test_key_and_csr("test-agent");
    let signed = ca_manager
        .sign_agent_csr(agent_id, "test-agent", &csr_pem, Some("localhost"))
        .expect("sign agent CSR");

    // ── 2. Start TCP echo server ──

    let (echo_addr, _echo_handle) = start_echo_server().await;
    let echo_subnet: Ipv4Network = format!("{}/32", echo_addr.ip()).parse().unwrap();

    // ── 3. Start QUIC listener (gateway) ──

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (listener, handle) = AgentTunnelListener::bind(listen_addr, Arc::clone(&ca_manager), "localhost")
        .await
        .expect("bind QUIC listener");

    let server_addr = listener.local_addr();

    let (shutdown_handle, shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
    let listener_task = tokio::spawn(async move {
        use devolutions_gateway_task::Task;
        let _ = listener.run(shutdown_signal).await;
    });

    // Give listener time to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── 4. Connect simulated agent (Quinn client with mTLS) ──

    let connection = connect_quinn_client(
        &signed.ca_cert_pem,
        &signed.client_cert_pem,
        &key_pair.serialize_pem(),
        server_addr,
    )
    .await;

    // ── 5. Open control stream and send RouteAdvertise ──

    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.expect("open control stream").into();

    let route_msg = ControlMessage::route_advertise(1, vec![echo_subnet], vec![]);
    ctrl.send(&route_msg).await.expect("send RouteAdvertise");

    // Give gateway time to process.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify agent is registered.
    assert!(
        handle.registry().get(&agent_id).await.is_some(),
        "agent should be registered in the registry"
    );
    assert_eq!(handle.registry().online_count().await, 1);

    // ── 6. Gateway opens proxy stream ──

    let session_id = Uuid::new_v4();
    let target_str = echo_addr.to_string();

    let handle_clone = handle.clone();
    let target_clone = target_str.clone();
    let proxy_task = tokio::spawn(async move {
        handle_clone
            .connect_via_agent(agent_id, session_id, &target_clone)
            .await
    });

    // ── 7. Agent accepts session stream ──

    let (send, recv) = connection
        .accept_bi()
        .await
        .expect("accept session stream from gateway");
    let mut session: SessionStream<_, _> = (send, recv).into();

    let connect_msg = session.recv_request().await.expect("recv ConnectRequest");
    assert_eq!(connect_msg.session_id(), session_id);
    assert_eq!(connect_msg.target(), target_str);

    // Connect to echo server.
    let mut tcp_stream = TcpStream::connect(echo_addr).await.expect("connect to echo server");

    // Send success response.
    session
        .send_response(&ConnectResponse::success())
        .await
        .expect("send ConnectResponse::Success");

    // ── 8. Wait for proxy task to complete ──

    let tunnel_stream = tokio::time::timeout(Duration::from_secs(5), proxy_task)
        .await
        .expect("proxy task should complete in time")
        .expect("proxy task should not panic")
        .expect("connect_via_agent should succeed");

    // ── 9. Bidirectional data test ──

    let test_data = b"Hello from the Quinn E2E integration test!";
    let (mut quic_read, mut quic_write) = tokio::io::split(tunnel_stream);

    // Gateway writes test data.
    quic_write.write_all(test_data).await.expect("write to TunnelStream");

    // Agent relays: QUIC → TCP echo → QUIC.
    let (mut session_send, mut session_recv) = session.into_inner();
    let mut relay_buf = vec![0u8; test_data.len()];
    session_recv
        .read_exact(&mut relay_buf)
        .await
        .expect("read from QUIC session stream");
    assert_eq!(&relay_buf, test_data);

    // Forward to echo server.
    tcp_stream.write_all(&relay_buf).await.expect("write to echo server");

    // Read echo response.
    let mut echo_buf = vec![0u8; test_data.len()];
    tcp_stream.read_exact(&mut echo_buf).await.expect("read echo response");
    assert_eq!(&echo_buf, test_data);

    // Send echo response back through QUIC.
    session_send
        .write_all(&echo_buf)
        .await
        .expect("write echo response to QUIC");
    let _ = session_send.finish();

    // Gateway reads the echoed data.
    let mut response_buf = vec![0u8; test_data.len()];
    quic_read
        .read_exact(&mut response_buf)
        .await
        .expect("read from TunnelStream");
    assert_eq!(&response_buf, test_data, "echo response should match");

    // ── 10. Cleanup ──

    connection.close(0u32.into(), b"test done");
    shutdown_handle.signal();
    let _ = tokio::time::timeout(Duration::from_secs(2), listener_task).await;
}

/// Domain routing E2E test.
///
/// Same as above but agent advertises domain "test.local" alongside subnet.
/// Verifies domain appears in the registry.
#[tokio::test]
async fn quic_agent_tunnel_domain_routing_e2e() {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("UTF-8 temp path");

    let ca_manager = CaManager::load_or_generate(&data_dir).expect("CA generation");

    let agent_id = Uuid::new_v4();
    let (key_pair, csr_pem) = generate_test_key_and_csr("domain-agent");
    let signed = ca_manager
        .sign_agent_csr(agent_id, "domain-agent", &csr_pem, Some("localhost"))
        .expect("sign agent CSR");

    let (echo_addr, _echo_handle) = start_echo_server().await;
    let echo_subnet: Ipv4Network = format!("{}/32", echo_addr.ip()).parse().unwrap();

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (listener, handle) = AgentTunnelListener::bind(listen_addr, Arc::clone(&ca_manager), "localhost")
        .await
        .expect("bind QUIC listener");

    let server_addr = listener.local_addr();

    let (shutdown_handle, shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
    let listener_task = tokio::spawn(async move {
        use devolutions_gateway_task::Task;
        let _ = listener.run(shutdown_signal).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let connection = connect_quinn_client(
        &signed.ca_cert_pem,
        &signed.client_cert_pem,
        &key_pair.serialize_pem(),
        server_addr,
    )
    .await;

    // Send RouteAdvertise with domain.
    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.expect("open control stream").into();

    let domains = vec![DomainAdvertisement {
        domain: agent_tunnel_proto::DomainName::new("test.local"),
        auto_detected: false,
    }];
    let route_msg = ControlMessage::route_advertise(1, vec![echo_subnet], domains);
    ctrl.send(&route_msg).await.expect("send RouteAdvertise");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify agent + domain registered.
    let peer = handle
        .registry()
        .get(&agent_id)
        .await
        .expect("agent should be registered");

    let route_state = peer.route_state();
    assert_eq!(route_state.domains.len(), 1);
    assert_eq!(route_state.domains[0].domain.as_str(), "test.local");
    assert!(!route_state.domains[0].auto_detected);

    // Cleanup.
    connection.close(0u32.into(), b"test done");
    shutdown_handle.signal();
    let _ = tokio::time::timeout(Duration::from_secs(2), listener_task).await;
}

/// Certificate renewal E2E test.
///
/// Pins the security invariant introduced by #1775 review: the gateway must
/// re-sign with the agent's mTLS-authenticated identity, never the CSR
/// subject. Here the renewal CSR is deliberately filed under
/// `CN=evil-impersonator` — the renewed cert's URN SAN must still encode the
/// original `agent_id`.
#[tokio::test]
async fn cert_renewal_preserves_mtls_identity_e2e() {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("UTF-8 temp path");

    let ca_manager = CaManager::load_or_generate(&data_dir).expect("CA generation");

    let agent_id = Uuid::new_v4();
    let (key_pair, csr_pem) = generate_test_key_and_csr("renewal-agent");
    let signed = ca_manager
        .sign_agent_csr(agent_id, "renewal-agent", &csr_pem, Some("localhost"))
        .expect("sign initial agent CSR");

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (listener, handle) = AgentTunnelListener::bind(listen_addr, Arc::clone(&ca_manager), "localhost")
        .await
        .expect("bind QUIC listener");

    let server_addr = listener.local_addr();

    let (shutdown_handle, shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
    let listener_task = tokio::spawn(async move {
        use devolutions_gateway_task::Task;
        let _ = listener.run(shutdown_signal).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let connection = connect_quinn_client(
        &signed.ca_cert_pem,
        &signed.client_cert_pem,
        &key_pair.serialize_pem(),
        server_addr,
    )
    .await;

    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.expect("open control stream").into();

    // Agent must announce routes first so the control loop is established.
    let route_msg = ControlMessage::route_advertise(1, vec![], vec![]);
    ctrl.send(&route_msg).await.expect("send RouteAdvertise");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(handle.registry().get(&agent_id).await.is_some());

    // Build the renewal CSR with an attacker-chosen Common Name.
    let (_renewal_key, evil_csr_pem) = generate_csr_with_cn("evil-impersonator");
    let renewal_msg = ControlMessage::cert_renewal_request(evil_csr_pem);
    ctrl.send(&renewal_msg).await.expect("send CertRenewalRequest");

    let response = tokio::time::timeout(Duration::from_secs(5), ctrl.recv())
        .await
        .expect("renewal response within timeout")
        .expect("decode renewal response");

    let renewed_pem = match response {
        ControlMessage::CertRenewalResponse {
            result:
                CertRenewalResult::Success {
                    client_cert_pem,
                    gateway_ca_cert_pem,
                },
            ..
        } => {
            assert_eq!(
                gateway_ca_cert_pem, signed.ca_cert_pem,
                "renewal must echo back the same CA cert"
            );
            client_cert_pem
        }
        other => panic!("expected CertRenewalResponse::Success, got {other:?}"),
    };

    let renewed_agent_id = extract_agent_id_from_pem(&renewed_pem).expect("renewed cert has urn:uuid SAN");
    assert_eq!(
        renewed_agent_id, agent_id,
        "renewed cert must encode the mTLS-authenticated agent_id, not the CSR subject"
    );

    connection.close(0u32.into(), b"test done");
    shutdown_handle.signal();
    let _ = tokio::time::timeout(Duration::from_secs(2), listener_task).await;
}
