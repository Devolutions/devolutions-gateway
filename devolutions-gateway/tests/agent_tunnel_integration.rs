#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

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
use agent_tunnel::cert::CaManager;
use agent_tunnel_proto::{ConnectResponse, ControlMessage, ControlStream, DomainAdvertisement, SessionStream};
use camino::Utf8PathBuf;
use ipnetwork::Ipv4Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// Start a TCP echo server that echoes back whatever it receives.
async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    (addr, handle)
}

/// Generate a key pair and CSR (same as the real agent does during enrollment).
fn generate_test_key_and_csr(agent_name: &str) -> (rcgen::KeyPair, String) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate test key pair");
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, agent_name);
    let csr = params.serialize_request(&key_pair).expect("serialize test CSR");
    let csr_pem = csr.pem().expect("CSR to PEM");
    (key_pair, csr_pem)
}

/// Create a Quinn client connection to the gateway with mTLS.
async fn connect_quinn_client(
    ca_cert_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
    server_addr: SocketAddr,
) -> quinn::Connection {
    use rustls_pemfile::{certs, private_key};

    let _ = rustls::crypto::ring::default_provider().install_default();

    // Parse client cert + key.
    let client_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        certs(&mut std::io::BufReader::new(client_cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .expect("parse client certs");
    let client_key = private_key(&mut std::io::BufReader::new(client_key_pem.as_bytes()))
        .expect("parse private key")
        .expect("no private key found");

    // Build root store with the CA cert.
    let mut roots = rustls::RootCertStore::empty();
    let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        certs(&mut std::io::BufReader::new(ca_cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .expect("parse CA certs");
    for cert in ca_certs {
        roots.add(cert).expect("add CA cert to root store");
    }

    // Build client config — skip hostname verification for test (connect by IP).
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("build verifier");

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_certs, client_key)
        .expect("client auth config");

    client_crypto.alpn_protocols = vec![agent_tunnel_proto::ALPN_PROTOCOL.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).expect("QUIC client config"),
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind addr")).expect("create endpoint");
    endpoint.set_default_client_config(client_config);

    endpoint
        .connect(server_addr, "localhost")
        .expect("initiate connection")
        .await
        .expect("QUIC handshake")
}

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
