//! Integration test for the QUIC agent tunnel.
//!
//! Verifies the full data path:
//!   TCP echo server ← Agent (simulated quiche client) ← QUIC ← Gateway listener ← QuicStream
//!
//! This test runs entirely in-process with real UDP sockets on localhost.

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agent_tunnel_proto::{ConnectMessage, ConnectResponse, ControlMessage};
use camino::Utf8PathBuf;
use ipnetwork::Ipv4Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use uuid::Uuid;

use super::cert::CaManager;
use super::listener::AgentTunnelListener;

const ALPN_PROTOCOL: &[u8] = b"devolutions-agent-tunnel";
const MAX_DATAGRAM_SIZE: usize = 1350;

/// Start a TCP echo server that echoes back whatever it receives.
/// Returns the server address and a join handle.
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

/// Drive the quiche connection: send all pending data over UDP.
async fn flush_quiche(conn: &mut quiche::Connection, socket: &UdpSocket, peer_addr: SocketAddr) {
    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut buf) {
            Ok((len, send_info)) => {
                let _ = socket.send_to(&buf[..len], send_info.to).await;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                eprintln!("quiche send error: {e}");
                break;
            }
        }
    }
    let _ = peer_addr; // Used for clarity in caller.
}

/// Receive UDP data and feed it to the quiche connection.
async fn recv_quiche(conn: &mut quiche::Connection, socket: &UdpSocket, timeout: Duration) -> bool {
    let mut buf = vec![0u8; 65535];

    let result = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;
    match result {
        Ok(Ok((len, from))) => {
            let local = socket.local_addr().unwrap();
            let recv_info = quiche::RecvInfo { from, to: local };
            match conn.recv(&mut buf[..len], recv_info) {
                Ok(_) => true,
                Err(e) => {
                    eprintln!("quiche recv error: {e}");
                    false
                }
            }
        }
        Ok(Err(e)) => {
            eprintln!("UDP recv error: {e}");
            false
        }
        Err(_) => false, // timeout
    }
}

/// Drive the QUIC handshake to completion.
async fn complete_handshake(conn: &mut quiche::Connection, socket: &UdpSocket, peer_addr: SocketAddr) {
    for _ in 0..50 {
        flush_quiche(conn, socket, peer_addr).await;
        if conn.is_established() {
            return;
        }
        recv_quiche(conn, socket, Duration::from_millis(500)).await;
        flush_quiche(conn, socket, peer_addr).await;
    }
    panic!("QUIC handshake did not complete in time");
}

/// Send a length-prefixed bincode message on a QUIC stream.
fn send_message<T: serde::Serialize>(conn: &mut quiche::Connection, stream_id: u64, msg: &T) {
    let payload = bincode::serialize(msg).unwrap();
    let len = (payload.len() as u32).to_be_bytes();
    let mut data = Vec::with_capacity(4 + payload.len());
    data.extend_from_slice(&len);
    data.extend_from_slice(&payload);
    conn.stream_send(stream_id, &data, false).unwrap();
}

/// Try to read a length-prefixed bincode message from accumulated stream data.
fn try_decode_message<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Option<(T, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let msg_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + msg_len {
        return None;
    }
    let msg: T = bincode::deserialize(&buf[4..4 + msg_len]).ok()?;
    Some((msg, 4 + msg_len))
}

/// Full E2E integration test.
///
/// 1. Start TCP echo server
/// 2. Start QUIC listener (gateway)
/// 3. Connect a simulated agent (quiche client) with mTLS
/// 4. Agent sends RouteAdvertise
/// 5. Gateway opens a proxy stream via connect_via_agent
/// 6. Agent reads ConnectMessage, connects to echo server, sends ConnectResponse::Success
/// 7. Gateway writes data through QuicStream
/// 8. Verify echo response arrives back through the tunnel
#[tokio::test]
async fn quic_agent_tunnel_e2e() {
    // ── 1. Setup certificates ──────────────────────────────────────────────
    let temp_dir = std::env::temp_dir().join(format!("dgw-e2e-{}", Uuid::new_v4()));
    let data_dir = Utf8PathBuf::from_path_buf(temp_dir.clone()).expect("UTF-8 temp path");

    let ca_manager = Arc::new(CaManager::load_or_generate(&data_dir).expect("CA generation should succeed"));

    let agent_id = Uuid::new_v4();
    let cert_bundle = ca_manager
        .issue_agent_certificate(agent_id, "test-agent")
        .expect("issue agent cert");

    // Write agent certs to temp files (quiche needs file paths).
    let agent_cert_path = data_dir.join("agent-cert.pem");
    let agent_key_path = data_dir.join("agent-key.pem");
    let ca_cert_path = ca_manager.ca_cert_path();

    std::fs::write(agent_cert_path.as_str(), &cert_bundle.client_cert_pem).unwrap();
    std::fs::write(agent_key_path.as_str(), &cert_bundle.client_key_pem).unwrap();

    // ── 2. Start TCP echo server ───────────────────────────────────────────
    let (echo_addr, _echo_handle) = start_echo_server().await;
    let echo_subnet: Ipv4Network = format!("{}/32", echo_addr.ip()).parse().unwrap();

    // ── 3. Start QUIC listener ─────────────────────────────────────────────
    // Bind a temporary UDP socket to find a free port, then release it.
    let temp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_port = temp_socket.local_addr().unwrap().port();
    drop(temp_socket);

    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();

    let (listener, handle) = AgentTunnelListener::bind(server_addr, Arc::clone(&ca_manager), "localhost")
        .await
        .expect("bind QUIC listener to known port");

    // Spawn the listener as a background task.
    let (shutdown_handle, shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();
    let listener_task = tokio::spawn(async move {
        use devolutions_gateway_task::Task;
        let _ = listener.run(shutdown_signal).await;
    });

    // Give the listener a moment to be ready.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── 4. Create simulated agent (quiche client) ──────────────────────────
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_local = client_socket.local_addr().unwrap();

    let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("quiche config");
    client_config
        .load_cert_chain_from_pem_file(agent_cert_path.as_str())
        .expect("load agent cert");
    client_config
        .load_priv_key_from_pem_file(agent_key_path.as_str())
        .expect("load agent key");
    client_config
        .load_verify_locations_from_file(ca_cert_path.as_str())
        .expect("load CA cert");
    client_config.verify_peer(true);
    client_config
        .set_application_protos(&[ALPN_PROTOCOL])
        .expect("set ALPN");
    client_config.set_max_idle_timeout(30_000);
    client_config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    client_config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    client_config.set_initial_max_data(10_000_000);
    client_config.set_initial_max_stream_data_bidi_local(1_000_000);
    client_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    client_config.set_initial_max_streams_bidi(100);

    let mut scid = vec![0u8; quiche::MAX_CONN_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);
    let scid = quiche::ConnectionId::from_vec(scid);

    let mut conn = quiche::connect(Some("localhost"), &scid, client_local, server_addr, &mut client_config)
        .expect("quiche connect");

    // ── 5. Complete mTLS handshake ─────────────────────────────────────────
    complete_handshake(&mut conn, &client_socket, server_addr).await;
    assert!(conn.is_established(), "QUIC connection should be established");

    // ── 6. Send RouteAdvertise ─────────────────────────────────────────────
    let route_msg = ControlMessage::route_advertise(1, vec![echo_subnet]);
    send_message(&mut conn, 0, &route_msg);
    flush_quiche(&mut conn, &client_socket, server_addr).await;

    // Give the gateway a moment to process the route advertisement.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Drain any responses.
    recv_quiche(&mut conn, &client_socket, Duration::from_millis(100)).await;
    flush_quiche(&mut conn, &client_socket, server_addr).await;

    // Verify the agent is registered in the registry.
    assert!(
        handle.registry().get(&agent_id).is_some(),
        "agent should be registered in the registry"
    );
    assert_eq!(handle.registry().online_count(), 1);

    // ── 7. Gateway opens proxy stream via connect_via_agent ────────────────
    let session_id = Uuid::new_v4();
    let target_str = format!("{}", echo_addr);

    // Spawn connect_via_agent as a background task (it will block until the agent responds).
    let handle_clone = handle.clone();
    let target_str_clone = target_str.clone();
    let proxy_task = tokio::spawn(async move {
        handle_clone
            .connect_via_agent(agent_id, session_id, &target_str_clone)
            .await
    });

    // Give the gateway time to send the ConnectMessage.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── 8. Agent receives and processes proxy request ──────────────────────
    // The agent needs to:
    // a. Receive ConnectMessage on a new server-initiated stream
    // b. Connect to the target
    // c. Send ConnectResponse::Success

    // Pump the connection to receive the ConnectMessage.
    let mut stream_buf: Vec<u8> = Vec::new();
    let mut proxy_stream_id: Option<u64> = None;

    for _ in 0..20 {
        recv_quiche(&mut conn, &client_socket, Duration::from_millis(200)).await;
        flush_quiche(&mut conn, &client_socket, server_addr).await;

        // Check for readable streams (skip stream 0 which is control).
        for stream_id in conn.readable() {
            if stream_id == 0 {
                // Drain control stream responses.
                let mut discard = vec![0u8; 65535];
                let _ = conn.stream_recv(stream_id, &mut discard);
                continue;
            }

            let mut buf = vec![0u8; 65535];
            if let Ok((len, _fin)) = conn.stream_recv(stream_id, &mut buf) {
                stream_buf.extend_from_slice(&buf[..len]);
                proxy_stream_id = Some(stream_id);
            }
        }

        if proxy_stream_id.is_some() && stream_buf.len() >= 4 {
            let msg_len_check =
                u32::from_be_bytes([stream_buf[0], stream_buf[1], stream_buf[2], stream_buf[3]]) as usize;
            if stream_buf.len() >= 4 + msg_len_check {
                break;
            }
        }
    }

    let proxy_stream_id = proxy_stream_id.expect("should have received a proxy stream from gateway");

    // Decode ConnectMessage.
    let (connect_msg, consumed): (ConnectMessage, usize) =
        try_decode_message(&stream_buf).expect("decode ConnectMessage");
    assert_eq!(connect_msg.session_id, session_id);
    assert_eq!(connect_msg.target, target_str);
    stream_buf.drain(..consumed);

    // Connect to the echo server.
    let mut target_tcp = TcpStream::connect(echo_addr).await.expect("connect to echo server");

    // Send ConnectResponse::Success.
    let response = ConnectResponse::success();
    send_message(&mut conn, proxy_stream_id, &response);
    flush_quiche(&mut conn, &client_socket, server_addr).await;

    // Give the gateway time to process the response.
    tokio::time::sleep(Duration::from_millis(200)).await;
    recv_quiche(&mut conn, &client_socket, Duration::from_millis(100)).await;
    flush_quiche(&mut conn, &client_socket, server_addr).await;

    // ── 9. Verify proxy_task completed successfully ────────────────────────
    let quic_stream = tokio::time::timeout(Duration::from_secs(5), proxy_task)
        .await
        .expect("proxy task should complete in time")
        .expect("proxy task should not panic")
        .expect("connect_via_agent should succeed");

    // ── 10. Bidirectional data test through the full tunnel ────────────────
    // Gateway writes to QuicStream → QUIC → Agent → TCP → Echo Server → TCP → Agent → QUIC → Gateway reads

    let test_data = b"Hello from the QUIC tunnel integration test!";
    let (mut quic_read, mut quic_write) = tokio::io::split(quic_stream);

    // Write test data from the "gateway side" into the QuicStream.
    quic_write.write_all(test_data).await.expect("write to QuicStream");

    // Agent side: relay data from QUIC stream to TCP target and back.
    // We need to pump the QUIC connection to deliver the data.

    // Read data from QUIC and forward to TCP target.
    let mut data_from_quic = Vec::new();
    for _ in 0..20 {
        recv_quiche(&mut conn, &client_socket, Duration::from_millis(200)).await;
        flush_quiche(&mut conn, &client_socket, server_addr).await;

        for stream_id in conn.readable() {
            if stream_id == proxy_stream_id {
                let mut buf = vec![0u8; 65535];
                if let Ok((len, _fin)) = conn.stream_recv(stream_id, &mut buf) {
                    data_from_quic.extend_from_slice(&buf[..len]);
                }
            } else {
                // Drain other streams.
                let mut discard = vec![0u8; 65535];
                let _ = conn.stream_recv(stream_id, &mut discard);
            }
        }

        if data_from_quic.len() >= test_data.len() {
            break;
        }
    }

    assert_eq!(
        &data_from_quic[..test_data.len()],
        test_data,
        "data should arrive at the agent side"
    );

    // Forward to echo server.
    target_tcp
        .write_all(&data_from_quic[..test_data.len()])
        .await
        .expect("write to echo server");

    // Read echo response from TCP.
    let mut echo_response = vec![0u8; test_data.len()];
    target_tcp
        .read_exact(&mut echo_response)
        .await
        .expect("read echo response");
    assert_eq!(&echo_response, test_data);

    // Send echo response back through QUIC.
    conn.stream_send(proxy_stream_id, &echo_response, false)
        .expect("send echo response on QUIC stream");
    flush_quiche(&mut conn, &client_socket, server_addr).await;

    // Give gateway time to deliver data through channels.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Read the response from the gateway-side QuicStream.
    let mut response_buf = vec![0u8; test_data.len()];
    let read_result = tokio::time::timeout(Duration::from_secs(5), quic_read.read_exact(&mut response_buf))
        .await
        .expect("should read response in time")
        .expect("read from QuicStream");

    assert_eq!(read_result, test_data.len());
    assert_eq!(&response_buf, test_data, "echo response should match original data");

    // ── 11. Cleanup ────────────────────────────────────────────────────────
    shutdown_handle.signal();
    let _ = tokio::time::timeout(Duration::from_secs(2), listener_task).await;
    let _ = std::fs::remove_dir_all(&temp_dir);

    eprintln!("E2E integration test passed!");
}
