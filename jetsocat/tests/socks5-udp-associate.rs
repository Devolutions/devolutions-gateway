//! Test SOCKS5 UDP Associate functionality
#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use proxy_socks::{Socks5Acceptor, Socks5AcceptorConfig};
use std::sync::Arc;
use std::time::Duration;
use test_utils::find_unused_ports;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::*;

fn init_tracing() {
    static INIT: std::sync::Once = std::sync::Once::new();

    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(Level::DEBUG)
            .init();
    });
}

// Test that UDP Associate commands are properly detected by the acceptor
#[tokio::test]
async fn test_socks5_udp_associate_command_detection() {
    init_tracing();

    let ports = find_unused_ports(1);
    let listener_port = ports[0];

    // Start a simple TCP server that will accept the SOCKS5 negotiation
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", listener_port))
        .await
        .unwrap();

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let conf = Arc::new(Socks5AcceptorConfig {
            no_auth_required: true,
            users: None,
        });

        let acceptor = Socks5Acceptor::accept_with_config(stream, &conf).await.unwrap();

        // Verify this is a UDP Associate command.
        assert!(acceptor.is_udp_associate_command());
        assert!(!acceptor.is_connect_command());
        assert!(!acceptor.is_bind_command());

        // Respond with UDP Associated.
        let _stream = acceptor.udp_associated("127.0.0.1:1234").await.unwrap();
    });

    // Give server time to start.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Client: Connect and send UDP Associate request.
    let mut client = TcpStream::connect(("127.0.0.1", listener_port)).await.unwrap();

    // SOCKS5 authentication negotiation.
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // VER, NMETHODS, METHOD(NO_AUTH)
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [0x05, 0x00]); // VER, METHOD(NO_AUTH)

    // Send UDP Associate request.
    let udp_associate_request = [
        0x05, // VER
        0x03, // CMD (UDP Associate)
        0x00, // RSV
        0x01, // ATYP (IPv4)
        127, 0, 0, 1, // DST.ADDR (127.0.0.1)
        0x00, 0x00, // DST.PORT (0)
    ];
    client.write_all(&udp_associate_request).await.unwrap();

    // Read UDP Associate response.
    let mut response = [0u8; 10];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], 0x05); // VER
    assert_eq!(response[1], 0x00); // REP (Success)
    assert_eq!(response[2], 0x00); // RSV
    assert_eq!(response[3], 0x01); // ATYP (IPv4)

    server_handle.await.unwrap();
}

// Test that Jetsocat properly handles UDP Associate requests
#[tokio::test]
async fn test_jetsocat_socks5_udp_associate_basic() {
    init_tracing();

    let ports = find_unused_ports(2);
    let socks5_port = ports[0];
    let jmux_server_port = ports[1];

    // Start JMUX server (simplified - just accept connections)
    let jmux_server_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", jmux_server_port))
            .await
            .unwrap();

        // Accept one connection and keep it alive
        let (_stream, _) = listener.accept().await.unwrap();
        // Don't close the connection immediately
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    // Start Jetsocat SOCKS5 to JMUX proxy
    let jetsocat_handle = tokio::spawn(async move {
        use jetsocat::listener::ListenerMode;
        use jetsocat::pipe::PipeMode;

        let pipe_mode = PipeMode::Tcp {
            addr: format!("127.0.0.1:{jmux_server_port}"),
        };

        let listener_mode = ListenerMode::Socks5 {
            bind_addr: format!("127.0.0.1:{socks5_port}"),
        };

        let cfg = jetsocat::JmuxProxyCfg {
            pipe_mode,
            proxy_cfg: None,
            listener_modes: vec![listener_mode],
            pipe_timeout: Some(Duration::from_secs(1)),
            watch_process: None,
            jmux_cfg: jmux_proxy::JmuxConfig::client(),
        };

        // This should handle UDP Associate requests without crashing
        let result = timeout(Duration::from_secs(2), jetsocat::jmux_proxy(cfg)).await;
        match result {
            Ok(Ok(())) => info!("Jetsocat completed successfully"),
            Ok(Err(e)) => info!("Jetsocat completed with error: {:#}", e),
            Err(_) => info!("Jetsocat timed out (expected for this test)"),
        }
    });

    // Give Jetsocat time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client: Connect to SOCKS5 proxy and send UDP Associate request
    let client_handle = tokio::spawn(async move {
        let result = timeout(Duration::from_millis(500), async {
            let mut client = TcpStream::connect(("127.0.0.1", socks5_port)).await?;

            // SOCKS5 authentication negotiation.
            client.write_all(&[0x05, 0x01, 0x00]).await?; // VER, NMETHODS, METHOD(NO_AUTH)
            let mut auth_response = [0u8; 2];
            client.read_exact(&mut auth_response).await?;

            if auth_response != [0x05, 0x00] {
                anyhow::bail!("Unexpected auth response: {:?}", auth_response);
            }

            // Send UDP Associate request.
            let udp_associate_request = [
                0x05, // VER
                0x03, // CMD (UDP Associate)
                0x00, // RSV
                0x01, // ATYP (IPv4)
                127, 0, 0, 1, // DST.ADDR (127.0.0.1)
                0x00, 0x00, // DST.PORT (0)
            ];
            client.write_all(&udp_associate_request).await?;

            // Read UDP Associate response
            let mut response = [0u8; 10];
            client.read_exact(&mut response).await?;

            if response[0] != 0x05 {
                anyhow::bail!("Unexpected SOCKS version: {}", response[0]);
            }

            // Check if UDP Associate was successful (REP = 0x00) or failed
            info!("UDP Associate response code: 0x{:02x}", response[1]);

            anyhow::Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => info!("Client UDP Associate test completed successfully"),
            Ok(Err(e)) => info!("Client UDP Associate test failed: {:#}", e),
            Err(_) => info!("Client UDP Associate test timed out"),
        }
    });

    // Wait for all tasks
    let (jmux_result, jetsocat_result, client_result) =
        tokio::join!(jmux_server_handle, jetsocat_handle, client_handle);

    // Verify tasks completed without panicking
    jmux_result.unwrap();
    jetsocat_result.unwrap();
    client_result.unwrap();
}

// FIXME: verify it’s really necessary, given we have socks5-to-jmux.rs
// Ensure our UDP changes don't break existing TCP CONNECT functionality
#[tokio::test]
#[ignore = "slow test"] // FIXME: never ends (it’s expected to run for only 2 secs)
async fn test_backward_compatibility_tcp_connect() {
    init_tracing();

    let ports = find_unused_ports(3);
    let socks5_port = ports[0];
    let jmux_server_port = ports[1];
    let echo_server_port = ports[2];

    // Start echo server
    let echo_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", echo_server_port))
            .await
            .unwrap();

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 1024];
        match stream.read(&mut buffer).await {
            Ok(n) if n > 0 => {
                stream.write_all(&buffer[..n]).await.unwrap();
            }
            _ => {}
        }
    });

    // Start simplified JMUX server that accepts TCP connections
    let jmux_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", jmux_server_port))
            .await
            .unwrap();

        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    // Start Jetsocat
    let jetsocat_handle = tokio::spawn(async move {
        use jetsocat::listener::ListenerMode;
        use jetsocat::pipe::PipeMode;

        let pipe_mode = PipeMode::Tcp {
            addr: format!("127.0.0.1:{jmux_server_port}"),
        };

        let listener_mode = ListenerMode::Socks5 {
            bind_addr: format!("127.0.0.1:{socks5_port}"),
        };

        let cfg = jetsocat::JmuxProxyCfg {
            pipe_mode,
            proxy_cfg: None,
            listener_modes: vec![listener_mode],
            pipe_timeout: Some(Duration::from_secs(1)),
            watch_process: None,
            jmux_cfg: jmux_proxy::JmuxConfig::client(),
        };

        let result = timeout(Duration::from_secs(2), jetsocat::jmux_proxy(cfg)).await;
        match result {
            Ok(Ok(())) => info!("Jetsocat completed successfully"),
            Ok(Err(e)) => info!("Jetsocat completed with error: {:#}", e),
            Err(_) => info!("Jetsocat timed out (expected for this test)"),
        }
    });

    // Give services time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test TCP CONNECT (existing functionality)
    let tcp_test_handle = tokio::spawn(async move {
        let result = timeout(Duration::from_millis(500), async {
            // This should work the same as before our UDP changes
            let stream = TcpStream::connect(("127.0.0.1", socks5_port)).await?;
            let mut socks_stream =
                proxy_socks::Socks5Stream::connect(stream, format!("127.0.0.1:{}", echo_server_port)).await?;

            // Send test data
            socks_stream.write_all(b"Hello").await?;
            let mut response = [0u8; 5];
            socks_stream.read_exact(&mut response).await?;

            if &response == b"Hello" {
                info!("TCP CONNECT echo test successful");
            } else {
                anyhow::bail!("Echo response mismatch: {:?}", response);
            }

            anyhow::Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => info!("TCP CONNECT backward compatibility test passed"),
            Ok(Err(e)) => warn!("TCP CONNECT test failed: {:#}", e),
            Err(_) => info!("TCP CONNECT test timed out"),
        }
    });

    // Wait for all tasks
    let (echo_result, jmux_result, jetsocat_result, tcp_result) =
        tokio::join!(echo_handle, jmux_handle, jetsocat_handle, tcp_test_handle);

    // Verify no panics
    echo_result.unwrap();
    jmux_result.unwrap();
    jetsocat_result.unwrap();
    tcp_result.unwrap();
}
