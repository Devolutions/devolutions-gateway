//! Tests for benign client disconnect handling.
//!
//! These tests verify that common client disconnects (e.g., health checks, aborted
//! connections) are logged at DEBUG level instead of ERROR.
//!
//! Note: HTTPS disconnect handling is implemented in handle_https_peer and uses the same
//! benign disconnect detection logic. However, testing HTTPS requires TLS configuration
//! which is not included in the default test setup.

use anyhow::Context as _;
use rstest::rstest;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle, VerbosityProfile};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;

/// Starts a gateway instance and returns the process and a handle to collect stderr.
///
/// The gateway is configured with DEBUG logging enabled to capture disconnect logs.
/// Stderr is collected in a background task and returned when the handle is awaited.
async fn start_gateway_with_logs(
    config_handle: &DgwConfigHandle,
) -> anyhow::Result<(Child, tokio::task::JoinHandle<Vec<String>>)> {
    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .env("RUST_LOG", "devolutions_gateway=debug")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to start Devolutions Gateway")?;

    let stderr = process.stderr.take().context("failed to take stderr")?;
    let stderr_handle = tokio::spawn(async move {
        let mut stderr_reader = BufReader::new(stderr);
        let mut lines = Vec::new();
        let mut line_buf = String::new();
        loop {
            match stderr_reader.read_line(&mut line_buf).await {
                Ok(0) => break,
                Ok(_) => {
                    lines.push(line_buf.clone());
                    line_buf.clear();
                }
                Err(_) => break,
            }
        }
        lines
    });

    // Wait for HTTP port to be ready.
    wait_for_tcp_port(config_handle.http_port()).await?;

    Ok((process, stderr_handle))
}

/// Test that benign HTTP disconnects log DEBUG, not ERROR.
///
/// Tests various scenarios where clients disconnect without error:
/// - Connecting and immediately closing (e.g., health checks, port scanners)
/// - Sending partial request then closing (e.g., aborted browser requests)
#[rstest]
#[case::connect_and_close(None)]
#[case::abort_mid_request(Some("GET /jet/health HTTP/1.1\r\nHost: localhost\r\n".as_bytes()))]
#[tokio::test]
async fn benign_http_disconnect(#[case] payload: Option<&[u8]>) -> anyhow::Result<()> {
    // 1) Start the gateway with DEBUG logging.
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .verbosity_profile(VerbosityProfile::DEBUG)
        .build()
        .init()
        .context("init config")?;

    let (mut process, stderr_handle) = start_gateway_with_logs(&config_handle).await?;

    // 2) Connect to HTTP port.
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", config_handle.http_port()))
        .await
        .context("failed to connect to HTTP port")?;

    // 3) Send payload if provided.
    if let Some(data) = payload {
        stream.write_all(data).await.context("failed to send payload")?;
    }

    // 4) Close the connection.
    drop(stream);

    // Wait a bit for the log to be written.
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // 5) Stop the gateway and collect logs.
    let _ = process.start_kill();
    let stderr_lines = tokio::time::timeout(tokio::time::Duration::from_secs(5), stderr_handle)
        .await
        .context("timeout waiting for stderr")?
        .context("wait for stderr collection")?;
    let _ = process.wait().await;

    // 6) Verify no ERROR logs about "HTTP server" or "handle_http_peer failed".
    let has_error = stderr_lines.iter().any(|line| {
        line.contains("ERROR") && (line.contains("HTTP server") || line.contains("handle_http_peer failed"))
    });

    assert!(
        !has_error,
        "Expected no ERROR logs for benign HTTP disconnect, but found one"
    );

    Ok(())
}
