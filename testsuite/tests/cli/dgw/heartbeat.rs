//! Heartbeat API regression tests.
//!
//! These tests verify the `/jet/heartbeat` endpoint behaviour under various
//! recording-path configurations.

use anyhow::Context as _;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle};

/// Scope token with `gateway.heartbeat.read` scope.
///
/// Token validation is disabled in tests, so the signature is fake.
/// - Header: `{"typ":"JWT","alg":"RS256"}`
/// - Payload: `{"type":"scope","jti":"...","scope":"gateway.heartbeat.read",...}`
const HEARTBEAT_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDMiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaGVhcnRiZWF0LnJlYWQifQ.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";

/// Starts a gateway instance and waits until its HTTP port is ready.
async fn start_gateway(config_handle: &DgwConfigHandle) -> anyhow::Result<tokio::process::Child> {
    let process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("failed to start Devolutions Gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    Ok(process)
}

/// Calls `GET /jet/heartbeat` and returns the parsed JSON body.
async fn get_heartbeat(http_port: u16) -> anyhow::Result<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

    let request = format!(
        "GET /jet/heartbeat HTTP/1.1\r\n\
         Host: 127.0.0.1:{http_port}\r\n\
         Authorization: Bearer {HEARTBEAT_SCOPE_TOKEN}\r\n\
         Connection: close\r\n\
         \r\n"
    );

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", http_port))
        .await
        .context("connect to gateway")?;

    stream.write_all(request.as_bytes()).await.context("send request")?;
    stream.flush().await.context("flush")?;

    // Read headers until the blank line, then read the body.
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.context("read header line")?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    let mut body = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut reader, &mut body)
        .await
        .context("read body")?;

    serde_json::from_str(&body).with_context(|| format!("parse heartbeat JSON: {body:?}"))
}

/// Regression test: when the configured recording folder does not exist yet (as is the case
/// immediately after upgrading before the gateway has had a chance to create it), the heartbeat
/// endpoint must still report disk space information.
///
/// Prior to the fix this regressed in 2026.1.1: `GetDiskFreeSpaceExW` / `statvfs` were called
/// directly on the non-existent path and failed with OS error 3 (path not found), causing
/// `recording_storage_total_space` and `recording_storage_available_space` to be absent from
/// the response.
#[tokio::test]
async fn heartbeat_reports_disk_space_when_recording_dir_not_yet_created() -> anyhow::Result<()> {
    // Configure a recording path that does not exist yet.
    let base = tempfile::tempdir().context("create tempdir for recording path")?;
    let nonexistent_recordings = base.path().join("recordings_not_created_yet");
    assert!(
        !nonexistent_recordings.exists(),
        "pre-condition: recording dir must not exist before the test"
    );

    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .recording_path(nonexistent_recordings.clone())
        .build()
        .init()
        .context("init config")?;

    let mut process = start_gateway(&config_handle).await?;

    let heartbeat = get_heartbeat(config_handle.http_port())
        .await
        .context("get heartbeat")?;

    let _ = process.start_kill();
    let _ = process.wait().await;

    // The recording folder still must not have been created by the gateway startup.
    assert!(
        !nonexistent_recordings.exists(),
        "recording dir should still not exist after gateway startup"
    );

    // Disk space must be reported even though the folder doesn't exist.
    assert!(
        !heartbeat["recording_storage_total_space"].is_null(),
        "recording_storage_total_space must be present when recording dir does not exist yet; \
         got heartbeat: {heartbeat}"
    );
    assert!(
        !heartbeat["recording_storage_available_space"].is_null(),
        "recording_storage_available_space must be present when recording dir does not exist yet; \
         got heartbeat: {heartbeat}"
    );

    Ok(())
}
