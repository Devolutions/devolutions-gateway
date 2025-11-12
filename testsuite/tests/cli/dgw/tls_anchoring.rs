use anyhow::Context as _;
use rstest::rstest;
use testsuite::cli::dgw_tokio_cmd;
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle};
use tokio::process::Child;

async fn start_gateway() -> anyhow::Result<(DgwConfigHandle, Child)> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    // Start JMUX server that will accept JMUX connections.
    let process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("failed to start Devolutions Gateway")?;

    // Give the server a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    Ok((config_handle, process))
}

/// Perform a WebSocket connection on the /jet/fwd/tcp endpoint.
async fn websocket_connect(port: u16, token: &str, session_id: &str) -> anyhow::Result<()> {
    let url = format!("ws://127.0.0.1:{port}/jet/fwd/tls/{session_id}?token={token}");

    // Try to connect with a timeout
    let (_ws_stream, response) =
        tokio::time::timeout(std::time::Duration::from_secs(5), tokio_tungstenite::connect_async(url))
            .await
            .context("timeout")?
            .context("websocket connection")?;

    println!("WebSocket connected successfully: {response:?}");

    // Give the server a moment to perform the connection with the remote server.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    Ok(())
}

#[derive(Debug, PartialEq)]
enum TlsOutcome {
    Failed,
    Succeeded,
}

async fn read_until_tls_done(mut logs: impl tokio::io::AsyncRead + Unpin) -> anyhow::Result<TlsOutcome> {
    use tokio::io::AsyncReadExt as _;

    let mut buf = Vec::new();

    loop {
        let n = logs.read_buf(&mut buf).await.context("read_buf")?;

        if n == 0 {
            anyhow::bail!("eof");
        }

        let logs = String::from_utf8_lossy(&buf);

        if logs.contains("PASTE_THIS_THUMBPRINT_IN_RDM_CONNECTION") {
            return Ok(TlsOutcome::Failed);
        } else if logs.contains("WebSocket-TLS forwarding") {
            return Ok(TlsOutcome::Succeeded);
        }
    }
}

#[rstest]
#[case::self_signed_correct_thumb(token::SELF_SIGNED_WITH_CORRECT_THUMB, TlsOutcome::Succeeded)]
#[case::self_signed_wrong_thumb(token::SELF_SIGNED_WITH_WRONG_THUMB, TlsOutcome::Failed)]
#[case::self_signed_no_thumb(token::SELF_SIGNED_NO_THUMB, TlsOutcome::Failed)]
#[case::valid_cert_no_thumb(token::VALID_CERT_NO_THUMB, TlsOutcome::Succeeded)]
#[tokio::test]
async fn test(#[case] token: &str, #[case] expected_outcome: TlsOutcome) -> anyhow::Result<()> {
    let (config_handle, mut process) = start_gateway().await?;

    let stdout = process.stdout.take().unwrap();

    let connect_fut = websocket_connect(config_handle.http_port(), token, token::SESSION_ID);
    let read_fut = read_until_tls_done(stdout);

    tokio::select! {
        res = connect_fut => {
            res.context("websocket connect")?;
            anyhow::bail!("expected read future to terminate before connect future");
        }
        res = read_fut => {
            let outcome = res.context("read")?;
            assert_eq!(outcome, expected_outcome);
        }
    }

    Ok(())
}

mod token {
    pub(super) const SESSION_ID: &str = "897fd399-540c-4be3-84a1-47c73f68c7a4";

    /// Token with correct thumbprint for self-signed.badssl.com
    pub(super) const SELF_SIGNED_WITH_CORRECT_THUMB: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0.eyJjZXJ0X3RodW1iMjU2IjoiMzkxYTIyOGUyZjQ4NjA2NDQwNTkyNjU1ODEzNTAxNThmNTUyMTNkODc0YzVmYmY1NzFjZThiZTYyYmZlY2Y1NCIsImRzdF9oc3QiOiJzZWxmLXNpZ25lZC5iYWRzc2wuY29tOjQ0MyIsImV4cCI6MTc2MjkzNzI5OCwiamV0X2FpZCI6Ijg5N2ZkMzk5LTU0MGMtNGJlMy04NGExLTQ3YzczZjY4YzdhNCIsImpldF9hcCI6InVua25vd24iLCJqZXRfY20iOiJmd2QiLCJqZXRfcmVjIjoibm9uZSIsImp0aSI6IjgwYTcxN2JmLTZlMzItNGEyMi05Yjk3LTVlYzFkNzk1YjVlMSIsIm5iZiI6MTc2MjkzNjM5OH0.ZHVtbXlfc2lnbmF0dXJl";

    /// Token with wrong thumbprint for self-signed.badssl.com
    pub(super) const SELF_SIGNED_WITH_WRONG_THUMB: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0.eyJjZXJ0X3RodW1iMjU2IjoiYTkxYTIyODIyZjQ4NjA2NDQwNTkyNjU1ODExMTExNThmNTUyMTNkODc0YzVmYmY1NzFjZThiZTYzYmZlY2Y1NCIsImRzdF9oc3QiOiJzZWxmLXNpZ25lZC5iYWRzc2wuY29tOjQ0MyIsImV4cCI6MTc2MjkzODI5MywiamV0X2FpZCI6Ijg5N2ZkMzk5LTU0MGMtNGJlMy04NGExLTQ3YzczZjY4YzdhNCIsImpldF9hcCI6InVua25vd24iLCJqZXRfY20iOiJmd2QiLCJqZXRfcmVjIjoibm9uZSIsImp0aSI6IjRlMjZhNjM2LTA0MjUtNDNlMy1iMGZmLWYzZDk1ODhjZWY4YSIsIm5iZiI6MTc2MjkzNzM5M30.ZHVtbXlfc2lnbmF0dXJl";

    /// Token without thumbprint for self-signed.badssl.com
    pub(super) const SELF_SIGNED_NO_THUMB: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0.eyJkc3RfaHN0Ijoic2VsZi1zaWduZWQuYmFkc3NsLmNvbTo0NDMiLCJleHAiOjE3NjI5Mzc0ODAsImpldF9haWQiOiI4OTdmZDM5OS01NDBjLTRiZTMtODRhMS00N2M3M2Y2OGM3YTQiLCJqZXRfYXAiOiJ1bmtub3duIiwiamV0X2NtIjoiZndkIiwiamV0X3JlYyI6Im5vbmUiLCJqdGkiOiI0ODdjZThiNS1lY2ZmLTRlY2QtYWE3ZC0wNTJkNThlM2U2YjEiLCJuYmYiOjE3NjI5MzY1ODB9.ZHVtbXlfc2lnbmF0dXJl";

    /// Token without thumbprint for badssl.com (valid cert)
    pub(super) const VALID_CERT_NO_THUMB: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0.eyJkc3RfaHN0IjoiYmFkc3NsLmNvbTo0NDMiLCJleHAiOjE3NjI5Mzc1MjEsImpldF9haWQiOiI4OTdmZDM5OS01NDBjLTRiZTMtODRhMS00N2M3M2Y2OGM3YTQiLCJqZXRfYXAiOiJ1bmtub3duIiwiamV0X2NtIjoiZndkIiwiamV0X3JlYyI6Im5vbmUiLCJqdGkiOiI4YWUzMzkxNS00ZDNlLTQyYmItODBkNi0yYjQzYjIyN2QzYTQiLCJuYmYiOjE3NjI5MzY2MjF9.ZHVtbXlfc2lnbmF0dXJl";
}
