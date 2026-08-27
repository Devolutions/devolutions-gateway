use std::time::Duration;

use anyhow::Context as _;
use rstest::rstest;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle};
use tokio::process::Child;

#[rstest]
#[case::self_signed_correct_thumb(true, true, TlsOutcome::Succeeded)]
#[case::self_signed_wrong_thumb(true, false, TlsOutcome::Failed)]
#[case::self_signed_no_thumb(false, false, TlsOutcome::Failed)]
#[tokio::test]
async fn test(
    #[case] include_thumbprint: bool,
    #[case] correct_thumbprint: bool,
    #[case] expected_outcome: TlsOutcome,
) -> anyhow::Result<()> {
    let tls_port = start_dummy_tls_server().await?;
    let (config_handle, mut process) = start_gateway().await?;

    let token = token::build(tls_port, include_thumbprint, correct_thumbprint);
    let stdout = process.stdout.take().unwrap();

    let connect_fut = websocket_connect(config_handle.http_port(), &token, token::SESSION_ID);
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

async fn start_gateway() -> anyhow::Result<(DgwConfigHandle, Child)> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .verbosity_profile(testsuite::dgw_config::VerbosityProfile::DEBUG)
        .build()
        .init()
        .context("init config")?;

    // Start a Devolutions Gateway instance.
    let process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("failed to start Devolutions Gateway")?;

    // Wait until the gateway is accepting connections on the HTTP port.
    wait_for_tcp_port(config_handle.http_port()).await?;

    Ok((config_handle, process))
}

/// Perform a WebSocket connection on the /jet/fwd/tls endpoint.
async fn websocket_connect(port: u16, token: &str, session_id: &str) -> anyhow::Result<()> {
    let url = format!("ws://127.0.0.1:{port}/jet/fwd/tls/{session_id}?token={token}");

    // Try to connect with a timeout.
    let (_ws_stream, response) = tokio::time::timeout(Duration::from_secs(5), tokio_tungstenite::connect_async(url))
        .await
        .context("timeout")?
        .context("websocket connection")?;

    println!("WebSocket connected successfully: {response:?}");

    // Give the server a moment to perform the connection with the remote server.
    tokio::time::sleep(Duration::from_secs(5)).await;

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
            eprintln!("{logs}");
            return Ok(TlsOutcome::Failed);
        } else if logs.contains("WebSocket-TLS forwarding") {
            return Ok(TlsOutcome::Succeeded);
        }
    }
}

/// Starts a dummy TLS server and returns its port.
async fn start_dummy_tls_server() -> anyhow::Result<u16> {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::crypto::ring::default_provider;
    use tokio_rustls::rustls::pki_types::pem::PemObject as _;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // Install the ring crypto provider if not already installed.
    let _ = default_provider().install_default();

    let cert_pem = tls::CERT_PEM;
    let key_pem = tls::KEY_PEM;

    // Parse certificate.
    let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes()).context("parse certificate")?;

    // Parse private key.
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("parse private key DER")?;

    // Build TLS config.
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("build TLS config")?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Bind to an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").await.context("bind")?;
    let port = listener.local_addr().context("local_addr")?.port();

    // We spawn-and-forget the task; the async runtime is dropped at the end of
    // the test, including all the spawned futures.
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };

            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    // Send a simple response and close.
                    let _ = tls_stream.write_all(b"Hello from dummy TLS server\n").await;
                    let _ = tls_stream.shutdown().await;
                }
            });
        }
    });

    Ok(port)
}

mod tls {
    pub(super) use testsuite::tls_fixtures::{CERT_PEM, KEY_PEM};

    /// SHA-256 thumbprint of the certificate.
    pub(super) const CERT_THUMBPRINT: &str = "bce13f257b9d856404c51b46f2420eff6d01b3a4c99fe3d0e11e4517c2291b70";
}

mod token {
    use base64::prelude::*;

    pub(super) const SESSION_ID: &str = "897fd399-540c-4be3-84a1-47c73f68c7a4";

    /// Build a JWT token for TLS anchoring tests.
    pub(super) fn build(port: u16, include_thumbprint: bool, correct_thumbprint: bool) -> String {
        /// Static JWT header: {"alg":"RS256","typ":"JWT","cty":"ASSOCIATION"}
        const HEADER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0";

        /// Static dummy signature.
        const SIGNATURE: &str = "ZHVtbXlfc2lnbmF0dXJl";

        /// A wrong thumbprint for testing.
        const WRONG_THUMBPRINT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

        let thumbprint_field = if include_thumbprint {
            let thumb = if correct_thumbprint {
                super::tls::CERT_THUMBPRINT
            } else {
                WRONG_THUMBPRINT
            };
            format!(r#""cert_thumb256":"{thumb}","#)
        } else {
            String::new()
        };

        let body_json = format!(
            r#"{{{thumbprint_field}"dst_hst":"127.0.0.1:{port}","exp":9999999999,"jet_aid":"{SESSION_ID}","jet_ap":"unknown","jet_cm":"fwd","jet_rec":"none","jti":"00000000-0000-0000-0000-000000000000","nbf":0}}"#
        );

        let body = BASE64_URL_SAFE_NO_PAD.encode(body_json.as_bytes());

        format!("{HEADER}.{body}.{SIGNATURE}")
    }
}
