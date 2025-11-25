use anyhow::Context as _;
use rstest::rstest;
use testsuite::cli::dgw_tokio_cmd;
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

    // Give the server a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    Ok((config_handle, process))
}

/// Perform a WebSocket connection on the /jet/fwd/tls endpoint.
async fn websocket_connect(port: u16, token: &str, session_id: &str) -> anyhow::Result<()> {
    let url = format!("ws://127.0.0.1:{port}/jet/fwd/tls/{session_id}?token={token}");

    // Try to connect with a timeout.
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
    /// Self-signed certificate for localhost (valid for 100 years).
    pub(super) const CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUPRJa8i280unV3/kW6TE2fSUw8PwwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI1MTEyNTA5NDAzMFoYDzIxMjUx
MTAxMDk0MDMwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDHpBlyRgUx/V9cQGw/eqDFc6odxB2hvnbudi67LvEj
cNIWOU79R1e/NswME4oecqT9W05n4UyxkABfm2qjODO0nDf47W0DsgbEA87qE715
RWg8AtC529CZAazqTV3gqYyRMsCuVKzPVxgWa8rhPc7E6In1uDRak0lWKQPQSBbc
34nxMOVIusZNlkAEar8/aYPr/YWvdEqkobEvXp+g9WsuMaU913ecacWDjyWDkf80
pPPtf+uet7WMysKMhzGQtpbgilT8XCo8uTsgUbK+TMWvkF9bcxAQDnJsrZRL7Jfh
ofsFfQbTIvbvpn+4J4kmHN36BTohlNL8TX1jrU3cPA7dAgMBAAGjUzBRMB0GA1Ud
DgQWBBTT+m6dyc/c3mXF3JAsZr9OqUwgWTAfBgNVHSMEGDAWgBTT+m6dyc/c3mXF
3JAsZr9OqUwgWTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBB
i/yonZY3ztaeGElzD8xkI+rJ+daJ5WzdfKnzudJllg/Ht8m7wO5SdQnMt2T44gbH
05uekc1zXnXb7fJKqs3R6DacctG0nQ3acuI+IMtTaBbbAcf3PJJlo0Pap0ypVC0R
IUiUhJGFNi4cCBOvJqsly0d3T5xqOXU1Q5j3mIwRBY68+m9btwwuZWvASRADtCyZ
RpisBzS4a6jSeHXa4iG/VhskbiZkcnfHNTw7yNJJdv125y2zQkWWF9wlLbYwWr40
x9Ba6YbssOz6epATKhvt80yclO34AzUyimssvViIUpgFEyaPhZZTw46Q/6X3ixK4
/v4eYM0cCHN0h+rynSor
-----END CERTIFICATE-----"#;

    /// Private key for the self-signed certificate.
    pub(super) const KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHpBlyRgUx/V9c
QGw/eqDFc6odxB2hvnbudi67LvEjcNIWOU79R1e/NswME4oecqT9W05n4UyxkABf
m2qjODO0nDf47W0DsgbEA87qE715RWg8AtC529CZAazqTV3gqYyRMsCuVKzPVxgW
a8rhPc7E6In1uDRak0lWKQPQSBbc34nxMOVIusZNlkAEar8/aYPr/YWvdEqkobEv
Xp+g9WsuMaU913ecacWDjyWDkf80pPPtf+uet7WMysKMhzGQtpbgilT8XCo8uTsg
UbK+TMWvkF9bcxAQDnJsrZRL7JfhofsFfQbTIvbvpn+4J4kmHN36BTohlNL8TX1j
rU3cPA7dAgMBAAECggEAKh7KK5zwTaq6atlAvWfe8anEk4EkC1MG/qq6k02FHMgZ
2wx+SNu7fKFQDaA1vNTNUJLqCOq05qWOHp3IsuURq6JmAMP/Aw+Vc9el2ScPC74E
Dt09MmlZKl77H3fxPYwoFx5RHrbIuvoSH/DgHgOPU2YIbWpOyWlXyLDgmBoNkM3N
fXYLXJONpStPHeQLhh7LcHO3CZgn6kycJyByEO2NtcchS5zITiJuwL+qR5/QIlvD
Yo7jdCjelJat38MZ9dE1us8xlIjQtsYF/acZZtcpYho+7ZpDCNcb+xF8KStKei+B
MMpWISsa+Zh9g7lPYTnG/i1dSMMT100XCEw8o4rBoQKBgQDnptz8acp7DB2wJH4L
c0xuw8IlrSl3BGUEj8H+RyFlpH3+//i6/fE9MrtF8b4FSYUp5AG4NVFGcRbwJVGW
jeL13YwIKMdXjmx8fDIylCgBB1tzBS9T/0ws3HS8avxhKvjgoXIZm6D3XDcBslrH
c9/LojT8YGI1wx7jWI2qKj8yeQKBgQDcn+kQ1QjzgIz6bAVWY3t1jr5uHHyaS+5G
ihY/mx4Mn3DURgPXZHz/HrN9rZkax0zuq9wuIlqgZ2KI37iCF49M4aZxC788LyDo
Hp0Cak3wt3g0Tj6J7SJiQe8h/6VBS4R5dRD2vhEc3xPAOf7WIFdlLYBOOvE/LmOt
N6ChkfgGhQKBgQDSiDqLRPJ7BjXtIh1T9sPeXxeR+mCXBG1yydx7ZtYZdHf2S1kZ
STX4cqT1GpGiaIEX41sUuZBWPu2j76bI98bvwRxFRhp1nsFGGfHdOf1pgfBBBtNO
udXXZ7zIiUs6XD24mcIDOAgBB9QOPLR4VP1uKsuRG1/mkKD/6jlGEANDsQKBgQDC
AoEygxQnBVFz2c/rwvnLS+Zb8AMGsGTtdPrRnjeThBX1JUi1fbGJq1bN2v27Fa2q
aEjr7NvjGGcG1C1tgQhL5Fa4LEtTwmHenSUW/aJiXwR+gpvuMDC/VRnTvPp2a9En
+XEcedGUoPq+XIGjjLctyxB8Osrw83tF1JgV3MXN/QKBgQC83B54rYDd4QmVH5nL
WLw834fgr+Z1hA6UqJIaahlD/bDwzbbJEv0pHCBxe01ywQFivqWBdVbuoy9YSeLS
KKEklzh+L0SorrYoBA5F63qx0zy05bba0ASplgDUEUNZn7oIFi7x5pVsNNaNxZpR
bQGM8UrNQvWQ+tutRmp7PM6VuQ==
-----END PRIVATE KEY-----"#;

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
