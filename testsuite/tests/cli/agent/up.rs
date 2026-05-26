//! E2E tests for `devolutions-agent up` enrollment,
//! focusing on the `--enrollment-string -` stdin path.

use base64::Engine as _;
use testsuite::cli::agent_assert_cmd;

/// Build a JWT with the given payload. The header and signature are placeholders —
/// the agent does not verify them; only the Gateway does.
fn make_jwt(payload: serde_json::Value) -> String {
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        b64.encode(header.to_string()),
        b64.encode(payload.to_string()),
        b64.encode("signature-placeholder"),
    )
}

fn sample_jwt() -> String {
    make_jwt(serde_json::json!({
        "scope": "gateway.tunnel.enroll",
        "exp": 1_999_999_999i64,
        "jti": "00000000-0000-0000-0000-000000000000",
        "jet_gw_url": "https://gateway.example.com:7171",
        "jet_agent_name": "site-a-agent",
    }))
}

/// `up --enrollment-string -` reads the JWT from stdin. The enrollment fails (no
/// real gateway), but the fact that it gets past argument parsing proves stdin
/// reading works end-to-end.
#[test]
fn up_enrollment_string_from_stdin() {
    let jwt = sample_jwt();

    let output = agent_assert_cmd()
        .args(["up", "--enrollment-string", "-"])
        .write_stdin(jwt)
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
    assert!(
        !stderr.contains("Invalid up arguments"),
        "argument parsing should succeed; stderr was: {stderr}"
    );
    assert!(
        stderr.contains("Bootstrap failed"),
        "should fail at enrollment, not parsing; stderr was: {stderr}"
    );
}

/// `up --enrollment-string -` with empty stdin must report an error about an
/// empty enrollment string.
#[test]
fn up_enrollment_string_stdin_empty_is_error() {
    let output = agent_assert_cmd()
        .args(["up", "--enrollment-string", "-"])
        .write_stdin("")
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
    assert!(
        stderr.contains("empty"),
        "error should mention empty enrollment string; stderr was: {stderr}"
    );
}

/// Enrollment against a real Gateway with a properly signed JWT.
///
/// Starts a Gateway with agent tunnel enabled, signs a JWT with the
/// matching provisioner key, and runs `devolutions-agent up` via stdin.
/// The enrollment should succeed (HTTP 200 from the Gateway).
#[tokio::test]
async fn up_enrollment_against_real_gateway() {
    use anyhow::Context as _;
    use picky::jose::jws::JwsAlg;
    use picky::jose::jwt::CheckedJwtSig;
    use picky::key::PrivateKey;
    use testsuite::cli::{agent_assert_cmd, dgw_tokio_cmd, wait_for_tcp_port};
    use testsuite::dgw_config::{AgentTunnelConfig, DgwConfig};

    // Generate a fresh provisioner key pair for this test.
    let priv_key = PrivateKey::generate_rsa(2048).expect("generate RSA key");
    let pub_key = priv_key.to_public_key().expect("derive public key");

    // Multibase-encode the SPKI DER for the gateway config (prefix 'm' = base64).
    let pub_key_der = pub_key.to_der().expect("export SPKI DER");
    let pub_key_multibase = format!("m{}", base64::engine::general_purpose::STANDARD.encode(&pub_key_der));

    let config_handle = DgwConfig::builder()
        .provisioner_public_key_base64(pub_key_multibase)
        .agent_tunnel(AgentTunnelConfig::builder().build())
        .enable_unstable(true)
        .build()
        .init()
        .expect("init gateway config");

    // Start a real Gateway.
    let mut gateway = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")
        .expect("spawn gateway");

    wait_for_tcp_port(config_handle.http_port())
        .await
        .expect("gateway HTTP port ready");

    // Sign a proper enrollment JWT with the provisioner private key.
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let jwt = CheckedJwtSig::new(
        JwsAlg::RS256,
        serde_json::json!({
            "scope": "gateway.agent.enroll",
            "nbf": now - 60,
            "exp": now + 3600,
            "jti": uuid::Uuid::new_v4(),
            "jet_gw_url": format!("http://127.0.0.1:{}", config_handle.http_port()),
            "jet_agent_name": "test-agent",
        }),
    )
    .encode(&priv_key)
    .expect("sign enrollment JWT");

    // Run the agent with --enrollment-string - (stdin).
    // Set DAGENT_CONFIG_PATH so certs are written to a temp directory.
    let agent_data_dir = tempfile::tempdir().expect("create agent temp dir");

    let output = agent_assert_cmd()
        .env("DAGENT_CONFIG_PATH", agent_data_dir.path())
        .args(["up", "--enrollment-string", "-"])
        .write_stdin(jwt)
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success();

    let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
    assert!(
        !stderr.contains("Bootstrap failed"),
        "enrollment should succeed; stderr was: {stderr}"
    );

    gateway.kill().await.ok();
}
