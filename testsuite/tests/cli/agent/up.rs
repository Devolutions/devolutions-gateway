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

    // Hardcoded test provisioner key (same as in devolutions-gateway/tests/token_security.rs).
    // Security is not required for these tests; we just need a valid key pair.
    const PROVISIONER_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDkrPiL/5dmGIT5
/KuC3H/jIjeLoLoddsLhAlikO5JQQo3Zs71GwT4Wd2z8WLMe0lVZu/Jr2S28p0M8
F3Lnz4IgzjocQomFgucFWWQRyD03ZE2BHfEeelFsp+/4GZaM6lKZauYlIMtjR1vD
lflgvxNTr0iaii4JR9K3IKCunCRy1HQYPcZ9waNtlG5xXtW9Uf1tLWPJpP/3I5HL
M85JPBv4r286vpeUlfQIa/NB4g5w6KZ6MfEAIU4KeEQpeLAyyYvwUzPR2uQZ4y4I
4Nj84dWYB1cMTlSGugvSgOFKYit1nwLGeA7EevVYPbILRfSMBU/+avGNJJ8HCaaq
FIyY42W9AgMBAAECggEBAImsGXcvydaNrIFUvW1rkxML5qUJfwN+HJWa9ALsWoo3
h28p5ypR7S9ZdyP1wuErgHcl0C1d80tA6BmlhGhLZeyaPCIHbQQUa0GtL7IE+9X9
bSvu+tt+iMcB1FdqEFmGOXRkB2sS82Ax9e0qvZihcOFRBkUEK/MqapIV8qctGkSG
wIE6yn5LHRls/fJU8BJeeqJmYpuWljipwTkp9hQ7SdRYFLNjwjlz/b0hjmgFs5QZ
LUNMyTHdHtXQHNsf/GayRUAKf5wzN/jru+nK6lMob2Ehfx9/RAfgaDHzy5BNFMj0
i9+sAycgIW1HpTuDvSEs3qP26NeQ82GbJzATmdAKa4ECgYEA9Vti0YG+eXJI3vdS
uXInU0i1SY4aEG397OlGMwh0yQnp2KGruLZGkTvqxG/Adj1ObDyjFH9XUhMrd0za
Nk/VJFybWafljUPcrfyPAVLQLjsBfMg3Y34sTF6QjUnhg49X2jfvy9QpC5altCtA
46/KVAGREnQJ3wMjfGGIFP8BUZsCgYEA7phYE/cYyWg7a/o8eKOFGqs11ojSqG3y
0OE7kvW2ugUuy3ex+kr19Q/8pOWEc7M1UEV8gmc11xgB70EhIFt9Jq379H0X4ahS
+mgLiPzKAdNCRPpkxwwN9HxFDgGWoYcgMplhoAmg9lWSDuE1Exy8iu5inMWuF4MT
/jG+cLnUZ4cCgYAfMIXIUjDvaUrAJTp73noHSUfaWNkRW5oa4rCMzjdiUwNKCYs1
yN4BmldGr1oM7dApTDAC7AkiotM0sC1RGCblH2yUIha5NXY5G9Dl/yv9pHyU6zK3
UBO7hY3kmA611aP6VoACLi8ljPn1hEYUa4VR1n0llmCm29RH/HH7EUuOnwKBgExH
OCFp5eq+AAFNRvfqjysvgU7M/0wJmo9c8obRN1HRRlyWL7gtLuTh74toNSgoKus2
y8+E35mce0HaOJT3qtMq3FoVhAUIoz6a9NUevBZJS+5xfraEDBIViJ4ps9aANLL4
hlV7vpICWWeYaDdsAHsKK0yjhjzOEx45GQFA578RAoGBAOB42BG53tL0G9pPeJPt
S2LM6vQKeYx+gXTk6F335UTiiC8t0CgNNQUkW105P/SdpCTTKojAsOPMKOF7z4mL
lj/bWmNq7xu9uVOcBKrboVFGO/n6FXyWZxHPOTdjTkpe8kvvmSwl2iaTNllvSr46
Z/fDKMxHxeXla54kfV+HiGkH
-----END PRIVATE KEY-----"#;

    // Precomputed SPKI DER of PROVISIONER_KEY_PEM, multibase-encoded (prefix 'm' = base64).
    const PROVISIONER_PUB_KEY_MULTIBASE: &str = "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Kz4i/+XZhiE+fyrgtx/4yI3i6C6HXbC4QJYpDuSUEKN2bO9RsE+Fnds/FizHtJVWbvya9ktvKdDPBdy58+CIM46HEKJhYLnBVlkEcg9N2RNgR3xHnpRbKfv+BmWjOpSmWrmJSDLY0dbw5X5YL8TU69ImoouCUfStyCgrpwkctR0GD3GfcGjbZRucV7VvVH9bS1jyaT/9yORyzPOSTwb+K9vOr6XlJX0CGvzQeIOcOimejHxACFOCnhEKXiwMsmL8FMz0drkGeMuCODY/OHVmAdXDE5UhroL0oDhSmIrdZ8CxngOxHr1WD2yC0X0jAVP/mrxjSSfBwmmqhSMmONlvQIDAQAB";

    let priv_key = PrivateKey::from_pem_str(PROVISIONER_KEY_PEM).expect("parse test provisioner key");

    let config_handle = DgwConfig::builder()
        .provisioner_public_key_base64(PROVISIONER_PUB_KEY_MULTIBASE.to_owned())
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
