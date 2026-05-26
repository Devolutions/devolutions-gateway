//! E2E tests for `devolutions-agent up` argument parsing,
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

/// `up --enrollment-string <jwt>` (inline) should parse the JWT and proceed to
/// enrollment. Since there is no real Gateway, enrollment fails with a network
/// error — but the argument parsing stage must succeed (no "Invalid up arguments" error).
#[test]
fn up_enrollment_string_inline() {
    let jwt = sample_jwt();

    let output = agent_assert_cmd()
        .args(["up", "--enrollment-string", &jwt])
        .assert()
        .failure(); // Enrollment itself fails — no gateway.

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

/// The JWT must not appear anywhere in the process command line when the
/// stdin sentinel `-` is used.  We verify this indirectly: the only
/// arguments on the command line are `up --enrollment-string -`, so
/// `assert_cmd`'s captured stderr (which includes the error) should not
/// contain the JWT itself.
#[test]
fn up_enrollment_string_stdin_does_not_leak_jwt_in_stderr() {
    let jwt = sample_jwt();

    let output = agent_assert_cmd()
        .args(["up", "--enrollment-string", "-"])
        .write_stdin(jwt.clone())
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
    assert!(
        !stderr.contains(&jwt),
        "JWT should not appear in stderr; stderr was: {stderr}"
    );
}
