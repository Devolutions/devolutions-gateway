use base64::Engine as _;

use super::*;

#[test]
fn parse_up_command_args_uses_default_config_path() {
    let args = vec![
        "--gateway".to_owned(),
        "https://gateway.example.com:7171".to_owned(),
        "--token".to_owned(),
        "bootstrap-token".to_owned(),
        "--name".to_owned(),
        "site-a-agent".to_owned(),
        "--advertise-routes".to_owned(),
        "10.0.0.0/8,192.168.1.0/24".to_owned(),
    ];

    let parsed = parse_up_command_args(&args).expect("parse up args");

    assert_eq!(
        parsed,
        UpCommand {
            gateway_url: "https://gateway.example.com:7171".to_owned(),
            enrollment_token: "bootstrap-token".to_owned(),
            agent_name: "site-a-agent".to_owned(),
            advertise_subnets: vec!["10.0.0.0/8".to_owned(), "192.168.1.0/24".to_owned()],
            quic_endpoint_override: None,
        }
    );
}

#[test]
fn parse_up_command_args_accepts_aliases() {
    let args = vec![
        "--gateway".to_owned(),
        "https://gateway.example.com:7171".to_owned(),
        "--enrollment-token".to_owned(),
        "bootstrap-token".to_owned(),
        "--agent-name".to_owned(),
        "site-a-agent".to_owned(),
        "--advertise-subnets".to_owned(),
        "10.0.0.0/8".to_owned(),
    ];

    let parsed = parse_up_command_args(&args).expect("parse up args");

    assert_eq!(parsed.advertise_subnets, vec!["10.0.0.0/8".to_owned()]);
}

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

#[test]
fn parse_up_command_args_accepts_enrollment_string() {
    let jwt = make_jwt(serde_json::json!({
        "scope": "gateway.tunnel.enroll",
        "exp": 1_999_999_999i64,
        "jti": "00000000-0000-0000-0000-000000000000",
        "jet_gw_url": "https://gateway.example.com:7171",
        "jet_agent_name": "site-a-agent",
    }));
    let args = vec!["--enrollment-string".to_owned(), jwt.clone()];

    let parsed = parse_up_command_args(&args).expect("parse up args");

    assert_eq!(parsed.gateway_url, "https://gateway.example.com:7171");
    // The JWT itself is used as the Bearer token for /jet/tunnel/enroll.
    assert_eq!(parsed.enrollment_token, jwt);
    assert_eq!(parsed.agent_name, "site-a-agent");
    assert_eq!(parsed.quic_endpoint_override, None);
}

#[test]
fn parse_up_command_args_jwt_quic_endpoint_claim() {
    let jwt = make_jwt(serde_json::json!({
        "scope": "gateway.tunnel.enroll",
        "exp": 1_999_999_999i64,
        "jti": "00000000-0000-0000-0000-000000000000",
        "jet_gw_url": "https://gateway.example.com:7171",
        "jet_agent_name": "site-a-agent",
        "jet_quic_endpoint": "gateway.example.com:7172",
    }));
    let args = vec!["--enrollment-string".to_owned(), jwt];

    let parsed = parse_up_command_args(&args).expect("parse up args");

    assert_eq!(
        parsed.quic_endpoint_override,
        Some("gateway.example.com:7172".to_owned())
    );
}

#[test]
fn parse_up_command_args_cli_quic_endpoint_wins_over_jwt() {
    let jwt = make_jwt(serde_json::json!({
        "scope": "gateway.tunnel.enroll",
        "exp": 1_999_999_999i64,
        "jti": "00000000-0000-0000-0000-000000000000",
        "jet_gw_url": "https://gateway.example.com:7171",
        "jet_agent_name": "site-a-agent",
        "jet_quic_endpoint": "from-jwt.example.com:7172",
    }));
    let args = vec![
        "--enrollment-string".to_owned(),
        jwt,
        "--quic-endpoint".to_owned(),
        "from-cli.example.com:7172".to_owned(),
    ];

    let parsed = parse_up_command_args(&args).expect("parse up args");

    assert_eq!(
        parsed.quic_endpoint_override,
        Some("from-cli.example.com:7172".to_owned())
    );
}
