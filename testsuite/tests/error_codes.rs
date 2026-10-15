//! Machine-readable error codes reported to clients.

use std::collections::HashSet;

use devolutions_gateway::error_code::ErrorCode;
use devolutions_gateway::token::{ContentType, TokenError};
use expect_test::expect;
use picky::jose::jwe::JweError;
use picky::jose::jws::JwsError;
use picky::jose::jwt::{JwtDate, JwtError};
use rstest::rstest;

fn invalid_utf8() -> std::str::Utf8Error {
    std::str::from_utf8(std::hint::black_box(&[0xC0])).unwrap_err()
}

fn json_error() -> serde_json::Error {
    serde_json::from_str::<u8>("not JSON").unwrap_err()
}

fn jws_error() -> JwsError {
    JwsError::InvalidEncoding { input: String::new() }
}

#[rstest]
// Raised before the signature is verified.
#[case::missing_delegation_key(TokenError::MissingDelegationKey, "malformed_token")]
#[case::jwe(TokenError::Jwe { source: JweError::AesGcm }, "malformed_token")]
#[case::jwe_payload(TokenError::JwePayload { source: invalid_utf8() }, "malformed_token")]
#[case::jws(TokenError::Jws { source: jws_error() }, "malformed_token")]
#[case::signature_verification(
    TokenError::SignatureVerification { source: jws_error(), key: "main provisioner key" },
    "bad_signature"
)]
#[case::unknown_subkey(TokenError::UnknownSubkey { provided_kid: String::new() }, "unknown_subkey")]
// Raised after the signature is verified.
#[case::bad_content_type(
    TokenError::BadContentType { source: "UNKNOWN".parse::<ContentType>().unwrap_err() },
    "malformed_token"
)]
#[case::expired(
    TokenError::Jwt { source: JwtError::Expired { not_after: 0, now: JwtDate::new(1) } },
    "expired"
)]
#[case::not_yet_valid(
    TokenError::Jwt { source: JwtError::NotYetValid { not_before: 1, now: JwtDate::new(0) } },
    "not_yet_valid"
)]
#[case::required_claim_missing(
    TokenError::Jwt { source: JwtError::RequiredClaimMissing { claim: "exp" } },
    "malformed_token"
)]
#[case::invalid_registered_claim_type(
    TokenError::Jwt { source: JwtError::InvalidRegisteredClaimType { claim: "exp" } },
    "malformed_token"
)]
#[case::claims_json(TokenError::Jwt { source: JwtError::Json { source: json_error() } }, "malformed_token")]
#[case::invalid_validator(
    TokenError::Jwt { source: JwtError::InvalidValidator { description: "" } },
    "invalid_token"
)]
#[case::content_type_not_allowed_for_subkey(
    TokenError::ContentTypeNotAllowedForSubkey { content_type: ContentType::Scope },
    "invalid_token"
)]
#[case::malformed_claim(
    TokenError::MalformedClaim { name: "jet_gw_id", source: anyhow::anyhow!("invalid UUID") },
    "malformed_token"
)]
#[case::gateway_id_scope_mismatch(TokenError::GatewayIdScopeMismatch, "gateway_id_mismatch")]
#[case::revoked(TokenError::Revoked, "revoked")]
#[case::invalid_claim_scheme(
    TokenError::InvalidClaimScheme { content_type: ContentType::Scope, source: json_error() },
    "malformed_token"
)]
#[case::plaintext_secrets(TokenError::PlaintextSecrets, "invalid_token")]
#[case::unexpected_replay(TokenError::UnexpectedReplay { reason: "different source IP" }, "unexpected_replay")]
#[case::old_jrl(TokenError::OldJrl, "invalid_token")]
#[case::subkey_signed_and_too_long_lifetime(TokenError::SubkeySignedAndTooLongLifetime, "invalid_token")]
#[case::too_long_lifetime(TokenError::TooLongLifetime, "invalid_token")]
fn token_error_code(#[case] error: TokenError, #[case] expected_code: &str) {
    assert_eq!(error.code().as_str(), expected_code);
}

/// Codes are public API: existing codes are never renamed or removed, and new codes are appended.
#[test]
fn codes_are_stable() {
    let codes = ErrorCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    expect![[r#"
        bad_request
        unauthorized
        forbidden
        not_found
        request_timeout
        conflict
        payload_too_large
        internal_error
        bad_gateway
        service_unavailable
        gateway_timeout
        insufficient_storage
        missing_token
        malformed_token
        bad_signature
        unknown_subkey
        expired
        not_yet_valid
        gateway_id_mismatch
        revoked
        unexpected_replay
        invalid_token
        wrong_token_type
        insufficient_scope"#]]
    .assert_eq(&codes);
}

#[test]
fn codes_are_unique_snake_case_and_documented() {
    let mut seen = HashSet::new();

    for code in ErrorCode::ALL {
        let code_str = code.as_str();

        assert!(seen.insert(code_str), "duplicated code: {code_str}");
        assert!(
            code_str.starts_with(|c: char| c.is_ascii_lowercase())
                && code_str.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "not snake_case: {code_str}"
        );
        assert!(!code.description().is_empty(), "undocumented code: {code_str}");
        assert_eq!(serde_json::to_value(code).unwrap(), code_str);
    }
}
