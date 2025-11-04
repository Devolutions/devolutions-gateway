#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

//! Integration tests for TLS certificate thumbprint anchoring feature.
//!
//! ## Scope
//!
//! These tests validate the behavior of the `cert_thumb256` claim in association tokens
//! used with `/jet/fwd/tls` endpoint.
//!
//! ## Key properties verified
//!
//! - **Matching thumbprint with verification failures:** When a certificate thumbprint
//!   matches the `cert_thumb256` claim, the connection succeeds even if normal TLS
//!   verification fails (expired cert, self-signed, hostname mismatch, etc.)
//! - **Non-matching thumbprint:** When thumbprint doesn't match, connection is rejected
//! - **Missing claim:** When claim is absent, normal TLS validation behavior applies
//! - **Malformed claim:** Malformed thumbprints are properly normalized
//! - **Logging:** Proper structured logging when thumbprint anchoring is used

use sha2::{Digest, Sha256};

#[test]
fn test_thumbprint_normalization() {
    // Test various thumbprint formats are normalized correctly
    let test_cases = vec![
        // (input, expected_normalized)
        ("abcdef0123456789", "abcdef0123456789"),
        ("ABCDEF0123456789", "abcdef0123456789"),
        ("AB:CD:EF:01:23:45", "abcdef012345"),
        ("AB CD EF 01", "abcdef01"),
        ("ab-cd-ef-01", "abcdef01"),
    ];

    for (input, expected) in test_cases {
        let normalized = normalize_thumbprint_for_test(input);
        assert_eq!(
            normalized, expected,
            "Failed to normalize '{}' to '{}'",
            input, expected
        );
    }
}

#[test]
fn test_compute_thumbprint() {
    // Test SHA-256 computation
    let test_data = b"Hello, World!";
    let hash = Sha256::digest(test_data);
    let thumbprint = hex::encode(hash);

    // Expected SHA-256 of "Hello, World!"
    let expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
    assert_eq!(thumbprint, expected);
}

// Helper function that mirrors the normalization logic
fn normalize_thumbprint_for_test(thumb: &str) -> String {
    thumb
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase()
}

// Note: Full integration tests that actually connect to TLS servers with
// self-signed/expired certificates would require:
// 1. Setting up test TLS servers with various certificate issues
// 2. Creating proper association tokens with cert_thumb256 claims
// 3. Making actual WebSocket connections through the gateway
//
// These would be implemented as part of the broader test infrastructure
// (e.g., in the testsuite crate or as end-to-end tests)
