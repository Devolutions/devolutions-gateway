//! Test-only signature and CSR oracle for CONTRACT.md §4, §6 and §7.3.
//!
//! This hand-written verifier is deliberately independent of the agent's RFC 9421 library and implementation.
//! X.509, DER and SPKI provide CSR types; P-256 checks the signatures.
//! It is not intended for production use.
//! Callers provide certificate lookup, nonce storage and the current Unix time.

mod csr;
mod proof;
mod sfv;
mod verify;

pub(crate) use csr::check_csr;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
pub(crate) use proof::verify_channel_proof;
pub(crate) use verify::{
    AuthenticatedDevice, CertStatus, Endpoint, NonceStore, RegisteredCert, Rejection, verify_request,
};

/// Verifies a raw P-256 / SHA-256 signature over supplied bytes.
fn verify_p256_signature(public_key: &VerifyingKey, message: &[u8], raw_signature: &[u8]) -> bool {
    Signature::from_slice(raw_signature).is_ok_and(|signature| public_key.verify(message, &signature).is_ok())
}

/// Exposes the same primitive to vector tests for RFC 9421 B.2.4 and fixture-integrity checks.
#[cfg(test)]
pub(crate) fn verify_raw_signature(public_key: &VerifyingKey, message: &[u8], raw_signature: &[u8]) -> bool {
    verify_p256_signature(public_key, message, raw_signature)
}

/// `Content-Digest: sha-256=:<base64>:` (RFC 9530), computed over the exact body bytes.
pub(crate) fn content_digest_header(body: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(body);
    format!("sha-256=:{}:", base64::engine::general_purpose::STANDARD.encode(digest))
}
