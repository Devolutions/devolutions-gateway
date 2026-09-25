//! CONTRACT.md §7.3 channel proof verification.

use p256::ecdsa::VerifyingKey;

use super::verify_p256_signature;

/// Domain separator of the channel proof.
const PROOF_DOMAIN: &[u8] = b"devolutions-agent-identity/v1/channel-proof";

/// Verifies `proof` (raw 64-byte `r‖s` ECDSA P-256 / SHA-256) over
/// `PROOF_DOMAIN ‖ 0x00 ‖ challenge ‖ connect_nonce (UTF-8)` with `public_key`.
pub(crate) fn verify_channel_proof(
    public_key: &VerifyingKey,
    challenge: &[u8],
    connect_nonce: &str,
    proof: &[u8],
) -> bool {
    let mut message = Vec::with_capacity(PROOF_DOMAIN.len() + 1 + challenge.len() + connect_nonce.len());
    message.extend_from_slice(PROOF_DOMAIN);
    message.push(0x00);
    message.extend_from_slice(challenge);
    message.extend_from_slice(connect_nonce.as_bytes());
    verify_p256_signature(public_key, &message, proof)
}
