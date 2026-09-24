//! CONTRACT.md §7.3 channel proof verification.

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};

/// Domain separator of the channel proof.
pub const PROOF_DOMAIN: &[u8] = b"devolutions-agent-identity/v1/channel-proof";

/// Verifies `proof` (raw 64-byte `r‖s` ECDSA P-256 / SHA-256) over
/// `PROOF_DOMAIN ‖ 0x00 ‖ challenge ‖ connect_nonce (UTF-8)` with `public_key`.
pub fn verify_channel_proof(public_key: &VerifyingKey, challenge: &[u8], connect_nonce: &str, proof: &[u8]) -> bool {
    let Ok(signature) = Signature::from_slice(proof) else {
        return false;
    };
    let mut message = Vec::with_capacity(PROOF_DOMAIN.len() + 1 + challenge.len() + connect_nonce.len());
    message.extend_from_slice(PROOF_DOMAIN);
    message.push(0x00);
    message.extend_from_slice(challenge);
    message.extend_from_slice(connect_nonce.as_bytes());
    public_key.verify(&message, &signature).is_ok()
}
