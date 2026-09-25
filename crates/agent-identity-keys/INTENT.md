# Device key custody

This crate holds device private keys.
It is not specific to Agent Identity; it is meant to be reusable, e.g. by Agent Tunnel.

## Invariants

- Private keys are generated inside the backend.
  They are never exported, serialized for transport, or logged.
- V1 supports P-256 ECDSA only.
- Every key has its own random name.
  Keys in the Windows key store can't be renamed, and the authority isn't known yet when the enrollment key is created.

## Interface

A key exposes:

- `signature::Signer<p256::ecdsa::Signature>` (fixed-size r‖s), used for RFC 9421 and the channel proof;
- `signature::Signer<p256::ecdsa::DerSignature>`, used for CSRs;
- its public key.

Callers never handle signature encodings themselves.

## Backends

- **Windows key store** (default on Windows):
  - Microsoft Software Key Storage Provider, machine key, non-exportable, accessible only to SYSTEM.
  - It hashes with SHA-256 and signs the digest with NCrypt, which yields r‖s.
  - It converts to DER with RustCrypto when the DER form is requested.
- **File**: PKCS#8 with owner-only permissions.
  This is a regular configuration option, not a debug feature: it serves Linux, macOS, Docker, and tests.

TPM keys (Microsoft Platform Crypto Provider) are wanted later; they are not part of V1.

## Implementation decisions

- RustCrypto traits and types.
- The `windows` crate for NCrypt.
- No `picky`.
