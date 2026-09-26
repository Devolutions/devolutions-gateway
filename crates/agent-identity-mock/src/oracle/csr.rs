//! PKCS#10 CSR checking per CONTRACT.md §4: P-256 key required, self-signature verified, subject and extensions ignored.
//! X.509 and DER provide CSR types; the signature is checked with P-256.

use der::Decode as _;
use der::asn1::ObjectIdentifier;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use x509_cert::request::CertReq;

/// id-ecPublicKey (RFC 5480).
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// secp256r1 / P-256 (RFC 5480).
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// ecdsa-with-SHA256 (RFC 5758).
const ECDSA_WITH_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Parses a PKCS#10 CSR (DER), requires a P-256 subject key and verifies the self-signature.
/// Returns the subject public key, or `None` for any §5.4 `invalid_request` case.
pub(crate) fn check_csr(der_bytes: &[u8]) -> Option<VerifyingKey> {
    let req = CertReq::from_der(der_bytes).ok()?;

    if req.algorithm.oid != ECDSA_WITH_SHA_256 {
        return None;
    }

    let spki = &req.info.public_key;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return None;
    }
    let params_oid = spki
        .algorithm
        .parameters
        .as_ref()?
        .decode_as::<ObjectIdentifier>()
        .ok()?;
    if params_oid != SECP256R1 {
        return None;
    }
    let key = VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes()).ok()?;

    let info_der = der::Encode::to_der(&req.info).ok()?;
    let signature = Signature::from_der(req.signature.raw_bytes()).ok()?;
    key.verify(&info_der, &signature).ok()?;

    Some(key)
}
