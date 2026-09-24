//! PKCS#10 CSR checking per CONTRACT.md §4: P-256 key required, self-signature
//! verified, subject and extensions ignored.

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

/// The CSR failed a §4 check; always surfaced as `invalid_request`.
#[derive(Debug, thiserror::Error)]
#[error("invalid CSR")]
pub struct CsrError;

/// Parses a PKCS#10 CSR (DER), requires a P-256 subject key and verifies the
/// self-signature. Returns the subject public key. Any failure maps to the §5.4
/// `invalid_request` code by the caller.
pub fn check_csr(der_bytes: &[u8]) -> Result<VerifyingKey, CsrError> {
    let req = CertReq::from_der(der_bytes).map_err(|_| CsrError)?;

    if req.algorithm.oid != ECDSA_WITH_SHA_256 {
        return Err(CsrError);
    }

    let spki = &req.info.public_key;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(CsrError);
    }
    let params_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(CsrError)?
        .decode_as::<ObjectIdentifier>()
        .map_err(|_| CsrError)?;
    if params_oid != SECP256R1 {
        return Err(CsrError);
    }
    let key = VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes()).map_err(|_| CsrError)?;

    let info_der = der::Encode::to_der(&req.info).map_err(|_| CsrError)?;
    let signature = Signature::from_der(req.signature.raw_bytes()).map_err(|_| CsrError)?;
    key.verify(&info_der, &signature).map_err(|_| CsrError)?;

    Ok(key)
}
