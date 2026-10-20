//! PKCS#10 CSR checking per CONTRACT.md §4: uncompressed P-256 key required, self-signature verified, subject and extensions ignored.
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
    // Only the uncompressed form (0x04 ‖ X ‖ Y), so that each key has exactly one SPKI SHA-256.
    let point = spki.subject_public_key.as_bytes()?;
    if point.len() != 65 || point[0] != 0x04 {
        return None;
    }
    let key = VerifyingKey::from_sec1_bytes(point).ok()?;

    let info_der = der::Encode::to_der(&req.info).ok()?;
    let signature = Signature::from_der(req.signature.raw_bytes()).ok()?;
    key.verify(&info_der, &signature).ok()?;

    Some(key)
}

#[cfg(test)]
mod tests {
    use der::Encode as _;
    use der::asn1::{Any, BitString};
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{DerSignature, SigningKey};
    use rstest::rstest;
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::request::{CertReq, CertReqInfo, Version};

    use super::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, SECP256R1, check_csr};

    /// Builds a CSR whose subject key is `encoded_point`, self-signed by `key`.
    fn csr(key: &SigningKey, encoded_point: &[u8]) -> Vec<u8> {
        let info = CertReqInfo {
            version: Version::V1,
            subject: Default::default(),
            public_key: SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: ID_EC_PUBLIC_KEY,
                    parameters: Some(Any::encode_from(&SECP256R1).expect("encodable OID")),
                },
                subject_public_key: BitString::from_bytes(encoded_point).expect("valid bit string"),
            },
            attributes: Default::default(),
        };
        let signature: DerSignature = key
            .try_sign(&info.to_der().expect("encodable request info"))
            .expect("signing succeeds");
        CertReq {
            info,
            algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: BitString::from_bytes(signature.as_bytes()).expect("valid bit string"),
        }
        .to_der()
        .expect("encodable request")
    }

    /// CONTRACT.md §4: the CSR public key must be "an uncompressed P-256 point [...], else `invalid_request`".
    #[rstest]
    #[case::uncompressed(false, true)]
    #[case::compressed(true, false)]
    fn csr_key_must_be_an_uncompressed_point(#[case] compress: bool, #[case] accepted: bool) {
        let key = SigningKey::from_slice(&[1; 32]).expect("valid P-256 scalar");
        let point = key.verifying_key().to_sec1_point(compress);
        assert_eq!(check_csr(&csr(&key, point.as_bytes())).is_some(), accepted);
    }
}
