use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der::Encode as _;
use der::asn1::BitString;
use device_key::DeviceKey;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::request::{CertReq, CertReqInfo, Version};

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Creates the base64 DER PKCS#10 request for an on-device key.
///
/// The request carries no attributes, as [CONTRACT.agent-identity.md §4 "Certificates"][contract] requires.
/// It is built by hand because x509-cert's `RequestBuilder` always adds an `extensionRequest` attribute,
/// which is invalid when empty.
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#4-certificates
pub fn create(key: &dyn DeviceKey) -> anyhow::Result<String> {
    let info = CertReqInfo {
        version: Version::V1,
        subject: "CN=Agent Identity".parse().context("parse CSR subject")?,
        public_key: SubjectPublicKeyInfoOwned::from_key(&key.public_key()).context("encode CSR public key")?,
        attributes: Default::default(),
    };
    let signature = key
        .try_sign(&info.to_der().context("encode CSR info")?)
        .context("sign CSR")?;
    let csr = CertReq {
        info,
        algorithm: AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        },
        signature: BitString::from_bytes(signature.to_der().as_bytes()).context("encode CSR signature")?,
    };
    Ok(STANDARD.encode(csr.to_der().context("encode CSR")?))
}

#[cfg(test)]
mod tests {
    use der::asn1::Any;
    use der::{Decode as _, Encode as _};
    use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
    use signature::{Signer, Verifier as _};

    use super::*;

    struct TestKey {
        signing_key: SigningKey,
        fail: bool,
    }

    impl DeviceKey for TestKey {
        fn name(&self) -> &str {
            "test_key"
        }

        fn public_key(&self) -> VerifyingKey {
            *self.signing_key.verifying_key()
        }

        fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
            if self.fail {
                return Err(signature::Error::new());
            }
            Signer::<Signature>::try_sign(&self.signing_key, message)
        }
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[test]
    fn csr_signatures_are_der_and_signing_failures_are_returned() -> anyhow::Result<()> {
        let mut key = TestKey {
            signing_key: SigningKey::from_slice(&[1u8; 32])?,
            fail: false,
        };
        let csr = CertReq::from_der(&STANDARD.decode(create(&key)?)?)?;
        assert_eq!(csr.algorithm.oid, ECDSA_WITH_SHA256);
        assert_eq!(
            VerifyingKey::from_sec1_bytes(
                csr.info
                    .public_key
                    .subject_public_key
                    .as_bytes()
                    .context("CSR has no public key")?
            )?,
            key.public_key()
        );
        let signature = DerSignature::from_bytes(csr.signature.as_bytes().context("CSR has no signature")?)?;
        key.public_key().verify(&csr.info.to_der()?, &signature)?;

        key.fail = true;
        // oracle: intent crates/device-key/INTENT.md §Signing
        assert!(create(&key).is_err());
        Ok(())
    }

    // `CONTRACT.agent-identity.md` §4: the agent's CSR carries no attributes.
    // RFC 2986 §4.1 makes `attributes [0] IMPLICIT` mandatory,
    // so the empty set is the element `A0 00`, not an omitted field.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: spec RFC 2986 §4.1
    #[test]
    fn csr_carries_no_attributes() -> anyhow::Result<()> {
        let key = TestKey {
            signing_key: SigningKey::from_slice(&[1u8; 32])?,
            fail: false,
        };
        let csr_der = STANDARD.decode(create(&key)?)?;
        assert_eq!(CertReq::from_der(&csr_der)?.info.attributes.len(), 0);

        // CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature }
        let csr_fields = Vec::<Any>::from_der(&csr_der)?;
        // CertificationRequestInfo ::= SEQUENCE { version, subject, subjectPKInfo, attributes }
        let info_fields = Vec::<Any>::from_der(&csr_fields[0].to_der()?)?;
        assert_eq!(info_fields.len(), 4);
        assert_eq!(info_fields[3].to_der()?, [0xA0, 0x00]);
        Ok(())
    }
}
