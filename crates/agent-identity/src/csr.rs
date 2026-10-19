use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der::Encode as _;
use device_key::DeviceKey;
use p256::ecdsa::{DerSignature, VerifyingKey};
use signature::{Keypair, Signer};
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, ObjectIdentifier};
use x509_cert::builder::{Builder as _, RequestBuilder};
use x509_cert::name::Name;

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

struct CsrSigner<'a>(&'a dyn DeviceKey);

impl Keypair for CsrSigner<'_> {
    type VerifyingKey = VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.public_key()
    }
}

impl DynSignatureAlgorithmIdentifier for CsrSigner<'_> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        })
    }
}

impl Signer<DerSignature> for CsrSigner<'_> {
    fn try_sign(&self, message: &[u8]) -> signature::Result<DerSignature> {
        self.0.try_sign(message).map(|signature| signature.to_der())
    }
}

/// Creates the base64 DER PKCS#10 request for an on-device key.
pub fn create(key: &dyn DeviceKey) -> anyhow::Result<String> {
    let subject: Name = "CN=Agent Identity".parse().context("parse CSR subject")?;
    let csr = RequestBuilder::new(subject)
        .context("build CSR")?
        .build::<_, DerSignature>(&CsrSigner(key))
        .context("sign CSR")?;
    Ok(STANDARD.encode(csr.to_der().context("encode CSR")?))
}

#[cfg(test)]
mod tests {
    use der::{Decode as _, Encode as _};
    use p256::ecdsa::{Signature, SigningKey};
    use signature::Verifier as _;
    use x509_cert::request::CertReq;

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
        assert!(create(&key).is_err());
        Ok(())
    }
}
