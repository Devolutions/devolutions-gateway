use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der::Encode as _;
use der::asn1::{Any, BitString, Ia5StringRef, OctetString, SetOfVec};
use device_key::DeviceKey;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attribute;
use x509_cert::ext::Extension;
use x509_cert::request::{CertReq, CertReqInfo, Version};

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// The PKCS#9 `extensionRequest` attribute ([RFC 2985 §5.4.2 "Extension request"][rfc2985]).
///
/// [rfc2985]: https://www.rfc-editor.org/rfc/rfc2985#section-5.4.2
const EXTENSION_REQUEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

/// The OID of the enrollment URL extension ([CONTRACT.agent-identity.md §4 "Certificates"][contract]).
///
/// This is a provisional OID under the documentation enterprise number of RFC 5612; the OID the contract names
/// replaces it.
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#certificates
pub(crate) const ENROLLMENT_URL_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1.1");

/// Creates the base64 DER PKCS#10 request for an on-device key, requesting the enrollment URL extension naming
/// `base_url`.
///
/// The request carries one attribute, an `extensionRequest` holding only that extension, as
/// [CONTRACT.agent-identity.md §4 "Certificates"][contract] requires: the caller passes its token's `u` without
/// trailing slashes at enrollment, and its identity's base URL at renewal.
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#certificates
pub fn create(key: &dyn DeviceKey, base_url: &str) -> anyhow::Result<String> {
    let url = Ia5StringRef::new(base_url).context("enrollment URL is not an IA5String")?;
    let extensions = vec![Extension {
        extn_id: ENROLLMENT_URL_EXTENSION,
        critical: false,
        extn_value: OctetString::new(url.to_der().context("encode enrollment URL")?)
            .context("encode enrollment URL extension")?,
    }];
    let extension_request = Attribute {
        oid: EXTENSION_REQUEST,
        values: SetOfVec::try_from([Any::encode_from(&extensions).context("encode requested extensions")?])
            .context("encode extensionRequest attribute")?,
    };
    let info = CertReqInfo {
        version: Version::V1,
        subject: "CN=Agent Identity".parse().context("parse CSR subject")?,
        public_key: SubjectPublicKeyInfoOwned::from_key(&key.public_key()).context("encode CSR public key")?,
        attributes: SetOfVec::try_from([extension_request]).context("encode CSR attributes")?,
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
    use der::asn1::{Any, Ia5StringRef};
    use der::{Decode as _, Encode as _, Tag, Tagged as _};
    use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
    use rstest::rstest;
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
        let csr = CertReq::from_der(&STANDARD.decode(create(&key, "https://example.test/dvls")?)?)?;
        // oracle: spec RFC 5758 §3.2
        assert_eq!(csr.algorithm.oid.to_string(), "1.2.840.10045.4.3.2");
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
        assert!(create(&key, "https://example.test/dvls").is_err());
        Ok(())
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    #[rstest]
    #[case::path_prefix("https://example.test/dvls")]
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    #[case::text_as_received("https://EXAMPLE.test:443/Dv%20ls")]
    fn csr_requests_only_the_enrollment_url_extension_naming_the_base_url(
        #[case] base_url: &str,
    ) -> anyhow::Result<()> {
        let key = TestKey {
            signing_key: SigningKey::from_slice(&[1u8; 32])?,
            fail: false,
        };

        let csr = CertReq::from_der(&STANDARD.decode(create(&key, base_url)?)?)?;

        let attributes = csr.info.attributes.as_slice();
        assert_eq!(attributes.len(), 1);
        // oracle: spec RFC 2985 §5.4.2
        assert_eq!(attributes[0].oid.to_string(), "1.2.840.113549.1.9.14");
        assert_eq!(attributes[0].values.len(), 1);
        // oracle: spec RFC 5280 §4.1
        // Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
        let extensions = Vec::<Any>::from_der(&attributes[0].values.as_slice()[0].to_der()?)?;
        assert_eq!(extensions.len(), 1);
        // Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }.
        // oracle: spec X.690 §11.5
        // The extension is non-critical, and DER omits a component equal to its default.
        let fields = Vec::<Any>::from_der(&extensions[0].to_der()?)?;
        assert_eq!(fields.len(), 2);
        // The extension is the one the agent looks for in the leaves it receives.
        assert_eq!(
            ObjectIdentifier::from_der(&fields[0].to_der()?)?,
            ENROLLMENT_URL_EXTENSION
        );
        assert_eq!(fields[1].tag(), Tag::OctetString);
        assert_eq!(Ia5StringRef::from_der(fields[1].value())?.as_str(), base_url);
        Ok(())
    }
}
