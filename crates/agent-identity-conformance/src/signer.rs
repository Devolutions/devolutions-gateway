use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use der::Encode as _;
use der::asn1::{BitString, Ia5String, ObjectIdentifier, OctetString, SetOfVec};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use p256::elliptic_curve::Generate as _;
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
use x509_cert::attr::Attribute;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq, Version};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// The OID of the enrollment URL extension that [CONTRACT.agent-identity.md] §4 "Certificates" defines.
///
/// The contract's OID, `2.25.123288656976046528792596909476335030418`, has an arc wider than the 32 bits `x509-cert` parses, so the parties use `1.3.6.1.4.1.32473.1.1`, from the documentation arc of RFC 5612, until the extension moves under Devolutions' private enterprise number.
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) const ENROLLMENT_URL_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1.1");

/// `ecdsa-with-SHA256`, RFC 5758 §3.2.
pub(crate) const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

pub(crate) struct KeyPair {
    pub(crate) key: SigningKey,
}

#[derive(Clone, Copy)]
pub(crate) enum SignatureParameter {
    Created,
    Expires,
    Nonce,
    KeyId,
    Algorithm,
    Tag,
}

const DEFAULT_PARAMETER_ORDER: [SignatureParameter; 6] = [
    SignatureParameter::Created,
    SignatureParameter::Expires,
    SignatureParameter::Nonce,
    SignatureParameter::KeyId,
    SignatureParameter::Algorithm,
    SignatureParameter::Tag,
];

impl KeyPair {
    /// Generates a new P-256 key from the thread's random number generator.
    pub(crate) fn generate() -> anyhow::Result<Self> {
        Ok(Self {
            key: SigningKey::generate_from_rng(&mut rand::rng()),
        })
    }

    /// A CSR for this key that requests the enrollment URL extension naming `base_url`, as the agent's CSR to the authority at `base_url` does ([CONTRACT.agent-identity.md] §4 "Certificates"): its token's `u` at enrollment, its identity's base URL at renewal.
    ///
    /// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
    pub(crate) fn csr(&self, base_url: &str) -> anyhow::Result<String> {
        self.csr_requesting(Some(&[enrollment_url_extension(base_url)?]))
    }

    /// A CSR for this key whose one attribute is an `extensionRequest` holding `extensions`, or that has no attribute when `extensions` is `None`, encoded `base64`.
    pub(crate) fn csr_requesting(&self, extensions: Option<&[Extension]>) -> anyhow::Result<String> {
        let mut attributes = SetOfVec::new();
        if let Some(extensions) = extensions {
            attributes.insert(Attribute::try_from(ExtensionReq(extensions.to_vec()))?)?;
        }
        let subject: Name = "CN=conformance request subject ignored"
            .parse()
            .context("parse CSR subject")?;
        let info = CertReqInfo {
            version: Version::V1,
            subject,
            public_key: SubjectPublicKeyInfoOwned::from_key(self.key.verifying_key()).context("encode CSR key")?,
            attributes,
        };
        let signature: DerSignature = self.key.try_sign(&info.to_der()?).context("sign CSR")?;
        let request = CertReq {
            info,
            algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            },
            signature: BitString::from_bytes(signature.as_bytes())?,
        };
        Ok(STANDARD.encode(request.to_der().context("encode CSR")?))
    }

    pub(crate) fn sign(
        &self,
        keyid: &str,
        tag: &str,
        body: Option<&[u8]>,
        created: i64,
        expires: i64,
        nonce: &str,
    ) -> SignedHeaders {
        self.sign_with_order(keyid, tag, body, (created, expires), nonce, &DEFAULT_PARAMETER_ORDER)
    }

    pub(crate) fn sign_with_order(
        &self,
        keyid: &str,
        tag: &str,
        body: Option<&[u8]>,
        time_bounds: (i64, i64),
        nonce: &str,
        order: &[SignatureParameter; 6],
    ) -> SignedHeaders {
        let (created, expires) = time_bounds;
        let (components, digest) = match tag {
            "renew" | "check-in" => {
                let body = body.expect("renew and check-in signatures require a body");
                (
                    "(\"@method\" \"content-digest\")",
                    Some(format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))),
                )
            }
            "connect" | "confirm" => {
                assert!(body.is_none(), "{tag} signatures require an empty body");
                ("(\"@method\")", None)
            }
            _ => panic!("unsupported signature tag {tag}"),
        };
        let parameters = order
            .iter()
            .map(|parameter| match parameter {
                SignatureParameter::Created => format!("created={created}"),
                SignatureParameter::Expires => format!("expires={expires}"),
                SignatureParameter::Nonce => format!("nonce=\"{nonce}\""),
                SignatureParameter::KeyId => format!("keyid=\"{keyid}\""),
                SignatureParameter::Algorithm => "alg=\"ecdsa-p256-sha256\"".to_owned(),
                SignatureParameter::Tag => format!("tag=\"{tag}\""),
            })
            .collect::<Vec<_>>()
            .join(";");
        let input = format!("sig={components};{parameters}");
        let mut base = String::from("\"@method\": POST\n");
        if let Some(value) = &digest {
            base.push_str(&format!("\"content-digest\": {value}\n"));
        }
        base.push_str("\"@signature-params\": ");
        base.push_str(&input[4..]);
        let signature: Signature = self.key.sign(base.as_bytes());
        SignedHeaders {
            input,
            signature: format!("sig=:{}:", STANDARD.encode(signature.to_bytes())),
            digest,
            nonce: nonce.to_owned(),
            #[cfg(test)]
            base,
        }
    }

    pub(crate) fn sign_now(&self, keyid: &str, tag: &str, body: Option<&[u8]>) -> SignedHeaders {
        self.sign_now_with_order(keyid, tag, body, &DEFAULT_PARAMETER_ORDER)
    }

    pub(crate) fn sign_now_with_order(
        &self,
        keyid: &str,
        tag: &str,
        body: Option<&[u8]>,
        order: &[SignatureParameter; 6],
    ) -> SignedHeaders {
        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill(&mut nonce_bytes[..]);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.sign_with_order(
            keyid,
            tag,
            body,
            (now, now + 60),
            &URL_SAFE_NO_PAD.encode(nonce_bytes),
            order,
        )
    }

    pub(crate) fn channel_proof(&self, challenge: &[u8], nonce: &str) -> Vec<u8> {
        let mut message = b"devolutions-agent-identity/v1/channel-proof\0".to_vec();
        message.extend_from_slice(challenge);
        message.extend_from_slice(nonce.as_bytes());
        let signature: Signature = self.key.sign(&message);
        signature.to_bytes().to_vec()
    }
}

#[derive(Clone)]
pub(crate) struct SignedHeaders {
    pub(crate) input: String,
    pub(crate) signature: String,
    pub(crate) digest: Option<String>,
    pub(crate) nonce: String,
    #[cfg(test)]
    pub(crate) base: String,
}

pub(crate) fn thumbprint(cert_base64: &str) -> anyhow::Result<String> {
    let cert = STANDARD.decode(cert_base64).context("decode certificate")?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(cert)))
}

/// The non-critical enrollment URL extension holding `url` as an `IA5String` ([CONTRACT.agent-identity.md] §4 "Certificates").
///
/// [CONTRACT.agent-identity.md]: ../../../docs/agent-identity/CONTRACT.agent-identity.md
pub(crate) fn enrollment_url_extension(url: &str) -> anyhow::Result<Extension> {
    Ok(Extension {
        extn_id: ENROLLMENT_URL_EXTENSION,
        critical: false,
        extn_value: OctetString::new(Ia5String::new(url).context("enrollment URL is not ASCII")?.to_der()?)?,
    })
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};

    use super::*;

    #[test]
    fn signer_reproduces_vector_inputs_and_verifies_under_vector_keys() -> anyhow::Result<()> {
        // oracle: intent docs/agent-identity/INTENT.agent-identity.md §Conformance
        const ALGORITHM_BEFORE_KEY_ID: [SignatureParameter; 6] = [
            SignatureParameter::Created,
            SignatureParameter::Expires,
            SignatureParameter::Nonce,
            SignatureParameter::Algorithm,
            SignatureParameter::KeyId,
            SignatureParameter::Tag,
        ];
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let cases = vectors["http_signature"]["cases"].as_array().context("vector cases")?;
        for (name, key_name) in [
            ("valid_renew", "device-a"),
            ("valid_connect", "device-a"),
            ("valid_confirm", "device-g"),
            ("valid_check_in", "device-a"),
            ("valid_renew_alg_before_keyid", "device-a"),
            ("valid_connect_alg_before_keyid", "device-a"),
            ("valid_confirm_alg_before_keyid", "device-g"),
            ("valid_check_in_alg_before_keyid", "device-a"),
        ] {
            let case = cases
                .iter()
                .find(|case| case["name"] == name)
                .context("missing signature vector")?;
            let vector_key = vectors["keys"]
                .as_array()
                .context("vector keys")?
                .iter()
                .find(|key| key["name"] == key_name)
                .context("missing vector key")?;
            let key_der = STANDARD.decode(vector_key["private_key_pkcs8"].as_str().context("vector private key")?)?;
            let pair = KeyPair {
                key: SigningKey::from_pkcs8_der(&key_der)?,
            };
            let input = case["headers"]["signature-input"].as_str().context("signature-input")?;
            let tag = case["endpoint"].as_str().context("endpoint")?;
            let nonce = input
                .split(";nonce=\"")
                .nth(1)
                .and_then(|value| value.split('"').next())
                .context("nonce")?;
            let keyid = vector_key["thumbprint"].as_str().context("thumbprint")?;
            let body = case["body"].as_str().map(str::as_bytes);
            let order = if name.ends_with("_alg_before_keyid") {
                &ALGORITHM_BEFORE_KEY_ID
            } else {
                &DEFAULT_PARAMETER_ORDER
            };
            let signed = pair.sign_with_order(keyid, tag, body, (1_790_000_000, 1_790_000_060), nonce, order);
            assert_eq!(signed.input, input, "{name} input");
            assert_eq!(signed.base, case["signature_base"], "{name} signature base");
            assert_eq!(signed.digest.as_deref(), case["headers"]["content-digest"].as_str());
            let raw = signed
                .signature
                .strip_prefix("sig=:")
                .and_then(|value| value.strip_suffix(':'))
                .context("signature header encoding")?;
            vector_public_key(vector_key)?
                .verify(
                    case["signature_base"].as_str().context("signature base")?.as_bytes(),
                    &Signature::from_slice(&STANDARD.decode(raw)?)?,
                )
                .with_context(|| format!("{name} signature does not verify under the vector key"))?;
        }
        let key_der = STANDARD.decode(vectors["keys"][0]["private_key_pkcs8"].as_str().context("vector key")?)?;
        let pair = KeyPair {
            key: SigningKey::from_pkcs8_der(&key_der)?,
        };
        let proof = &vectors["channel_proof"];
        let challenge = STANDARD.decode(proof["challenge"].as_str().context("challenge")?)?;
        let nonce = proof["connect_nonce"].as_str().context("connect nonce")?;
        let message_hex = proof["message_hex"].as_str().context("message hex")?;
        let message = (0..message_hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&message_hex[index..index + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        let proof_key = VerifyingKey::from_sec1_bytes(
            &STANDARD.decode(proof["public_key_sec1"].as_str().context("channel proof public key")?)?,
        )?;
        proof_key
            .verify(
                &message,
                &Signature::from_slice(&pair.channel_proof(&challenge, nonce))?,
            )
            .context("channel proof does not verify over the vector message")?;
        let rfc = &vectors["rfc9421_b_2_4"];
        let pub_der = STANDARD.decode(rfc["public_key_spki"].as_str().context("rfc public key")?)?;
        let key = VerifyingKey::from_public_key_der(&pub_der)?;
        let signature = Signature::from_slice(&STANDARD.decode(rfc["signature"].as_str().context("rfc signature")?)?)?;
        key.verify(
            rfc["signature_base"].as_str().context("rfc base")?.as_bytes(),
            &signature,
        )?;
        Ok(())
    }

    /// A CSR the suite sends must look like the agent's, so that an authority refusing it refuses the agent too.
    #[test]
    fn csr_requests_only_the_enrollment_url_extension() -> anyhow::Result<()> {
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
        // oracle: spec RFC 2986 §4.1
        // oracle: spec RFC 5272 §3.1
        use der::Decode as _;
        use p256::pkcs8::EncodePublicKey as _;

        let url = "https://host:8443/dvls";
        let pair = KeyPair::generate()?;
        let request = CertReq::from_der(&STANDARD.decode(pair.csr(url)?)?)?;
        let [attribute] = request.info.attributes.as_slice() else {
            anyhow::bail!("the CSR does not carry exactly one attribute");
        };
        // id-ExtensionReq, PKCS #9 (RFC 2985 §5.4.2).
        assert_eq!(attribute.oid, ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14"));
        let [value] = attribute.values.as_slice() else {
            anyhow::bail!("the extensionRequest attribute does not hold exactly one value");
        };
        let extensions: Vec<Extension> = value.decode_as()?;
        let [extension] = extensions.as_slice() else {
            anyhow::bail!("the extensionRequest does not hold exactly one extension");
        };
        assert_eq!(extension.extn_id, ENROLLMENT_URL_EXTENSION);
        assert!(!extension.critical, "the enrollment URL extension is critical");
        assert_eq!(Ia5String::from_der(extension.extn_value.as_bytes())?.as_str(), url);
        assert_eq!(request.algorithm.oid, ECDSA_WITH_SHA256);
        assert_eq!(
            request.info.public_key.to_der()?,
            pair.key.verifying_key().to_public_key_der()?.as_bytes()
        );
        pair.key
            .verifying_key()
            .verify(
                &request.info.to_der()?,
                &DerSignature::from_bytes(request.signature.raw_bytes())?,
            )
            .context("the CSR self-signature does not verify")?;
        let bare = CertReq::from_der(&STANDARD.decode(pair.csr_requesting(None)?)?)?;
        assert!(
            bare.info.attributes.is_empty(),
            "a CSR without extensions carries an attribute"
        );
        Ok(())
    }

    fn vector_public_key(vector_key: &serde_json::Value) -> anyhow::Result<VerifyingKey> {
        let sec1 = STANDARD.decode(vector_key["public_key_sec1"].as_str().context("vector public key")?)?;
        Ok(VerifyingKey::from_sec1_bytes(&sec1)?)
    }
}
