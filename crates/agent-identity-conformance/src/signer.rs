use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use der::Encode as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use p256::elliptic_curve::Generate as _;
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
use x509_cert::builder::{Builder as _, RequestBuilder};
use x509_cert::name::Name;

pub(crate) struct KeyPair {
    pub(crate) key: SigningKey,
    pub(crate) csr: String,
}

impl KeyPair {
    pub(crate) fn generate() -> anyhow::Result<Self> {
        let key = SigningKey::generate_from_rng(&mut rand::rng());
        let subject: Name = "CN=conformance request subject ignored"
            .parse()
            .context("parse CSR subject")?;
        let csr = RequestBuilder::new(subject)
            .context("build CSR")?
            .build::<_, DerSignature>(&key)
            .context("sign CSR")?
            .to_der()
            .context("encode CSR")?;
        Ok(Self {
            key,
            csr: STANDARD.encode(csr),
        })
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
        let input = format!(
            "sig={components};created={created};expires={expires};nonce=\"{nonce}\";keyid=\"{keyid}\";alg=\"ecdsa-p256-sha256\";tag=\"{tag}\""
        );
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
        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill(&mut nonce_bytes[..]);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.sign(keyid, tag, body, now, now + 60, &URL_SAFE_NO_PAD.encode(nonce_bytes))
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

#[cfg(test)]
mod tests {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};

    use super::*;

    #[test]
    fn fixed_rfc6979_vectors_and_channel_proof() -> anyhow::Result<()> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/agent-identity/test-vectors.json"))?;
        let cases = vectors["http_signature"]["cases"].as_array().context("vector cases")?;
        for (name, key_name) in [
            ("valid_renew", "device-a"),
            ("valid_connect", "device-a"),
            ("valid_confirm", "device-g"),
            ("valid_check_in", "device-a"),
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
                csr: String::new(),
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
            let signed = pair.sign(keyid, tag, body, 1_790_000_000, 1_790_000_060, nonce);
            assert_eq!(signed.input, input, "{name} input");
            assert_eq!(signed.base, case["signature_base"], "{name} signature base");
            assert_eq!(signed.signature, case["headers"]["signature"], "{name} signature");
            assert_eq!(signed.digest.as_deref(), case["headers"]["content-digest"].as_str());
        }
        let key_der = STANDARD.decode(vectors["keys"][0]["private_key_pkcs8"].as_str().context("vector key")?)?;
        let pair = KeyPair {
            key: SigningKey::from_pkcs8_der(&key_der)?,
            csr: String::new(),
        };
        let proof = &vectors["channel_proof"];
        let challenge = STANDARD.decode(proof["challenge"].as_str().context("challenge")?)?;
        let nonce = proof["connect_nonce"].as_str().context("connect nonce")?;
        let mut message = b"devolutions-agent-identity/v1/channel-proof\0".to_vec();
        message.extend_from_slice(&challenge);
        message.extend_from_slice(nonce.as_bytes());
        let expected_hex = proof["message_hex"].as_str().context("message hex")?;
        assert_eq!(
            message.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            expected_hex
        );
        let expected_proof = proof["cases"][0]["proof"].as_str().context("valid proof")?;
        assert_eq!(STANDARD.encode(pair.channel_proof(&challenge, nonce)), expected_proof);
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
}
