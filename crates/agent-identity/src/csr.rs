use agent_identity_keys::{CsrSigner, IdentityKey};
use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der::Encode as _;
use p256::ecdsa::DerSignature;
use x509_cert::builder::{Builder as _, RequestBuilder};
use x509_cert::name::Name;

/// Creates the base64 DER PKCS#10 request for an on-device key.
pub fn create(key: &dyn IdentityKey) -> anyhow::Result<String> {
    let subject: Name = "CN=Agent Identity".parse().context("parse CSR subject")?;
    let csr = RequestBuilder::new(subject)
        .context("build CSR")?
        .build::<_, DerSignature>(&CsrSigner(key))
        .context("sign CSR")?;
    Ok(STANDARD.encode(csr.to_der().context("encode CSR")?))
}
