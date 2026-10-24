//! Enrollment CSRs as the agent builds them, and the enrollment URL a certificate names (CONTRACT.agent-identity.md §4).
//! CSRs are built and certificates parsed at run time, so that no test data embeds the enrollment URL extension's OID.

use der::asn1::Ia5String;
use der::{Decode as _, Encode as _};
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::builder::{Builder as _, RequestBuilder};
use x509_cert::name::Name;

use crate::oracle::ENROLLMENT_URL_EXTENSION;

/// Returns the P-256 key whose scalar repeats `seed`, which is from 1 to 254.
pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).expect("valid P-256 scalar")
}

/// Returns a CSR for `key` with an empty subject and an `extensionRequest` holding only the enrollment URL extension
/// naming `url`.
pub(crate) fn csr_naming(key: &SigningKey, url: &str) -> Vec<u8> {
    let mut builder = RequestBuilder::new(Name::default()).expect("empty subject");
    let url = Ia5String::new(url).expect("ASCII URL");
    builder
        .add_extension((ENROLLMENT_URL_EXTENSION, false, &url))
        .expect("encodable extension");
    builder
        .build::<_, DerSignature>(key)
        .expect("signed CSR")
        .to_der()
        .expect("encodable CSR")
}

/// Returns the enrollment URL extension of the certificate `der`: whether it is critical, and its `IA5String` value.
pub(crate) fn enrollment_url_extension(der: &[u8]) -> Option<(bool, String)> {
    let certificate = x509_cert::Certificate::from_der(der).expect("DER certificate");
    let extension = certificate
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .find(|extension| extension.extn_id == ENROLLMENT_URL_EXTENSION)?;
    let url = Ia5String::from_der(extension.extn_value.as_bytes()).expect("IA5String value");
    Some((extension.critical, url.to_string()))
}
