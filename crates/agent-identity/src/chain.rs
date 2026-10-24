//! Certificate chain checks against roots the agent already holds.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use der::{Decode as _, Encode as _};
use p256::pkcs8::DecodePublicKey as _;
use signature::Verifier as _;
use spki::ObjectIdentifier;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

/// `ecdsa-with-SHA256` ([RFC 5758 §3.2]), which the contract allows with a P-256 key.
///
/// [RFC 5758 §3.2]: https://www.rfc-editor.org/rfc/rfc5758#section-3.2
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// `ecdsa-with-SHA384` ([RFC 5758 §3.2]), which the contract allows with a P-384 key.
///
/// [RFC 5758 §3.2]: https://www.rfc-editor.org/rfc/rfc5758#section-3.2
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Returns whether a signature path runs from the leaf of `chain`, through the chain's own certificates in order, to the
/// public key of one of `roots`; both hold `base64` DER certificates, and `chain` is leaf first.
///
/// Each step follows [RFC 5280 §6.1]: the certificate's issuer name equals its signer's subject, and its signature
/// verifies under the signer's key with an algorithm the contract allows, `ecdsa-with-SHA256` by a P-256 key or
/// `ecdsa-with-SHA384` by a P-384 key, never RSA.
/// A signer from `chain` must be a CA that may sign certificates, so that no leaf, such as the one the authority issued
/// to another device, signs for the authority; a root is trusted as is, as RFC 5280 trusts an anchor.
/// Validity periods are not checked, because the path only has to prove that the server holds the CA key of a root.
///
/// [RFC 5280 §6.1]: https://www.rfc-editor.org/rfc/rfc5280#section-6.1
pub(crate) fn verifies_against(chain: &[String], roots: &[&str]) -> bool {
    let roots: Vec<Certificate> = roots.iter().filter_map(|root| decode(root)).collect();
    let Some(chain) = chain
        .iter()
        .map(|certificate| decode(certificate))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let mut signers = chain.iter();
    let Some(mut certificate) = signers.next() else {
        return false;
    };
    // The CA certificates between the leaf and the next signer, other than self-issued ones, which a pathLenConstraint
    // limits.
    let mut intermediates = 0;
    loop {
        if roots.iter().any(|root| is_signed_by(certificate, root)) {
            return true;
        }
        let Some(signer) = signers.next() else {
            return false;
        };
        if !(may_sign_certificates(signer, intermediates) && is_signed_by(certificate, signer)) {
            return false;
        }
        if signer.tbs_certificate().issuer() != signer.tbs_certificate().subject() {
            intermediates += 1;
        }
        certificate = signer;
    }
}

fn decode(certificate: &str) -> Option<Certificate> {
    Certificate::from_der(&STANDARD.decode(certificate).ok()?).ok()
}

/// Returns whether `certificate` is a CA that may sign certificates with `intermediates` CA certificates, other than
/// self-issued ones, below it ([RFC 5280 §6.1.4]): basicConstraints with `cA` set, keyCertSign when keyUsage is present,
/// and a pathLenConstraint of at least `intermediates`.
///
/// [RFC 5280 §6.1.4]: https://www.rfc-editor.org/rfc/rfc5280#section-6.1.4
fn may_sign_certificates(certificate: &Certificate, intermediates: usize) -> bool {
    let tbs = certificate.tbs_certificate();
    let Ok(Some((_, constraints))) = tbs.get_extension::<BasicConstraints>() else {
        return false;
    };
    let key_cert_sign = match tbs.get_extension::<KeyUsage>() {
        Ok(Some((_, usage))) => usage.key_cert_sign(),
        Ok(None) => true,
        Err(_) => false,
    };
    constraints.ca
        && key_cert_sign
        && constraints
            .path_len_constraint
            .is_none_or(|limit| intermediates <= usize::from(limit))
}

/// Returns whether `signer` signed `certificate`: under the issuer name `certificate` gives, with `ecdsa-with-SHA256`
/// and a P-256 signer key or `ecdsa-with-SHA384` and a P-384 one ([CONTRACT.agent-identity.md §4 "Certificates"]).
///
/// The signature algorithm the certificate names picks the verifier, and the verifier accepts only a signer key on
/// its curve, so any other pairing, an RSA key included, does not verify.
///
/// [CONTRACT.agent-identity.md §4 "Certificates"]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#certificates
fn is_signed_by(certificate: &Certificate, signer: &Certificate) -> bool {
    return certificate.tbs_certificate().issuer() == signer.tbs_certificate().subject()
        && signature_verifies(certificate, signer).is_some();

    fn signature_verifies(certificate: &Certificate, signer: &Certificate) -> Option<()> {
        let key = signer.tbs_certificate().subject_public_key_info().to_der().ok()?;
        let message = certificate.tbs_certificate().to_der().ok()?;
        let signature = certificate.signature().as_bytes()?;
        match certificate.signature_algorithm().oid {
            ECDSA_WITH_SHA256 => p256::ecdsa::VerifyingKey::from_public_key_der(&key)
                .ok()?
                .verify(&message, &p256::ecdsa::DerSignature::from_bytes(signature).ok()?)
                .ok(),
            ECDSA_WITH_SHA384 => p384::ecdsa::VerifyingKey::from_public_key_der(&key)
                .ok()?
                .verify(&message, &p384::ecdsa::DerSignature::from_bytes(signature).ok()?)
                .ok(),
            _ => None,
        }
    }
}
