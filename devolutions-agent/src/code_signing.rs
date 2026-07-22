//! Windows code-signing validation helpers.

use std::path::Path;

use anyhow::{Context as _, bail};
use win_api_wrappers::security::crypt::{AuthenticodeSignatureStatus, authenticode_status};

/// List of allowed thumbprints for Devolutions code signing certificates.
pub(crate) const DEVOLUTIONS_CERT_THUMBPRINTS: &[&str] = &[
    "3f5202a9432d54293bdfe6f7e46adb0a6f8b3ba6",
    "8db5a43bb8afe4d2ffb92da9007d8997a4cc4e13",
    "50f753333811ff11f1920274afde3ffd4468b210",
];

pub(crate) fn certificate_sha1_thumbprint(cert_der: &[u8]) -> anyhow::Result<[u8; 20]> {
    use windows::Win32::Security::Cryptography::{CALG_SHA1, CryptHashCertificate};

    let mut thumbprint = [0u8; 20];
    let mut thumbprint_size = u32::try_from(thumbprint.len()).expect("SHA-1 length fits in u32");

    // SAFETY: `cert_der` points to encoded certificate bytes for the duration of the call.
    // `thumbprint` and `thumbprint_size` are valid writable output pointers.
    unsafe {
        CryptHashCertificate(
            None,
            CALG_SHA1,
            0,
            cert_der,
            Some(thumbprint.as_mut_ptr()),
            &mut thumbprint_size,
        )
    }
    .context("failed to calculate certificate thumbprint")?;

    if usize::try_from(thumbprint_size).expect("thumbprint size fits in usize") != thumbprint.len() {
        bail!("certificate thumbprint has unexpected length");
    }

    Ok(thumbprint)
}

pub(crate) fn is_devolutions_certificate_thumbprint(calculated_thumbprint: &[u8; 20]) -> bool {
    DEVOLUTIONS_CERT_THUMBPRINTS.iter().any(|thumbprint| {
        let mut thumbprint_bytes = [0u8; 20];
        hex::decode_to_slice(thumbprint, &mut thumbprint_bytes)
            .expect("BUG: Invalid thumbprint in `DEVOLUTIONS_CERT_THUMBPRINTS`");

        &thumbprint_bytes == calculated_thumbprint
    })
}

pub(crate) fn validate_devolutions_authenticode_signature(path: &Path) -> anyhow::Result<String> {
    let wintrust_result = authenticode_status(path).with_context(|| {
        format!(
            "failed to read authenticode signature for client executable '{}'",
            path.display()
        )
    })?;

    if !matches!(wintrust_result.status, AuthenticodeSignatureStatus::Valid) {
        bail!("client executable signature is not valid: {:?}", wintrust_result.status);
    }

    let signer = wintrust_result
        .provider
        .as_ref()
        .and_then(|provider| provider.signers.first())
        .context("client executable signature has no signer")?;
    let signing_cert = signer
        .cert_chain
        .first()
        .context("client executable signature has no signing certificate")?;

    let thumbprint = certificate_sha1_thumbprint(&signing_cert.cert.encoded)?;
    if !is_devolutions_certificate_thumbprint(&thumbprint) {
        bail!(
            "client executable is signed with an unexpected certificate thumbprint: {}",
            hex::encode(thumbprint)
        );
    }

    Ok(hex::encode(thumbprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_devolutions_certificate_thumbprints() {
        for thumbprint in DEVOLUTIONS_CERT_THUMBPRINTS {
            let mut thumbprint_bytes = [0u8; 20];
            hex::decode_to_slice(thumbprint, &mut thumbprint_bytes)
                .expect("test thumbprint should be valid hexadecimal");
            assert!(is_devolutions_certificate_thumbprint(&thumbprint_bytes));
        }
    }

    #[test]
    fn rejects_unknown_certificate_thumbprint() {
        assert!(!is_devolutions_certificate_thumbprint(&[0u8; 20]));
    }
}
