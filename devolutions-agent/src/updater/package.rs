//! Package installation and validation logic

use std::ops::DerefMut;

use camino::Utf8Path;

use crate::updater::io::remove_file_on_reboot;
use crate::updater::{Product, UpdaterCtx, UpdaterError};

/// List of allowed thumbprints for Devolutions code signing certificates
const DEVOLUTIONS_CERT_THUMBPRINTS: &[&str] = &[
    "3f5202a9432d54293bdfe6f7e46adb0a6f8b3ba6",
    "8db5a43bb8afe4d2ffb92da9007d8997a4cc4e13",
];

pub(crate) async fn install_package(ctx: &UpdaterCtx, path: &Utf8Path) -> Result<(), UpdaterError> {
    match ctx.product {
        Product::Gateway => install_msi(ctx, path).await,
    }
}

async fn install_msi(ctx: &UpdaterCtx, path: &Utf8Path) -> Result<(), UpdaterError> {
    // When running in service, we do always have enough rights to install MSI. However, for ease
    // of testing, we can skip MSI installation.
    ensure_enough_rights()?;

    info!("Installing MSI from path: {}", path);

    let log_path = path.with_extension("log");

    let msi_install_result = tokio::process::Command::new("msiexec")
        .arg("/i")
        .arg(path.as_str())
        .arg("/quiet")
        .arg("/l*v")
        .arg(log_path.as_str())
        .status()
        .await;

    if log_path.exists() {
        info!("MSI installation log: {log_path}");

        // Schedule log file for deletion on reboot
        if let Err(error) = remove_file_on_reboot(&log_path) {
            error!(%error, "Failed to schedule log file for deletion on reboot");
        }
    }

    if msi_install_result.is_err() {
        return Err(UpdaterError::MsiInstall {
            product: ctx.product,
            msi_path: path.to_owned(),
        });
    }

    Ok(())
}

fn ensure_enough_rights() -> Result<(), UpdaterError> {
    use windows::core::Owned;
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: `GetCurrentProcess` returns a "pseudo handle" that does not need to be closed.
    let process_handle = unsafe { GetCurrentProcess() };

    // SAFETY: `INVALID_HANDLE_VALUE` are predefined values that represent an invalid handle,
    // and thus safe to use as a default value.
    let mut token_handle = unsafe { Owned::new(INVALID_HANDLE_VALUE) };

    // SAFETY: Called with valid process handle, should not fail.
    let open_token_result =
        unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, token_handle.deref_mut() as *mut _) };

    if open_token_result.is_err() || token_handle.is_invalid() {
        // Should never happen, as we are passing a valid handle, but just in case, handle this case
        // as non-elevated access.
        return Err(UpdaterError::NotElevated);
    }

    let mut token_elevation = TOKEN_ELEVATION::default();
    let mut return_size = 0u32;

    // SAFETY: Called with valid token and pre-allocated buffer.
    let token_query_result = unsafe {
        GetTokenInformation(
            *token_handle,
            TokenElevation,
            Some(&mut token_elevation as *mut _ as _),
            std::mem::size_of::<TOKEN_ELEVATION>().try_into().unwrap(),
            &mut return_size as _,
        )
    };

    if token_query_result.is_err() || token_elevation.TokenIsElevated == 0 {
        return Err(UpdaterError::NotElevated);
    }

    Ok(())
}

pub(crate) fn validate_package(ctx: &UpdaterCtx, path: &Utf8Path) -> Result<(), UpdaterError> {
    match ctx.product {
        Product::Gateway => validate_msi(ctx, path),
    }
}

fn validate_msi(ctx: &UpdaterCtx, path: &Utf8Path) -> Result<(), UpdaterError> {
    use windows::core::HSTRING;
    use windows::Win32::Security::Cryptography::{
        CertFreeCertificateContext, CryptHashCertificate, CALG_SHA1, CERT_CONTEXT,
    };
    use windows::Win32::System::ApplicationInstallationAndServicing::{
        MsiGetFileSignatureInformationW, MSI_INVALID_HASH_IS_FATAL,
    };

    // Wrapper type to free CERT_CONTEXT retrieved via `MsiGetFileSignatureInformationW``
    struct OwnedCertContext(pub *mut CERT_CONTEXT);

    impl Drop for OwnedCertContext {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: inner pointer is always valid, as it is only set
                // via `MsiGetFileSignatureInformationW` call
                let _ = unsafe { CertFreeCertificateContext(Some(self.0)) };
            }
        }
    }

    let msi_path_hstring = HSTRING::from(path.as_str());
    let mut cert_context = OwnedCertContext(std::ptr::null_mut());

    // SAFETY: `msi_path_hstring` is a valid reference-counted UTF16 string, and `cert_context` is
    // initialized and will be freed on drop.
    let result = unsafe {
        MsiGetFileSignatureInformationW(
            &msi_path_hstring,
            MSI_INVALID_HASH_IS_FATAL, // Validate signature
            &mut cert_context.0 as _,
            None,
            None,
        )
    };

    let mut validation_failed = result.is_err() || cert_context.0.is_null();

    if !validation_failed {
        // SAFETY: `cert_context.0` is not null if this block is reached.
        validation_failed |= unsafe { (*cert_context.0).pbCertEncoded.is_null() };
    }

    if validation_failed {
        return Err(UpdaterError::MsiSignature {
            product: ctx.product,
            msi_path: path.to_owned(),
        });
    }

    let mut calculated_cert_sha1 = [0u8; 20];
    let mut calculated_cert_sha1_size = calculated_cert_sha1.len() as u32;

    // SAFETY: cert_context.0.pbCertEncoded is a valid pointer to the certificate bytes retrieved
    // via `MsiGetFileSignatureInformationW` call and validated above.
    unsafe {
        CryptHashCertificate(
            None,
            CALG_SHA1,
            0,
            core::slice::from_raw_parts((*cert_context.0).pbCertEncoded, (*cert_context.0).cbCertEncoded as _),
            Some(&mut calculated_cert_sha1 as _),
            &mut calculated_cert_sha1_size as _,
        )
    }
    .map_err(|_| UpdaterError::MsiCertHash {
        product: ctx.product,
        msi_path: path.to_owned(),
    })?;

    let is_thumbprint_valid = DEVOLUTIONS_CERT_THUMBPRINTS.iter().any(|thumbprint| {
        let mut thumbprint_bytes = [0u8; 20];
        hex::decode_to_slice(thumbprint, &mut thumbprint_bytes)
            .expect("BUG: Invalid thumbprint in `DEVOLUTIONS_CERT_THUMBPRINTS`");

        thumbprint_bytes == calculated_cert_sha1
    });

    if !is_thumbprint_valid {
        return Err(UpdaterError::MsiCertificateThumbprint {
            product: ctx.product,
            thumbprint: hex::encode(calculated_cert_sha1),
        });
    }

    Ok(())
}
