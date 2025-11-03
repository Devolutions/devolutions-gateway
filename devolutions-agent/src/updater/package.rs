//! Package installation and validation logic

use std::ops::DerefMut;

use camino::Utf8Path;
use uuid::Uuid;

use win_api_wrappers::utils::WideString;

use crate::updater::io::remove_file_on_reboot;
use crate::updater::{Product, UpdaterCtx, UpdaterError};

/// List of allowed thumbprints for Devolutions code signing certificates
const DEVOLUTIONS_CERT_THUMBPRINTS: &[&str] = &[
    "3f5202a9432d54293bdfe6f7e46adb0a6f8b3ba6",
    "8db5a43bb8afe4d2ffb92da9007d8997a4cc4e13",
];

pub(crate) async fn install_package(
    ctx: &UpdaterCtx,
    path: &Utf8Path,
    log_path: &Utf8Path,
) -> Result<(), UpdaterError> {
    match ctx.product {
        Product::Gateway | Product::HubService => install_msi(ctx, path, log_path).await,
    }
}

pub(crate) async fn uninstall_package(
    ctx: &UpdaterCtx,
    product_code: Uuid,
    log_path: &Utf8Path,
) -> Result<(), UpdaterError> {
    match ctx.product {
        Product::Gateway | Product::HubService => uninstall_msi(ctx, product_code, log_path).await,
    }
}

async fn install_msi(ctx: &UpdaterCtx, path: &Utf8Path, log_path: &Utf8Path) -> Result<(), UpdaterError> {
    // When running in service, we do always have enough rights to install MSI. However, for ease
    // of testing, we can skip MSI installation.
    ensure_enough_rights()?;

    info!("Installing MSI from path: {}", path);

    let mut msiexec_command = tokio::process::Command::new("msiexec");

    msiexec_command
        .arg("/i")
        .arg(path.as_str())
        .arg("/quiet")
        .arg("/l*v")
        .arg(log_path.as_str());

    for param in ctx.actions.get_msiexec_install_params() {
        msiexec_command.arg(param);
    }

    let msi_install_result = msiexec_command.status().await;

    if log_path.exists() {
        info!("MSI installation log: {log_path}");

        // Schedule log file for deletion on reboot
        if let Err(error) = remove_file_on_reboot(log_path) {
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

async fn uninstall_msi(ctx: &UpdaterCtx, product_code: Uuid, log_path: &Utf8Path) -> Result<(), UpdaterError> {
    // See `install_msi`
    ensure_enough_rights()?;

    info!(%product_code, "Uninstalling MSI");

    let msi_uninstall_result = tokio::process::Command::new("msiexec")
        .arg("/x")
        .arg(product_code.braced().to_string())
        .arg("/quiet")
        .arg("/l*v")
        .arg(log_path.as_str())
        .status()
        .await;

    if log_path.exists() {
        info!(%product_code, "MSI uninstall log: {log_path}");

        // Schedule log file for deletion on reboot
        if let Err(error) = remove_file_on_reboot(log_path) {
            error!(%error, "Failed to schedule log file for deletion on reboot");
        }
    }

    if msi_uninstall_result.is_err() {
        return Err(UpdaterError::MsiUninstall {
            product: ctx.product,
            product_code,
        });
    }

    Ok(())
}

fn ensure_enough_rights() -> Result<(), UpdaterError> {
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::Owned;

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
            Some(&mut token_elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
            size_of::<TOKEN_ELEVATION>()
                .try_into()
                .expect("TOKEN_ELEVATION size always fits into u32"),
            &mut return_size as *mut u32,
        )
    };

    if token_query_result.is_err() || token_elevation.TokenIsElevated == 0 {
        return Err(UpdaterError::NotElevated);
    }

    Ok(())
}

pub(crate) fn validate_package(ctx: &UpdaterCtx, path: &Utf8Path) -> Result<(), UpdaterError> {
    match ctx.product {
        Product::Gateway | Product::HubService => validate_msi(ctx, path),
    }
}

fn validate_msi(ctx: &UpdaterCtx, path: &Utf8Path) -> Result<(), UpdaterError> {
    use windows::Win32::Security::Cryptography::{
        CALG_SHA1, CERT_CONTEXT, CertFreeCertificateContext, CryptHashCertificate,
    };
    use windows::Win32::System::ApplicationInstallationAndServicing::{
        MSI_INVALID_HASH_IS_FATAL, MsiGetFileSignatureInformationW,
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

    let wide_msi_path = WideString::from(path.as_str());
    let mut cert_context = OwnedCertContext(std::ptr::null_mut());

    // SAFETY: `wide_msi_path` is a valid null-terminated UTF-16 string, and `cert_context`
    // validity is ensured by `OwnedCertContext`, therefore the function is safe to call.
    let result = unsafe {
        MsiGetFileSignatureInformationW(
            wide_msi_path.as_pcwstr(),
            MSI_INVALID_HASH_IS_FATAL, // Validate signature
            &mut cert_context.0 as *mut *mut CERT_CONTEXT,
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

    const SHA1_HASH_SIZE: u8 = 20;
    let mut calculated_cert_sha1 = [0u8; SHA1_HASH_SIZE as usize];
    let mut calculated_cert_sha1_size = u32::from(SHA1_HASH_SIZE);

    // SAFETY: `cert_context.0` validity is checked above.
    let cert_data = unsafe { (*cert_context.0).pbCertEncoded };
    // SAFETY: `cert_context.0` validity is checked above.
    let cert_len = unsafe { (*cert_context.0).cbCertEncoded };
    // SAFETY: `cert_context` valid throughout the function, (ensured by the `OwnedCertContext`).
    // therefore is is safe to construct a slice from it.
    let encoded_slice = unsafe {
        core::slice::from_raw_parts(
            cert_data,
            usize::try_from(cert_len).expect("BUG: Invalid certificate length"),
        )
    };

    // SAFETY: `encoded_slice` validity is ensured by `OwnedCertContext`, and `calculated_cert_sha1`
    // and `calculated_cert_sha1_size` are valid pointers, therefore the function is safe to call.
    unsafe {
        CryptHashCertificate(
            None,
            CALG_SHA1,
            0,
            encoded_slice,
            Some(&mut calculated_cert_sha1 as *mut u8),
            &mut calculated_cert_sha1_size as *mut u32,
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
