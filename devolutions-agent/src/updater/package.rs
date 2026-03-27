//! Package installation and validation logic

use std::ops::DerefMut;

use camino::{Utf8Path, Utf8PathBuf};
use uuid::Uuid;
use win_api_wrappers::utils::WideString;

use crate::updater::io::remove_file_on_reboot;
use crate::updater::{AGENT_UPDATE_IN_PROGRESS, Product, UpdaterCtx, UpdaterError};

/// List of allowed thumbprints for Devolutions code signing certificates
const DEVOLUTIONS_CERT_THUMBPRINTS: &[&str] = &[
    "3f5202a9432d54293bdfe6f7e46adb0a6f8b3ba6",
    "8db5a43bb8afe4d2ffb92da9007d8997a4cc4e13",
    "50f753333811ff11f1920274afde3ffd4468b210",
];

/// Filename of the updater shim executable installed alongside the agent.
const AGENT_UPDATER_SHIM_NAME: &str = "DevolutionsAgentUpdater.exe";

pub(crate) async fn install_package(
    ctx: &UpdaterCtx,
    path: &Utf8Path,
    log_path: &Utf8Path,
) -> Result<(), UpdaterError> {
    match ctx.product {
        Product::Gateway | Product::HubService => install_msi(ctx, path, log_path).await,
        Product::Agent => install_agent_via_shim(ctx, path).await,
    }
}

pub(crate) async fn uninstall_package(
    ctx: &UpdaterCtx,
    product_code: Uuid,
    log_path: &Utf8Path,
) -> Result<(), UpdaterError> {
    match ctx.product {
        Product::Gateway | Product::HubService => uninstall_msi(ctx, product_code, log_path).await,
        // For agent self-update the shim handles uninstall + install in sequence; the
        // in-process uninstall step is skipped to avoid stopping the service prematurely.
        Product::Agent => Ok(()),
    }
}

/// Install a new version of Devolutions Agent by launching the updater shim as a detached process.
///
/// The shim (`devolutions-agent-updater.exe`) is copied to a temp location before being launched
/// so that the MSI installer can freely overwrite the agent installation directory. The shim
/// then runs `msiexec` silently, which stops the agent service, replaces its files, and
/// restarts it. Since the shim is detached from the agent service, it survives the service
/// restart and ensures the installation completes.
///
/// When `downgrade_product_code` is `Some` the shim will first run `msiexec /x` to uninstall
/// the currently installed version before running `msiexec /i` for the target version.
async fn install_agent_via_shim(ctx: &UpdaterCtx, msi_path: &Utf8Path) -> Result<(), UpdaterError> {
    let shim_path = find_agent_updater_shim()?;

    // Copy the shim to a temp location so it survives the MSI replacing the installation dir.
    let temp_shim_path = copy_shim_to_temp(&shim_path).await?;
    info!(%msi_path, %temp_shim_path, "Launching agent updater shim as detached process");

    // Schedule the temp shim copy for deletion at the next system reboot.
    if let Err(error) = remove_file_on_reboot(&temp_shim_path) {
        error!(%error, "Failed to schedule temp shim for deletion on reboot");
    }

    launch_updater_shim_detached(
        ctx,
        &temp_shim_path,
        msi_path,
        ctx.downgrade_product_code,
    ).await?;

    if ctx.downgrade_product_code.is_some() {
        info!("Agent updater shim launched; agent will be uninstalled then reinstalled at the target version");
    } else {
        info!("Agent updater shim launched; agent service will be updated and restarted shortly");
    }

    Ok(())
}

/// Locate the agent updater shim executable next to the running agent binary.
fn find_agent_updater_shim() -> Result<Utf8PathBuf, UpdaterError> {
    let exe_path = std::env::current_exe().map_err(UpdaterError::Io)?;

    let exe_path = Utf8PathBuf::from_path_buf(exe_path)
        .map_err(|_| UpdaterError::Io(std::io::Error::other("agent executable path contains invalid UTF-8")))?;

    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| UpdaterError::Io(std::io::Error::other("cannot determine agent executable directory")))?;

    let shim_path = exe_dir.join(AGENT_UPDATER_SHIM_NAME);

    if !shim_path.exists() {
        return Err(UpdaterError::AgentUpdaterShimNotFound { path: shim_path });
    }

    Ok(shim_path)
}

/// Copy the shim executable to a temporary path (UUID-named) so it can run independently of
/// the installation directory.
async fn copy_shim_to_temp(shim_path: &Utf8Path) -> Result<Utf8PathBuf, UpdaterError> {
    let temp_shim_path = Utf8PathBuf::from_path_buf(std::env::temp_dir())
        .expect("BUG: OS should always return valid UTF-8 temp path")
        .join(format!("{}-devolutions-agent-updater.exe", Uuid::new_v4()));

    tokio::fs::copy(shim_path, &temp_shim_path)
        .await
        .map_err(UpdaterError::Io)?;

    Ok(temp_shim_path)
}

/// Launch the updater shim and wait for it to finish, a shutdown signal, or a timeout.
///
/// Sets [`AGENT_UPDATE_IN_PROGRESS`] for the duration so any concurrent update attempts
/// are rejected. Clears the flag on timeout or unexpected shim exit, but NOT on shutdown:
/// when a shutdown signal is received the MSI is assumed to be making progress (it will
/// stop and restart the agent service), so the flag is left set until the process exits.
///
/// `DETACHED_PROCESS` disassociates the child from the parent's console.
/// `CREATE_NEW_PROCESS_GROUP` creates a new process group so that Ctrl+C signals from the
/// parent do not propagate to the child.
/// `CREATE_BREAKAWAY_FROM_JOB` removes the shim (and its children, including msiexec) from
/// the service's Windows Job Object.  Without this flag the shim inherits the per-service
/// Job Object that the SCM assigns to every service process.  When the MSI installer stops
/// the DevolutionsAgent service the SCM terminates that job, which kills the shim and its
/// msiexec child mid-installation, causing MSI rollback with errors 1923 / 1920.  The agent
/// runs as LocalSystem, which holds SeTcbPrivilege; that allows breakaway from any job
/// regardless of whether the job has JOB_OBJECT_LIMIT_BREAKAWAY_OK set.
///
/// When `downgrade_product_code` is `Some`, it is passed to the shim as `-x <product_code>`
/// (before the MSI path) so it can uninstall the old version before installing the new one.
async fn launch_updater_shim_detached(
    ctx: &UpdaterCtx,
    shim_path: &Utf8Path,
    msi_path: &Utf8Path,
    downgrade_product_code: Option<Uuid>,
) -> Result<(), UpdaterError> {
    use std::sync::atomic::Ordering;

    // Flags reference: https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const SHIM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10 * 60);

    // Reject concurrent agent updates.
    if AGENT_UPDATE_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(UpdaterError::AgentUpdateAlreadyInProgress);
    }

    let shim_log_path = shim_path.with_extension("shim.log");

    let mut cmd = tokio::process::Command::new(shim_path.as_str());
    if let Some(code) = downgrade_product_code {
        cmd.args(["-x", &code.braced().to_string()]);
    }
    cmd.arg(msi_path.as_str());
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
        .map_err(|source| UpdaterError::AgentShimLaunch { source })?;

    info!(%shim_log_path, "Waiting for agent updater shim to complete (or service shutdown)");

    let mut shutdown = ctx.shutdown_signal.clone();

    tokio::select! {
        result = child.wait() => {
            // The shim exited before the agent service was stopped by the MSI.
            // This is unexpected: the MSI should stop the service (killing us) before the
            // shim finishes. Treat any exit — successful or not — as a failure.
            let code = result.ok().and_then(|s| s.code()).unwrap_or(-1);
            AGENT_UPDATE_IN_PROGRESS.store(false, Ordering::Release);
            error!(
                %shim_log_path,
                exit_code = code,
                "Agent updater shim exited unexpectedly before the service was restarted; \
                 the update may not have completed. Check the shim log for details.",
            );
        }
        _ = tokio::time::sleep(SHIM_TIMEOUT) => {
            // Shim has been running for too long; something is wrong.
            AGENT_UPDATE_IN_PROGRESS.store(false, Ordering::Release);
            error!(
                %shim_log_path,
                timeout_secs = SHIM_TIMEOUT.as_secs(),
                "Agent updater shim timed out; the update may not have completed. \
                 Check the shim log for details.",
            );
        }
        _ = shutdown.wait() => {
            // The service is being stopped — most likely by the MSI installer as part of the
            // update process. Assume the update is proceeding correctly and exit cleanly.
            // AGENT_UPDATE_IN_PROGRESS is intentionally left `true`; the next agent instance
            // starts fresh and resets it via the static initialiser.
            info!("Shutdown signal received while waiting for updater shim; assuming MSI update is in progress");
        }
    }

    Ok(())
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

    match msi_install_result {
        Ok(status) => {
            let exit_code = status.code().unwrap_or(-1);

            // MSI exit codes:
            // 0 = Success
            // 3010 = Success but reboot required (unexpected - our installers shouldn't require reboot)
            // 1641 = Success and reboot initiated
            // Other codes = Error
            match exit_code {
                0 => {
                    info!("MSI installation completed successfully");
                    Ok(())
                }
                3010 | 1641 => {
                    // Our installers should not require a reboot, but if they do, log as warning
                    // and continue since the installation technically succeeded
                    warn!(
                        %exit_code,
                        "MSI installation completed but unexpectedly requires system reboot"
                    );
                    Ok(())
                }
                _ => {
                    error!(%exit_code, "MSI installation failed with exit code");
                    Err(UpdaterError::MsiInstall {
                        product: ctx.product,
                        msi_path: path.to_owned(),
                    })
                }
            }
        }
        Err(_) => {
            error!("Failed to execute msiexec command");
            Err(UpdaterError::MsiInstall {
                product: ctx.product,
                msi_path: path.to_owned(),
            })
        }
    }
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

    match msi_uninstall_result {
        Ok(status) => {
            let exit_code = status.code().unwrap_or(-1);

            // MSI exit codes:
            // 0 = Success
            // 3010 = Success but reboot required (unexpected - our installers shouldn't require reboot)
            // 1641 = Success and reboot initiated
            // Other codes = Error
            match exit_code {
                0 => {
                    info!(%product_code, "MSI uninstallation completed successfully");
                    Ok(())
                }
                3010 | 1641 => {
                    // Our installers should not require a reboot, but if they do, log as warning
                    // and continue since the uninstallation technically succeeded
                    warn!(
                        %exit_code,
                        %product_code,
                        "MSI uninstallation completed but unexpectedly requires system reboot"
                    );
                    Ok(())
                }
                _ => {
                    error!(%exit_code, %product_code, "MSI uninstallation failed with exit code");
                    Err(UpdaterError::MsiUninstall {
                        product: ctx.product,
                        product_code,
                    })
                }
            }
        }
        Err(_) => {
            error!(%product_code, "Failed to execute msiexec command");
            Err(UpdaterError::MsiUninstall {
                product: ctx.product,
                product_code,
            })
        }
    }
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
        Product::Gateway | Product::HubService | Product::Agent => validate_msi(ctx, path),
    }
}

fn validate_msi(ctx: &UpdaterCtx, path: &Utf8Path) -> Result<(), UpdaterError> {
    use windows::Win32::Security::Cryptography::{
        CALG_SHA1, CERT_CONTEXT, CertFreeCertificateContext, CryptHashCertificate,
    };
    use windows::Win32::System::ApplicationInstallationAndServicing::{
        MSI_INVALID_HASH_IS_FATAL, MsiGetFileSignatureInformationW,
    };

    // Allow skipping signature validation in debug mode
    if ctx.conf.get_conf().debug.skip_msi_signature_validation {
        warn!("DEBUG MODE: Skipping MSI signature validation");
        return Ok(());
    }

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
