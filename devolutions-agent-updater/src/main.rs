//! Devolutions Agent Updater shim.
//!
//! This minimal executable is launched as a detached process by the Devolutions Agent service
//! to perform a silent MSI update of Devolutions Agent itself.
//!
//! Running as a detached process is necessary because the MSI installer stops and restarts
//! the Devolutions Agent Windows service during installation. If the agent tried to call
//! msiexec directly and wait for it, the agent would be killed mid-update. By launching
//! this shim as a detached process, the shim survives the agent service restart and
//! ensures the MSI installation completes successfully.
//!
//! # Usage
//!
//! ```text
//! devolutions-agent-updater [-x <product_code_to_uninstall>] <msi_path>
//! ```
//!
//! When `-x <product_code_to_uninstall>` is provided (a braced GUID such as
//! `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`), the shim first runs
//! `msiexec /x` to uninstall the currently installed version and then runs
//! `msiexec /i` to install the target version.  This is required for downgrades
//! because MSI upgrade conditions prevent installing an older version on top of
//! a newer one.

// Suppress the console window in release builds. In debug builds, we keep the console for
// visibility when running from a terminal during development.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use win_api_wrappers::service::{ServiceManager, ServiceStartupMode};

#[cfg(windows)]
const AGENT_SERVICE_NAME: &str = "DevolutionsAgent";

#[cfg(windows)]
struct AgentServiceState {
    was_running: bool,
    startup_was_automatic: bool,
}

fn main() {
    #[cfg(not(windows))]
    {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "devolutions-agent-updater is only supported on Windows"
        );
        std::process::exit(1);
    }

    #[cfg(windows)]
    windows_main();
}

#[cfg(windows)]
fn windows_main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        let _ = write_to_stderr("Usage: devolutions-agent-updater [-x <product_code>] <msi_path>");
        std::process::exit(1);
    }

    // Parse optional -x <product_code> flag before the positional MSI path.
    let (uninstall_product_code, msi_path) = {
        let mut iter = args.iter().skip(1).peekable();
        let product_code = if iter.peek().map(|s| s.as_str()) == Some("-x") {
            iter.next(); // consume "-x"
            let code = iter.next().map(String::as_str);
            if code.is_none() {
                let _ = write_to_stderr("Error: -x requires a product code argument");
                std::process::exit(1);
            }
            code
        } else {
            None
        };
        let msi = match iter.next() {
            Some(s) => s.as_str(),
            None => {
                let _ = write_to_stderr("Usage: devolutions-agent-updater [-x <product_code>] <msi_path>");
                std::process::exit(1);
            }
        };
        (product_code, msi)
    };

    // Derive paths from the MSI path.
    // The shim log uses a separate extension so it doesn't conflict with the msiexec log.
    let shim_log_path = format!("{msi_path}.shim.log");
    let install_log_path = format!("{msi_path}.install.log");

    write_log(&shim_log_path, "devolutions-agent-updater: starting");
    write_log(&shim_log_path, &format!("  MSI path: {msi_path}"));
    write_log(&shim_log_path, &format!("  Install log: {install_log_path}"));

    // Capture agent service state before the update so we can restore it afterwards.
    let service_state = match query_agent_service_state() {
        Ok(state) => {
            write_log(
                &shim_log_path,
                &format!(
                    "Agent service state: running={}, automatic_startup={}",
                    state.was_running, state.startup_was_automatic
                ),
            );
            Some(state)
        }
        Err(e) => {
            write_log(&shim_log_path, &format!("Failed to query agent service state: {e:#}"));
            None
        }
    };

    let exit_code = run_update(
        uninstall_product_code,
        msi_path,
        &shim_log_path,
        &install_log_path,
        service_state.as_ref(),
    );

    // Always mark the shim log for deletion on the next reboot (best-effort).
    mark_file_for_deletion_on_reboot(&shim_log_path);

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

/// Run the optional uninstall followed by the MSI install.
///
/// Returns 0 on success or a non-zero msiexec exit code on failure.
#[cfg(windows)]
fn run_update(
    uninstall_product_code: Option<&str>,
    msi_path: &str,
    shim_log_path: &str,
    install_log_path: &str,
    service_state: Option<&AgentServiceState>,
) -> i32 {
    // For downgrades, uninstall the currently installed version first.
    if let Some(product_code) = uninstall_product_code {
        write_log(shim_log_path, &format!("  Uninstalling product code: {product_code}"));

        let uninstall_log_path = format!("{msi_path}.uninstall.log");
        let status = std::process::Command::new("msiexec")
            .args([
                "/x",
                product_code,
                "/quiet",
                "/norestart",
                "/l*v",
                uninstall_log_path.as_str(),
            ])
            .status();

        // Mark the uninstall log for deletion on reboot regardless of the msiexec result.
        mark_file_for_deletion_on_reboot(&uninstall_log_path);

        match status {
            Ok(exit_status) => {
                let code = exit_status.code().unwrap_or(-1);
                match code {
                    0 | 3010 | 1641 => {
                        write_log(
                            shim_log_path,
                            &format!("devolutions-agent-updater: uninstall completed with code {code} (success)"),
                        );
                    }
                    _ => {
                        write_log(
                            shim_log_path,
                            &format!("devolutions-agent-updater: uninstall failed with exit code {code}"),
                        );
                        return code;
                    }
                }
            }
            Err(err) => {
                write_log(
                    shim_log_path,
                    &format!("devolutions-agent-updater: failed to launch msiexec for uninstall: {err}"),
                );
                return 1;
            }
        }
    }

    let status = std::process::Command::new("msiexec")
        .args(["/i", msi_path, "/quiet", "/norestart", "/l*v", install_log_path])
        .status();

    // Mark the install log for deletion on reboot regardless of the msiexec result.
    mark_file_for_deletion_on_reboot(install_log_path);

    match status {
        Ok(exit_status) => {
            let code = exit_status.code().unwrap_or(-1);

            // MSI exit codes:
            // 0    = Success
            // 3010 = Success (reboot required, but our installers shouldn't need a reboot)
            // 1641 = Success (reboot initiated)
            match code {
                0 | 3010 | 1641 => {
                    write_log(
                        shim_log_path,
                        &format!("devolutions-agent-updater: msiexec completed with code {code} (success)"),
                    );
                    // Post-update: restore service running state when startup mode is manual.
                    if let Some(state) = service_state {
                        match start_agent_service_if_needed(state) {
                            Ok(true) => write_log(shim_log_path, "Agent service started successfully"),
                            Ok(false) => {}
                            Err(e) => write_log(shim_log_path, &format!("Failed to start agent service: {e:#}")),
                        }
                    }
                    0
                }
                _ => {
                    write_log(
                        shim_log_path,
                        &format!("devolutions-agent-updater: msiexec failed with exit code {code}"),
                    );
                    code
                }
            }
        }
        Err(err) => {
            write_log(
                shim_log_path,
                &format!("devolutions-agent-updater: failed to launch msiexec: {err}"),
            );
            1
        }
    }
}

/// Append a line to a log file, ignoring errors (best-effort logging).
#[cfg(windows)]
fn write_log(path: &str, msg: &str) {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{msg}");
    }
}

#[cfg(windows)]
fn write_to_stderr(msg: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    writeln!(std::io::stderr(), "{msg}")
}

#[cfg(windows)]
fn mark_file_for_deletion_on_reboot(path: &str) {
    if let Err(error) = win_api_wrappers::fs::remove_file_on_reboot(Path::new(path)) {
        let _ = write_to_stderr(&format!("Failed to mark file for deletion on reboot: {error:#}"));
    }
}

#[cfg(windows)]
fn query_agent_service_state() -> anyhow::Result<AgentServiceState> {
    let sm = ServiceManager::open_read()?;
    let svc = sm.open_service_read(AGENT_SERVICE_NAME)?;
    Ok(AgentServiceState {
        startup_was_automatic: svc.startup_mode()? == ServiceStartupMode::Automatic,
        was_running: svc.is_running()?,
    })
}

#[cfg(windows)]
fn start_agent_service_if_needed(state: &AgentServiceState) -> anyhow::Result<bool> {
    if state.startup_was_automatic || !state.was_running {
        return Ok(false);
    }

    let sm = ServiceManager::open_all_access()?;
    let svc = sm.open_service_all_access(AGENT_SERVICE_NAME)?;
    svc.start()?;
    Ok(true)
}
