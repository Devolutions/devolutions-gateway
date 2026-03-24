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

fn main() {
    #[cfg(not(windows))]
    {
        eprintln!("devolutions-agent-updater is only supported on Windows");
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
    let msiexec_log_path = format!("{msi_path}.log");

    write_log(&shim_log_path, "devolutions-agent-updater: starting");
    write_log(&shim_log_path, &format!("  MSI path: {msi_path}"));
    write_log(&shim_log_path, &format!("  msiexec log: {msiexec_log_path}"));

    // For downgrades, uninstall the currently installed version first.
    if let Some(product_code) = uninstall_product_code {
        write_log(&shim_log_path, &format!("  Uninstalling product code: {product_code}"));

        let uninstall_log_path = format!("{msi_path}.uninstall.log");
        let status = std::process::Command::new("msiexec")
            .args(["/x", product_code, "/quiet", "/norestart", "/l*v", uninstall_log_path.as_str()])
            .status();

        match status {
            Ok(exit_status) => {
                let code = exit_status.code().unwrap_or(-1);
                match code {
                    0 | 3010 | 1641 => {
                        write_log(
                            &shim_log_path,
                            &format!("devolutions-agent-updater: uninstall completed with code {code} (success)"),
                        );
                    }
                    _ => {
                        write_log(
                            &shim_log_path,
                            &format!("devolutions-agent-updater: uninstall failed with exit code {code}"),
                        );
                        std::process::exit(code);
                    }
                }
            }
            Err(err) => {
                write_log(
                    &shim_log_path,
                    &format!("devolutions-agent-updater: failed to launch msiexec for uninstall: {err}"),
                );
                std::process::exit(1);
            }
        }
    }

    let status = std::process::Command::new("msiexec")
        .args([
            "/i",
            msi_path,
            "/quiet",
            "/norestart",
            "/l*v",
            msiexec_log_path.as_str(),
        ])
        .status();

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
                        &shim_log_path,
                        &format!("devolutions-agent-updater: msiexec completed with code {code} (success)"),
                    );
                }
                _ => {
                    write_log(
                        &shim_log_path,
                        &format!("devolutions-agent-updater: msiexec failed with exit code {code}"),
                    );
                    std::process::exit(code);
                }
            }
        }
        Err(err) => {
            write_log(
                &shim_log_path,
                &format!("devolutions-agent-updater: failed to launch msiexec: {err}"),
            );
            std::process::exit(1);
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

fn write_to_stderr(msg: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    writeln!(std::io::stderr(), "{msg}")
}
