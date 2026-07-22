//! Process creation helpers for Windows execution.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use chrono::Utc;
use tracing::{debug, error, info, warn};
use win_api_wrappers::process::{self, StartupInfo};
use win_api_wrappers::security::attributes::SecurityAttributesInit;
use win_api_wrappers::token::Token;
use win_api_wrappers::utils::{self, CommandLine, Pipe, WideString};
use windows::Win32::Foundation::WAIT_TIMEOUT;
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, NORMAL_PRIORITY_CLASS, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::broker::executor::{ExecutionOutput, MAX_CAPTURED_OUTPUT_BYTES, ProcessStartedCallback, tail_utf8};
use crate::broker::operation_tracker::OperationTracker;

/// Create a process under the given token and wait for exit.
///
/// This is the unified process-creation path used by both SYSTEM and current-user modes.
/// The process always runs with no visible window (`STARTF_USESHOWWINDOW` + `SW_HIDE`, the
/// same approach `devolutions-session` uses). When `capture` is true, the child's
/// stdout+stderr are redirected into a single pipe and returned (tail-truncated to
/// [`crate::broker::executor::MAX_CAPTURED_OUTPUT_BYTES`]); otherwise no output is captured.
///
/// Returns the process exit code and (when captured) its output.
#[allow(clippy::cast_possible_wrap)]
pub(super) fn create_process(
    token: &Token,
    command: &[String],
    session_id: u32,
    capture: bool,
    process_started: Option<ProcessStartedCallback>,
) -> anyhow::Result<ExecutionOutput> {
    let cmd_line = CommandLine::new(command.to_vec());

    debug!(session_id, capture, "Building process creation parameters");

    // Resolve the executable using the user's environment PATH.
    // CreateProcessAsUserW searches the CALLING process's PATH (SYSTEM) to find the
    // executable, not the child's environment block. Since tools like winget.exe live
    // in per-user directories (e.g. %LOCALAPPDATA%\Microsoft\WindowsApps), we must
    // resolve the full path ourselves using the user's environment.
    let user_env = utils::environment_block(Some(token), false).context("failed to load user environment block")?;

    let exe_name = command.first().context("empty command")?;
    let resolved_exe = resolve_executable(exe_name, &user_env)?;

    info!(
        exe = %resolved_exe.display(),
        "Resolved executable path from user environment"
    );

    // The window is always hidden. `WinSta0\Default` keeps the process on the interactive
    // desktop; `SW_HIDE` keeps any console it allocates invisible.
    let mut startup_info = StartupInfo {
        desktop: WideString::from("WinSta0\\Default"),
        flags: STARTF_USESHOWWINDOW,
        show_window: u16::try_from(SW_HIDE.0).expect("SW_HIDE fits into u16"),
        ..Default::default()
    };

    // Capture pipes are only set up when requested. They must be kept alive through
    // process creation, and the child's ends closed afterwards so the reader sees EOF.
    let inheritable = SecurityAttributesInit {
        inherit_handle: true,
        ..Default::default()
    }
    .init();
    let (output_read, held_output_write, held_stdin_read) = if capture {
        let (out_read, out_write) =
            Pipe::new_anonymous(Some(&inheritable), 0).context("failed to create output capture pipe")?;
        // Empty stdin (write end closed immediately so the child reads EOF).
        let (in_read, in_write) = Pipe::new_anonymous(Some(&inheritable), 0).context("failed to create stdin pipe")?;
        drop(in_write);

        startup_info.flags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup_info.std_input = in_read.handle.raw();
        startup_info.std_output = out_write.handle.raw();
        startup_info.std_error = out_write.handle.raw();

        (Some(out_read), Some(out_write), Some(in_read))
    } else {
        (None, None, None)
    };

    let creation_flags = CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS;

    debug!("Calling process::create_process_as_user");

    let process_info = match process::create_process_as_user(
        Some(token),
        Some(&resolved_exe),
        Some(&cmd_line),
        None,
        None,
        // Inherit handles only when capturing (so the child receives the pipe ends).
        capture,
        creation_flags,
        Some(&user_env),
        None,
        &mut startup_info,
    ) {
        Ok(info) => info,
        Err(error) => {
            error!(
                error = format!("{error:#}"),
                exe = %resolved_exe.display(),
                session_id,
                "create_process_as_user failed"
            );
            return Err(error).with_context(|| {
                format!(
                    "CreateProcessAsUserW failed for '{}' (session {})",
                    resolved_exe.display(),
                    session_id
                )
            });
        }
    };
    let started_at = Utc::now();
    if let Some(process_started) = process_started {
        process_started(started_at);
    }

    // Close our copies of the child's handles so the read end observes EOF on exit.
    drop(held_output_write);
    drop(held_stdin_read);

    info!(
        session_id,
        pid = process_info.process_id,
        capture,
        "Process spawned, waiting for exit"
    );

    // Drain the pipe on a separate thread so a child producing more output than the pipe
    // buffer can hold does not deadlock against our wait-for-exit.
    let reader = output_read.map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => {
                        buffer.extend_from_slice(&chunk[..read]);
                        if buffer.len() > MAX_CAPTURED_OUTPUT_BYTES {
                            let excess = buffer.len() - MAX_CAPTURED_OUTPUT_BYTES;
                            buffer.drain(..excess);
                        }
                    }
                    Err(_) => break,
                }
            }
            buffer
        })
    });

    let timeout_ms = operation_timeout_ms();
    if process_info
        .process
        .wait(Some(timeout_ms))
        .context("failed to wait for process")?
        == WAIT_TIMEOUT
    {
        warn!(
            session_id,
            pid = process_info.process_id,
            timeout_ms,
            "Process timed out; terminating"
        );
        process_info
            .process
            .terminate(1)
            .context("failed to terminate timed-out process")?;
        let _ = process_info.process.wait(None);
        bail!(
            "operation timed out after {} seconds",
            OperationTracker::operation_timeout().as_secs()
        );
    }

    let exit_code = process_info
        .process
        .exit_code()
        .context("failed to get process exit code")?;

    let stdout = match reader {
        Some(handle) => tail_utf8(&handle.join().unwrap_or_default()),
        None => String::new(),
    };

    Ok(ExecutionOutput {
        exit_code: exit_code as i32,
        stdout,
        started_at: Some(started_at),
    })
}

/// Resolve an executable name to its full path using the given environment's PATH.
///
/// Handles both absolute paths and bare names (e.g., `winget.exe`).
/// Appends `.exe` if no extension is present and the file is not found as-is.
fn resolve_executable(exe_name: &str, env: &std::collections::HashMap<String, String>) -> anyhow::Result<PathBuf> {
    let exe_path = Path::new(exe_name);

    // If already an absolute path, just verify it exists.
    if exe_path.is_absolute() {
        if exe_path.exists() {
            return Ok(exe_path.to_owned());
        }
        bail!("executable not found at absolute path: {}", exe_path.display());
    }

    if !exe_name.eq_ignore_ascii_case("winget.exe") {
        bail!("broker command executable must be an absolute path: {exe_name}");
    }

    // Get PATH from environment (case-insensitive key lookup).
    let path_var = env
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();

    let extensions: &[&str] = if exe_path.extension().is_some() {
        &[""]
    } else {
        &["", ".exe", ".cmd", ".bat", ".com"]
    };

    for dir in path_var.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }
        for ext in extensions {
            let mut candidate = PathBuf::from(dir);
            let file_name = format!("{}{}", exe_name, ext);
            candidate.push(&file_name);
            if candidate.exists() && is_trusted_winget_path(&candidate, env) {
                return Ok(candidate);
            }
        }
    }

    bail!("trusted executable '{exe_name}' not found in target user PATH");
}

fn operation_timeout_ms() -> u32 {
    u32::try_from(OperationTracker::operation_timeout().as_millis()).unwrap_or(u32::MAX)
}

fn is_trusted_winget_path(candidate: &Path, env: &std::collections::HashMap<String, String>) -> bool {
    if !candidate
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("winget.exe"))
    {
        return false;
    }

    let candidate = candidate.as_os_str().to_string_lossy().to_lowercase();
    let program_files = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("ProgramFiles"))
        .map(|(_, value)| value)
        .map_or(r"C:\Program Files", |value| value)
        .to_lowercase();
    let local_app_data = env
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("LOCALAPPDATA"))
        .map(|(_, value)| value.to_lowercase());

    candidate.starts_with(&format!("{program_files}\\windowsapps\\"))
        || local_app_data.is_some_and(|path| candidate == format!("{path}\\microsoft\\windowsapps\\winget.exe"))
}
