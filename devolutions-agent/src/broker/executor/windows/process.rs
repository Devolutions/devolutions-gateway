//! Process creation helpers for Windows execution.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use tracing::{debug, error, info};
use win_api_wrappers::process::{self, StartupInfo};
use win_api_wrappers::security::attributes::SecurityAttributesInit;
use win_api_wrappers::token::Token;
use win_api_wrappers::utils::{self, CommandLine, Pipe, WideString};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, NORMAL_PRIORITY_CLASS, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::broker::executor::{ExecutionOutput, tail_utf8};

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
) -> anyhow::Result<ExecutionOutput> {
    let cmd_line = CommandLine::new(command.to_vec());

    debug!(
        command_line = %command.join(" "),
        session_id,
        capture,
        "Building process creation parameters"
    );

    // Resolve the executable using the user's environment PATH.
    // CreateProcessAsUserW searches the CALLING process's PATH (SYSTEM) to find the
    // executable, not the child's environment block. Since tools like winget.exe live
    // in per-user directories (e.g. %LOCALAPPDATA%\Microsoft\WindowsApps), we must
    // resolve the full path ourselves using the user's environment.
    let user_env = utils::environment_block(Some(token), false).context("failed to load user environment block")?;

    let exe_name = command.first().context("empty command")?;
    let resolved_exe = resolve_executable(exe_name, &user_env).with_context(|| {
        format!(
            "could not find '{}' in user's PATH: {:?}",
            exe_name,
            user_env.get("Path").or_else(|| user_env.get("PATH"))
        )
    })?;

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
                command_line = %command.join(" "),
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
            let _ = pipe.read_to_end(&mut buffer);
            buffer
        })
    });

    // Wait for the process to exit (no timeout; the server enforces an overall timeout).
    process_info.process.wait(None).context("failed to wait for process")?;

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
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    bail!("executable '{}' not found in PATH", exe_name);
}
