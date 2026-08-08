//! Process creation helpers for Windows execution.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use chrono::Utc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use win_api_wrappers::process::{self, StartupInfo};
use win_api_wrappers::security::attributes::SecurityAttributesInit;
use win_api_wrappers::token::Token;
use win_api_wrappers::utils::{self, CommandLine, Pipe, WideString};
use windows::Win32::Foundation::WAIT_TIMEOUT;
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, NORMAL_PRIORITY_CLASS, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::broker::executor::{
    ExecutionOutput, MAX_CAPTURED_OUTPUT_BYTES, OperationCanceled, ProcessStartedCallback, tail_utf8,
};
use crate::broker::operation_tracker::OperationTracker;
use crate::broker::policy_security;

/// How long a canceled process is given to exit after the graceful console
/// ctrl event before it is forcefully terminated.
const CANCEL_GRACE_PERIOD: Duration = Duration::from_secs(60);

/// Granularity of the wait loop used to observe Cancellation requests.
const WAIT_SLICE_MS: u32 = 500;

/// Create a process under the given token and wait for exit.
///
/// This is the unified process-creation path used by both SYSTEM and current-user modes.
/// The process always runs with no visible window (`STARTF_USESHOWWINDOW` + `SW_HIDE`, the
/// same approach `devolutions-session` uses). When `capture` is true, the child's
/// stdout+stderr are redirected into a single pipe and returned (tail-truncated to
/// [`crate::broker::executor::MAX_CAPTURED_OUTPUT_BYTES`]); otherwise no output is captured.
///
/// Returns the process exit code and (when captured) its output.
///
/// When `cancel` is provided and fires while the process is running, the process is
/// stopped (gracefully first, forcefully after [`CANCEL_GRACE_PERIOD`]) and an error
/// chain containing [`OperationCanceled`] is returned.
#[allow(clippy::cast_possible_wrap)]
pub(super) fn create_process(
    token: &Token,
    command: &[String],
    session_id: u32,
    capture: bool,
    requires_elevation: bool,
    process_started: Option<ProcessStartedCallback>,
    cancel: Option<&CancellationToken>,
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
    // `_exe_guard` (when elevation is required) keeps the verified executable locked
    // against modification and replacement until this function returns, i.e. after the
    // spawned process has finished.
    let (resolved_exe, _exe_guard) = resolve_executable(exe_name, &user_env, requires_elevation)?;

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

    // `CREATE_NEW_PROCESS_GROUP` makes the child's PID a process group ID so a
    // console ctrl event can later target the whole group for graceful Cancellation.
    let creation_flags = CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP | NORMAL_PRIORITY_CLASS;

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

    let deadline = Instant::now() + OperationTracker::operation_timeout();
    // INVARIANT: whenever the loop breaks, the process has exited (or was terminated),
    // so the capture reader below observes EOF and joining it cannot block.
    let outcome = loop {
        if let Some(cancel) = cancel
            && cancel.is_cancelled()
        {
            stop_canceled_process(&process_info, session_id)?;
            break WaitOutcome::Canceled;
        }

        if process_info
            .process
            .wait(Some(WAIT_SLICE_MS))
            .context("failed to wait for process")?
            != WAIT_TIMEOUT
        {
            break WaitOutcome::Exited;
        }

        if Instant::now() >= deadline {
            warn!(
                session_id,
                pid = process_info.process_id,
                "Process timed out; terminating"
            );
            process_info
                .process
                .terminate(1)
                .context("failed to terminate timed-out process")?;
            let _ = process_info.process.wait(None);
            break WaitOutcome::TimedOut;
        }
    };

    // Join the reader thread on every outcome so it is never left detached.
    let stdout = match reader {
        Some(handle) => tail_utf8(&handle.join().unwrap_or_default()),
        None => String::new(),
    };

    match outcome {
        WaitOutcome::Canceled => Err(anyhow::Error::new(OperationCanceled)),
        WaitOutcome::TimedOut => bail!(
            "operation timed out after {} seconds",
            OperationTracker::operation_timeout().as_secs()
        ),
        WaitOutcome::Exited => {
            let exit_code = process_info
                .process
                .exit_code()
                .context("failed to get process exit code")?;

            Ok(ExecutionOutput {
                exit_code: exit_code as i32,
                stdout,
                started_at: Some(started_at),
            })
        }
    }
}

/// How the wait loop in [`create_process`] concluded.
enum WaitOutcome {
    /// The process exited on its own.
    Exited,
    /// The operation was canceled and the process was stopped.
    Canceled,
    /// The operation timeout elapsed and the process was terminated.
    TimedOut,
}

/// Resolve an executable name to its full path using the given environment's PATH.
///
/// Handles both absolute paths and bare names (e.g., `winget.exe`).
/// Appends `.exe` if no extension is present and the file is not found as-is.
///
/// When `requires_elevation` is true (the command will run with an elevated or
/// machine-scope token), the resolved executable must additionally be writable only by
/// trusted principals (SYSTEM, built-in Administrators, or TrustedInstaller); otherwise
/// a standard user could replace the binary (e.g. via a weakly-ACL'd `%ProgramData%`
/// install root) and have the broker launch it with elevated privileges. In that case
/// the returned path is the final path pinned by the returned
/// [`policy_security::VerifiedExecutable`] guard, which must be kept alive until the
/// process has been spawned so the verified binary cannot be swapped in between. This
/// check is skipped for non-elevated executions, since per-user tool installs (pip
/// venvs, `~/.cargo`, etc.) are not admin-owned.
fn resolve_executable(
    exe_name: &str,
    env: &std::collections::HashMap<String, String>,
    requires_elevation: bool,
) -> anyhow::Result<(PathBuf, Option<policy_security::VerifiedExecutable>)> {
    let exe_path = Path::new(exe_name);

    // If already an absolute path, just verify it exists.
    if exe_path.is_absolute() {
        if exe_path.exists() {
            let guard = policy_security::verify_elevated_executable_security(exe_path, requires_elevation)?;
            let resolved = guard
                .as_ref()
                .map_or_else(|| exe_path.to_owned(), |g| g.path().to_owned());
            return Ok((resolved, guard));
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
                let guard = policy_security::verify_elevated_executable_security(&candidate, requires_elevation)?;
                let resolved = guard.as_ref().map_or(candidate, |g| g.path().to_owned());
                return Ok((resolved, guard));
            }
        }
    }

    bail!("trusted executable '{exe_name}' not found in target user PATH");
}

/// Stop a process whose operation was canceled.
///
/// Attempts a graceful stop first by delivering a `CTRL_BREAK_EVENT` to the child's
/// process group, then waits up to [`CANCEL_GRACE_PERIOD`] for the process to exit.
/// If the event cannot be delivered or the grace period elapses, the root process is
/// forcefully terminated.
fn stop_canceled_process(process_info: &process::ProcessInformation, session_id: u32) -> anyhow::Result<()> {
    let pid = process_info.process_id;
    info!(session_id, pid, "Cancellation requested; stopping process");

    match send_ctrl_break(pid) {
        Ok(()) => {
            let grace_ms = u32::try_from(CANCEL_GRACE_PERIOD.as_millis()).expect("grace period fits into u32");
            if process_info
                .process
                .wait(Some(grace_ms))
                .context("failed to wait for canceled process")?
                != WAIT_TIMEOUT
            {
                info!(session_id, pid, "Canceled process exited after ctrl event");
                return Ok(());
            }
            warn!(session_id, pid, "Canceled process ignored ctrl event; terminating");
        }
        Err(error) => {
            warn!(
                session_id,
                pid,
                error = format!("{error:#}"),
                "Failed to deliver ctrl event to canceled process; terminating"
            );
        }
    }

    process_info
        .process
        .terminate(1)
        .context("failed to terminate canceled process")?;
    let _ = process_info.process.wait(None);
    info!(session_id, pid, "Canceled process terminated");

    Ok(())
}

/// Deliver a `CTRL_BREAK_EVENT` to the process group identified by `pid`.
///
/// Console attachment is per-process state, so concurrent deliveries are serialized.
/// The broker temporarily attaches to the child's console; the event only targets the
/// child's process group (the broker is not part of it), so the broker is unaffected.
fn send_ctrl_break(pid: u32) -> anyhow::Result<()> {
    use windows::Win32::System::Console::{AttachConsole, CTRL_BREAK_EVENT, FreeConsole, GenerateConsoleCtrlEvent};

    static CONSOLE_LOCK: Mutex<()> = Mutex::new(());

    let _guard = CONSOLE_LOCK.lock().expect("console lock poisoned");

    // SAFETY: FFI call with no outstanding preconditions; detaching from a console we
    // are not attached to simply fails and is ignored.
    unsafe {
        let _ = FreeConsole();
    }

    // SAFETY: FFI call with no outstanding preconditions; `pid` identifies the target
    // process whose console we attach to, failure is reported as an error.
    unsafe { AttachConsole(pid) }.context("AttachConsole failed")?;

    // SAFETY: FFI call with no outstanding preconditions; the calling process is
    // attached to the target console and `pid` is a process group ID because the child
    // was created with `CREATE_NEW_PROCESS_GROUP`.
    let result = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) }.context("GenerateConsoleCtrlEvent failed");

    // SAFETY: FFI call with no outstanding preconditions; detach from the child's console.
    unsafe {
        let _ = FreeConsole();
    }

    result
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::security::acl::{
        Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee, set_named_security_info,
    };
    use win_api_wrappers::str::U16CString;
    use windows::Win32::Foundation::GENERIC_ALL;
    use windows::Win32::Security::Authorization::{GRANT_ACCESS, SE_FILE_OBJECT};
    use windows::Win32::Security::{NO_INHERITANCE, WinWorldSid};

    use super::*;

    fn grant(permissions: u32, sid: Sid) -> ExplicitAccess {
        ExplicitAccess {
            access_permissions: permissions,
            access_mode: GRANT_ACCESS,
            inheritance: NO_INHERITANCE,
            trustee: Trustee::Sid(sid),
        }
    }

    fn make_everyone_writable(path: &Path) {
        let everyone = Sid::from_well_known(WinWorldSid, None).expect("well-known Everyone SID");
        let dacl = InheritableAcl {
            kind: InheritableAclKind::Protected,
            acl: Acl::new()
                .and_then(|acl| acl.set_entries(&[grant(GENERIC_ALL.0, everyone)]))
                .expect("build ACL with Everyone full-control entry"),
        };
        let name = U16CString::from_os_str(path.as_os_str()).expect("no interior NUL in temp path");
        set_named_security_info(&name, SE_FILE_OBJECT, None, None, Some(&dacl), None)
            .expect("set everyone-writable DACL");
    }

    #[test]
    fn elevated_execution_rejects_everyone_writable_absolute_executable() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let exe = temp_dir.path().join("fake.exe");
        std::fs::write(&exe, b"").expect("write fake executable");
        make_everyone_writable(&exe);

        let env = HashMap::new();
        let error = resolve_executable(&exe.display().to_string(), &env, true)
            .expect_err("an everyone-writable executable must be rejected when it will run with an elevated token");
        assert!(
            error.to_string().contains("elevated package-manager executable"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn non_elevated_execution_allows_everyone_writable_absolute_executable() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let exe = temp_dir.path().join("fake.exe");
        std::fs::write(&exe, b"").expect("write fake executable");
        make_everyone_writable(&exe);

        let env = HashMap::new();
        let (resolved, guard) = resolve_executable(&exe.display().to_string(), &env, false)
            .expect("non-elevated executables are not subject to the admin-only-writable check");
        assert_eq!(resolved, exe);
        assert!(guard.is_none(), "no guard is produced for non-elevated executions");
    }
}
