use super::process::Process;
use super::security::privilege::ScopedPrivileges;
use anyhow::Result;
use windows::Win32::Foundation::{CloseHandle, ERROR_NO_TOKEN, HANDLE};
use windows::Win32::Security::{SE_TCB_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;

/// Returns true if a user is logged in the provided session.
pub fn session_has_logged_in_user(session_id: u32) -> Result<bool> {
    let mut current_process_token = Process::current_process().token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;

    let mut _priv_tcb = ScopedPrivileges::enter(&mut current_process_token, &[SE_TCB_NAME])?;

    let mut handle = HANDLE::default();

    // SAFETY: `WTSQueryUserToken` is safe to call with a valid session id and handle memory ptr.
    match unsafe { WTSQueryUserToken(session_id, &mut handle as *mut _) } {
        Err(err) if err.code() == ERROR_NO_TOKEN.to_hresult() => Ok(false),
        Err(err) => Err(err.into()),
        Ok(()) => {
            // Close handle immediately.
            // SAFETY: `CloseHandle` is safe to call with a valid handle.
            unsafe { CloseHandle(handle).expect("BUG: WTSQueryUserToken should return a valid handle") };
            Ok(true)
        }
    }
}
