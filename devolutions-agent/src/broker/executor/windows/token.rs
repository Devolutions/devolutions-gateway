//! Token and session helpers for Windows execution.

use anyhow::{Context as _, bail};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use win_api_wrappers::token::{Token, TokenElevationType};
use win_api_wrappers::wts;
use windows::Win32::Security::{SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_QUERY, TokenPrimary};

/// Detect whether the current process is running under the SYSTEM account.
///
/// Compares the process token SID against S-1-5-18 (LocalSystem).
pub(super) fn detect_running_as_system() -> bool {
    let Ok(token) = Process::current_process().token(TOKEN_QUERY) else {
        return false;
    };

    let Ok(sid_and_attrs) = token.sid_and_attributes() else {
        return false;
    };

    let Ok(system_sid) = Sid::from_well_known(windows::Win32::Security::WinLocalSystemSid, None) else {
        return false;
    };

    sid_and_attrs.sid == system_sid
}

pub(super) fn duplicate_as_primary(token: &Token) -> anyhow::Result<Token> {
    token.duplicate(TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary)
}

/// Enumerate WTS sessions to find one belonging to `effective_user`.
///
/// `effective_user` can be `DOMAIN\user` or just `user`.
pub(super) fn find_user_session(effective_user: &str) -> anyhow::Result<u32> {
    let target_username = effective_user
        .rsplit('\\')
        .next()
        .unwrap_or(effective_user)
        .to_lowercase();

    let sessions = wts::get_sessions().context("failed to enumerate WTS sessions")?;

    for session in &sessions {
        if session.session_id == 0 {
            continue;
        }

        if let Ok(session_user) = wts::get_session_user_name(session.session_id)
            && session_user.to_lowercase() == target_username
        {
            return Ok(session.session_id);
        }
    }

    anyhow::bail!("no active session found for user '{effective_user}'")
}

/// Attempt to obtain an elevated (linked) token from a filtered/limited token.
///
/// On UAC-enabled systems with split tokens, the standard user token has a linked
/// elevated token. This function retrieves it when elevation is requested.
pub(super) fn get_elevated_token(token: &Token) -> anyhow::Result<Token> {
    let elevation_type = token.elevation_type().context("failed to query elevation type")?;

    match elevation_type {
        TokenElevationType::Full => {
            // Already elevated — duplicate as primary.
            duplicate_as_primary(token).context("failed to duplicate full token")
        }
        TokenElevationType::Limited => {
            // Obtain the linked (elevated) token and duplicate as primary.
            let linked = token.linked_token().context("failed to get linked token")?;
            duplicate_as_primary(&linked).context("failed to duplicate linked token")
        }
        TokenElevationType::Default => {
            bail!("token elevation type is Default; cannot elevate (UAC may be disabled)");
        }
    }
}
