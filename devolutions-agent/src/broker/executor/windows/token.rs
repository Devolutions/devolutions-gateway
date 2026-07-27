//! Token and session helpers for Windows execution.

use anyhow::{Context as _, bail};
use tracing::debug;
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

/// Enumerate WTS sessions to find the active one whose user token belongs to `user_sid`.
///
/// Matching is performed on the session token user SID rather than on the
/// `DOMAIN\username` display strings, so distinct accounts sharing the same
/// name (e.g. `MACHINE\alice` vs `DOMAIN\alice`) cannot be confused.
///
/// Returns the session ID together with the session user token.
/// The caller must have the SeTcb privilege enabled (required by `WTSQueryUserToken`).
pub(super) fn find_user_session(user_sid: &Sid) -> anyhow::Result<(u32, Token)> {
    let sessions = wts::get_sessions().context("failed to enumerate WTS sessions")?;

    for session in &sessions {
        if session.session_id == 0 {
            continue;
        }
        if session.state != wts::WTSConnectState::Active {
            continue;
        }

        // Sessions without a logged-in user (or otherwise unqueryable) are skipped.
        let token = match Token::for_session(session.session_id) {
            Ok(token) => token,
            Err(error) => {
                debug!(session_id = session.session_id, %error, "Skipping session: failed to query user token");
                continue;
            }
        };

        match token.sid_and_attributes() {
            Ok(sid_and_attributes) if sid_and_attributes.sid == *user_sid => {
                return Ok((session.session_id, token));
            }
            Ok(_) => {}
            Err(error) => {
                debug!(session_id = session.session_id, %error, "Skipping session: failed to query token user SID");
            }
        }
    }

    bail!("no active session found for user SID '{user_sid}'")
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
