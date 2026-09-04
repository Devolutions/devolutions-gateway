//! Shared test-only helpers used across this crate's unit tests.

use win_api_wrappers::identity::sid::Sid;
use windows::Win32::Security::WinLocalSystemSid;

/// The well-known SYSTEM SID: a deterministic, privilege-independent stand-in for a
/// trusted actor used throughout this crate's tests (SYSTEM is always a valid, resolvable
/// well-known SID, regardless of which account actually runs the tests).
pub(crate) fn system_sid() -> Sid {
    Sid::from_well_known(WinLocalSystemSid, None).expect("well-known SYSTEM SID")
}
