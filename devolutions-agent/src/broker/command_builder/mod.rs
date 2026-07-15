//! Command-line builders for package manager operations.
//!
//! Constructs the commands the broker would execute from validated request fields.
//! The broker never executes client-supplied commands directly.

pub mod powershell;
pub mod winget;

use now_policy_api::{ManagerName, PackageRequest};

/// Build a command line from a validated request, dispatching to the appropriate
/// package manager builder.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    match request.manager {
        ManagerName::Winget => Ok(winget::build_winget_command(request)),
        ManagerName::PowerShell => powershell::build_powershell5_command(request),
        ManagerName::PowerShell7 => powershell::build_powershell7_command(request),
    }
}

/// Append `--flag value` to command if value is `Some` and non-empty.
pub(crate) fn set_if_specified(command: &mut Vec<String>, flag: &str, value: Option<&str>) {
    if let Some(v) = value
        && !v.is_empty()
    {
        command.push(flag.to_owned());
        command.push(v.to_owned());
    }
}

/// Append `--flag` to command if value is true.
pub(crate) fn set_if_true(command: &mut Vec<String>, flag: &str, value: bool) {
    if value {
        command.push(flag.to_owned());
    }
}
