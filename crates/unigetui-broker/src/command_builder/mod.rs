//! Command-line builders for package manager operations.
//!
//! Constructs the commands the broker would execute from validated request fields.
//! The broker never executes client-supplied commands directly.

pub mod winget;

use crate::model::PackageRequest;

/// Build a command line from a validated request, dispatching to the appropriate
/// package manager builder.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_command(request: &PackageRequest) -> Vec<String> {
    match request.manager.name {
        crate::model::ManagerName::Winget => winget::build_winget_command(request),
        crate::model::ManagerName::PowerShell => winget::build_winget_command(request), // TODO: PowerShell builder
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
