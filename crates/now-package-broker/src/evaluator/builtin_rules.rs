//! Built-in request restrictions that apply before, and regardless of, the policy.

use std::borrow::Cow;

use now_policy_api::{ManagerName, Operation, PackageRequest};

use super::RequestFlags;
use super::identifier::selects_identifier;

/// Packages the broker never uninstalls, by package manager and identifier.
///
/// The Devolutions Agent hosts the broker, so removing it through the broker would remove the
/// policy enforcement with it.
/// To protect another package, add an entry for each package manager that distributes it, using
/// the identifier that manager uses for the package.
/// Entries are compared like Deny rule identifiers: letter case is ignored and decorated
/// identifiers (such as versioned specifiers) match.
const PROTECTED_PACKAGES: &[(ManagerName, &str)] = &[
    // https://github.com/microsoft/winget-pkgs/tree/master/manifests/d/Devolutions/Agent
    (ManagerName::Winget, "Devolutions.Agent"),
    // `package/chocolatey/devoagent/devoagent.template.nuspec`
    (ManagerName::Chocolatey, "devo-agent"),
];

/// Whether the request uninstalls a [`PROTECTED_PACKAGES`] entry, directly or as the previous
/// version replaced by an install or update.
pub(super) fn uninstalls_protected_package(request: &PackageRequest, flags: &RequestFlags) -> bool {
    let removes_package = request.operation == Operation::Uninstall || flags.has_uninstall_previous;
    removes_package
        && PROTECTED_PACKAGES.iter().any(|(manager, identifier)| {
            *manager == request.manager && selects_identifier(request.manager, &request.package.id.0, identifier)
        })
}

/// Kill-before-operation entry as passed to `taskkill /IM`: `.exe` is appended to a name without
/// an extension, as clients may send bare process names (`chrome`).
///
/// Other names are returned unchanged; [`is_acceptable_kill_process_name`] rejects any other
/// extension.
pub(crate) fn normalize_kill_process_name(name: &str) -> Cow<'_, str> {
    if name.is_empty() || name.contains('.') {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(format!("{name}.exe"))
    }
}

/// Whether `name` is a plain executable image name that `taskkill /IM` matches literally.
///
/// `/IM` accepts `*` wildcards, so names must not contain wildcard characters, path separators,
/// drive or stream separators, quotes, or control characters, and must end in `.exe`.
/// Apply [`normalize_kill_process_name`] first.
pub(crate) fn is_acceptable_kill_process_name(name: &str) -> bool {
    const EXTENSION: &str = ".exe";

    let has_executable_extension = name.len() > EXTENSION.len()
        && name
            .get(name.len() - EXTENSION.len()..)
            .is_some_and(|extension| extension.eq_ignore_ascii_case(EXTENSION));

    has_executable_extension
        && !name
            .chars()
            .any(|character| character.is_control() || matches!(character, '*' | '?' | '\\' | '/' | ':' | '"' | '\''))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_executable_names_are_acceptable_kill_targets() {
        for name in ["Code.exe", "notepad.EXE", "My App.exe", "app-1.2.exe"] {
            assert!(is_acceptable_kill_process_name(name), "{name}");
        }
    }

    #[test]
    fn wildcard_path_and_malformed_kill_targets_are_rejected() {
        for name in [
            "",
            ".exe",
            "*",
            "*.exe",
            "a?.exe",
            "notepad.exe ",
            r"C:\Windows\notepad.exe",
            "dir/notepad.exe",
            "C:notepad.exe",
            "\"notepad.exe\"",
            "note'pad.exe",
            "note\npad.exe",
            "note\u{0}pad.exe",
            "notepad.ex",
            "chrome.bat",
            "chrome.",
        ] {
            assert!(
                !is_acceptable_kill_process_name(&normalize_kill_process_name(name)),
                "{name:?}"
            );
        }
    }

    #[test]
    fn names_without_an_extension_get_exe_appended() {
        assert_eq!(normalize_kill_process_name("chrome"), "chrome.exe");
        assert_eq!(normalize_kill_process_name("Chrome.EXE"), "Chrome.EXE");
        assert_eq!(normalize_kill_process_name("chrome.bat"), "chrome.bat");
        assert_eq!(normalize_kill_process_name(""), "");
        assert!(is_acceptable_kill_process_name(&normalize_kill_process_name("chrome")));
        assert!(is_acceptable_kill_process_name(&normalize_kill_process_name(
            "Chrome.EXE"
        )));
        assert!(!is_acceptable_kill_process_name(&normalize_kill_process_name("*")));
        assert!(!is_acceptable_kill_process_name(&normalize_kill_process_name(
            r"dir\chrome"
        )));
    }
}
