//! Command-line builders for package manager operations.
//!
//! Constructs the commands the broker would execute from validated request fields.
//! The broker never executes client-supplied commands directly.

pub mod bun;
pub mod cargo;
pub mod chocolatey;
pub mod dotnet;
pub mod npm;
pub mod pip;
pub mod powershell;
pub mod scoop;
pub mod vcpkg;
pub mod winget;

use anyhow::bail;
use now_policy_api::{ManagerName, PackageRequest};

/// Build a command line from a validated request, dispatching to the appropriate
/// package manager builder.
///
/// Returns the command as a list of arguments (first element is the executable).
pub fn build_command(request: &PackageRequest) -> anyhow::Result<Vec<String>> {
    match request.manager {
        ManagerName::Bun => bun::build_bun_command(request),
        ManagerName::Cargo => cargo::build_cargo_command(request),
        ManagerName::Dotnet => dotnet::build_dotnet_command(request),
        ManagerName::Npm => npm::build_npm_command(request),
        ManagerName::Winget => winget::build_winget_command(request),
        ManagerName::PowerShell => powershell::build_powershell5_command(request),
        ManagerName::PowerShell7 => powershell::build_powershell7_command(request),
        ManagerName::Chocolatey => chocolatey::build_chocolatey_command(request),
        ManagerName::Pip => pip::build_pip_command(request),
        ManagerName::Scoop => scoop::build_scoop_command(request),
        ManagerName::Vcpkg => vcpkg::build_vcpkg_command(request),
        unsupported => bail!("package manager is not supported by the broker: {unsupported}"),
    }
}

/// Characters that cmd.exe may interpret in a generated batch script, even inside double quotes.
pub(crate) const BATCH_METACHARACTERS: [char; 11] = ['"', '%', '!', '^', '&', '|', '<', '>', '\r', '\n', '\0'];

/// Quote a value as a PowerShell single-quoted string literal.
///
/// PowerShell treats U+2018 through U+201B as single quotes too, so each of them is doubled
/// along with the ASCII apostrophe, matching `CodeGeneration.EscapeSingleQuotedStringContent`.
pub(crate) fn quote_powershell_literal(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            quoted.push(c);
        }
        quoted.push(c);
    }
    quoted.push('\'');
    quoted
}

/// Validate a package version against a conservative allowlist.
///
/// ASCII alphanumerics, `.`, `-`, `+` and `_` are always accepted.
/// `extra` lists additional characters a manager needs for its version syntax.
pub(crate) fn validate_package_version(manager: &str, version: &str, extra: &[char]) -> anyhow::Result<()> {
    const MAX_VERSION_LEN: usize = 128;

    if version.is_empty() || version.len() > MAX_VERSION_LEN {
        bail!("{manager} package version must be between 1 and {MAX_VERSION_LEN} bytes");
    }
    if version.starts_with('-') {
        bail!("{manager} package version cannot start with a hyphen");
    }
    if !version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_') || extra.contains(&c))
    {
        bail!("{manager} package version contains unsupported characters");
    }

    Ok(())
}

/// Validate a package source or repository name against a conservative allowlist.
///
/// Accepts ASCII alphanumerics, `.`, `-`, `_` and inner spaces, starting with an alphanumeric.
pub(crate) fn validate_source_name(manager: &str, name: &str) -> anyhow::Result<()> {
    const MAX_SOURCE_NAME_LEN: usize = 128;

    if name.is_empty() || name.len() > MAX_SOURCE_NAME_LEN {
        bail!("{manager} package source name must be between 1 and {MAX_SOURCE_NAME_LEN} bytes");
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) || name.ends_with(' ') {
        bail!("{manager} package source name must start with an alphanumeric character and not end with a space");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' '))
    {
        bail!("{manager} package source name contains unsupported characters");
    }

    Ok(())
}

/// Reject command arguments that would be written into a generated batch script unsafely.
pub(crate) fn validate_batch_arguments(manager: &str, command: &[String]) -> anyhow::Result<()> {
    if command.iter().any(|arg| arg.contains(BATCH_METACHARACTERS)) {
        bail!("{manager} command arguments cannot contain batch metacharacters");
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_literal_doubles_every_single_quote_character() {
        assert_eq!(quote_powershell_literal("plain"), "'plain'");
        assert_eq!(quote_powershell_literal("a'b"), "'a''b'");
        for quote in ['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
            assert_eq!(
                quote_powershell_literal(&format!("a{quote}b")),
                format!("'a{quote}{quote}b'")
            );
        }
        assert_eq!(
            quote_powershell_literal("\u{2018}'\u{201B}"),
            "'\u{2018}\u{2018}''\u{201B}\u{201B}'"
        );
    }

    #[test]
    fn package_version_allowlist() {
        for version in ["1.2.3", "1.2.3-beta.1+build_5", "v2", "latest"] {
            validate_package_version("test", version, &[]).expect(version);
        }
        validate_package_version("test", "[1.0,2.0)", &['[', ']', '(', ')', ',']).expect("extra characters");

        let too_long = "1".repeat(129);
        for version in [
            "",
            too_long.as_str(),
            "-1.0",
            "1.0 beta",
            "1.0'",
            "1.0\u{2019}",
            "1.0\"",
            "1.0;x",
            "1.0&x",
            "1.0|x",
            "1.0%x%",
            "1.0$x",
            "1.0`x",
            "1.0\n",
            "1.0é",
        ] {
            validate_package_version("test", version, &[]).expect_err(version);
        }
    }

    #[test]
    fn source_name_allowlist() {
        for name in ["winget", "PSGallery", "my.repo-1_x", "Internal Repo"] {
            validate_source_name("test", name).expect(name);
        }
        for name in [
            "",
            " winget",
            "winget ",
            "-winget",
            "win'get",
            "win\u{2018}get",
            "win\"get",
            "win&get",
            "win/get",
            "win\\get",
            "win:get",
            "win;get",
            "win$get",
        ] {
            validate_source_name("test", name).expect_err(name);
        }
    }

    #[test]
    fn batch_arguments_reject_metacharacters() {
        validate_batch_arguments(
            "test",
            &["winget.exe".to_owned(), "C:\\Program Files (x86)\\".to_owned()],
        )
        .expect("plain arguments");
        for metacharacter in BATCH_METACHARACTERS {
            validate_batch_arguments("test", &[format!("a{metacharacter}b")]).expect_err("metacharacter");
        }
    }
}
