//! Request options set through package manager custom parameters.
//!
//! The WinGet and Scoop command builders append custom parameters verbatim, so policy-relevant
//! options passed there take effect even when the corresponding request field is unset.
//! The other command builders reject custom parameters.

use now_policy_api::{Architecture, CustomParameterString, ManagerName, Scope};

/// Policy-relevant options found in custom parameters.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct CustomOptions<'a> {
    pub interactive: bool,
    pub skip_hash_check: bool,
    pub no_upgrade: bool,
    pub uninstall_previous: bool,
    /// Install location values; `None` when the value is missing.
    pub locations: Vec<Option<&'a str>>,
    /// Scope values; `None` when the value is missing or not recognized.
    pub scopes: Vec<Option<Scope>>,
    /// Architecture values; `None` when the value is missing or not recognized.
    pub architectures: Vec<Option<Architecture>>,
}

pub(super) fn custom_options(manager: ManagerName, parameters: &[CustomParameterString]) -> CustomOptions<'_> {
    match manager {
        ManagerName::Winget => winget_options(parameters),
        ManagerName::Scoop => scoop_options(parameters),
        _ => CustomOptions::default(),
    }
}

/// Parse WinGet options.
///
/// WinGet matches long option names ignoring letter case and accepts values as the next argument
/// or after `=`. Values are kept exactly as WinGet receives them.
fn winget_options(parameters: &[CustomParameterString]) -> CustomOptions<'_> {
    let mut options = CustomOptions::default();
    let mut parameters = parameters.iter().map(|parameter| parameter.0.as_str());

    while let Some(parameter) = parameters.next() {
        let Some((name, is_long, attached_value)) = split_option(parameter) else {
            continue;
        };
        let is = |long_name: &str, short_name: Option<&str>| {
            if is_long {
                name.eq_ignore_ascii_case(long_name)
            } else {
                short_name == Some(name)
            }
        };

        if is("location", Some("l")) {
            options.locations.push(attached_value.or_else(|| parameters.next()));
        } else if is("scope", None) {
            let value = attached_value.or_else(|| parameters.next());
            options.scopes.push(value.and_then(parse_scope));
        } else if is("architecture", Some("a")) {
            let value = attached_value.or_else(|| parameters.next());
            options.architectures.push(value.and_then(parse_architecture));
        } else if is("interactive", Some("i")) {
            options.interactive = true;
        } else if is("ignore-security-hash", None) || is("force", None) {
            options.skip_hash_check = true;
        } else if is("no-upgrade", None) {
            options.no_upgrade = true;
        } else if is("uninstall-previous", None) {
            options.uninstall_previous = true;
        }
    }

    options
}

/// Parse Scoop options.
///
/// Scoop accepts clustered short options (`-ks`), so every letter of a short option is considered.
/// An architecture set here is treated as unrecognized because its value may be attached to the cluster.
fn scoop_options(parameters: &[CustomParameterString]) -> CustomOptions<'_> {
    let mut options = CustomOptions::default();

    for parameter in parameters {
        let Some((name, is_long, _)) = split_option(&parameter.0) else {
            continue;
        };

        if is_long {
            if name.eq_ignore_ascii_case("skip-hash-check") {
                options.skip_hash_check = true;
            } else if name.eq_ignore_ascii_case("arch") {
                options.architectures.push(None);
            }
        } else {
            if name.contains('s') {
                options.skip_hash_check = true;
            }
            if name.contains('a') {
                options.architectures.push(None);
            }
        }
    }

    options
}

/// Split an option argument into its name, whether it is a long option, and its attached `=value`.
fn split_option(parameter: &str) -> Option<(&str, bool, Option<&str>)> {
    let option = parameter.trim_start();
    let (option, is_long) = match option.strip_prefix("--") {
        Some(long) => (long, true),
        None => (option.strip_prefix('-')?, false),
    };
    Some(match option.split_once('=') {
        Some((name, value)) => (name.trim_end(), is_long, Some(value)),
        None => (option.trim_end(), is_long, None),
    })
}

fn parse_scope(value: &str) -> Option<Scope> {
    match value.trim() {
        value if value.eq_ignore_ascii_case("user") => Some(Scope::User),
        value if value.eq_ignore_ascii_case("machine") => Some(Scope::Machine),
        _ => None,
    }
}

fn parse_architecture(value: &str) -> Option<Architecture> {
    match value.trim() {
        value if value.eq_ignore_ascii_case("x86") => Some(Architecture::X86),
        value if value.eq_ignore_ascii_case("x64") => Some(Architecture::X64),
        value if value.eq_ignore_ascii_case("arm64") => Some(Architecture::Arm64),
        value if value.eq_ignore_ascii_case("neutral") => Some(Architecture::Neutral),
        _ => None,
    }
}

/// Resolve a request value against values set through custom parameters.
///
/// Returns the single known value, or `None` when the custom parameters conflict with the request,
/// repeat the option, or use an unrecognized value.
pub(super) fn resolve<T: Copy>(requested: Option<T>, custom: &[Option<T>]) -> Option<Option<T>> {
    match (requested, custom) {
        (_, []) => None,
        (None, [value]) => Some(*value),
        _ => Some(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters(values: &[&str]) -> Vec<CustomParameterString> {
        values
            .iter()
            .map(|value| CustomParameterString((*value).to_owned()))
            .collect()
    }

    #[test]
    fn winget_location_values_are_extracted_in_every_accepted_form() {
        for values in [
            &["--location", r"C:\Tools"][..],
            &["--LOCATION", r"C:\Tools"],
            &[r"--location=C:\Tools"],
            &["-l", r"C:\Tools"],
            &[r"-l=C:\Tools"],
        ] {
            let parameters = parameters(values);
            assert_eq!(
                custom_options(ManagerName::Winget, &parameters).locations,
                [Some(r"C:\Tools")],
                "{values:?}"
            );
        }
        assert_eq!(
            custom_options(ManagerName::Winget, &parameters(&["--location"])).locations,
            [None]
        );

        let raw = parameters(&["--location", "C:\\Tools\n", "-l=C:\\Tools "]);
        assert_eq!(
            custom_options(ManagerName::Winget, &raw).locations,
            [Some("C:\\Tools\n"), Some("C:\\Tools ")]
        );
    }

    #[test]
    fn winget_policy_relevant_options_are_detected() {
        let flags = parameters(&[
            "--Interactive",
            "--ignore-security-hash",
            "--no-upgrade",
            "--uninstall-previous",
        ]);
        let options = custom_options(ManagerName::Winget, &flags);
        assert!(options.interactive && options.skip_hash_check && options.no_upgrade && options.uninstall_previous);

        assert!(custom_options(ManagerName::Winget, &parameters(&["-i"])).interactive);
        assert!(custom_options(ManagerName::Winget, &parameters(&["--FORCE"])).skip_hash_check);

        let selectors = parameters(&["--scope", "Machine", "-a=x86", "--architecture", "arm"]);
        let options = custom_options(ManagerName::Winget, &selectors);
        assert_eq!(options.scopes, [Some(Scope::Machine)]);
        assert_eq!(options.architectures, [Some(Architecture::X86), None]);

        assert_eq!(
            custom_options(
                ManagerName::Winget,
                &parameters(&["--silent", "--log", r"C:\Temp\log.txt", "-h"])
            ),
            CustomOptions::default()
        );
    }

    #[test]
    fn scoop_policy_relevant_options_are_detected() {
        for values in [&["--skip-hash-check"][..], &["-s"], &["-ks"]] {
            assert!(
                custom_options(ManagerName::Scoop, &parameters(values)).skip_hash_check,
                "{values:?}"
            );
        }
        for values in [&["--arch", "32bit"][..], &["-a", "64bit"], &["-ka32bit"]] {
            assert_eq!(
                custom_options(ManagerName::Scoop, &parameters(values)).architectures,
                [None],
                "{values:?}"
            );
        }
        assert_eq!(
            custom_options(ManagerName::Scoop, &parameters(&["--no-cache", "-k"])),
            CustomOptions::default()
        );
    }

    #[test]
    fn other_managers_ignore_custom_parameters() {
        let flags = parameters(&["--force", "--scope", "machine"]);
        assert_eq!(custom_options(ManagerName::Npm, &flags), CustomOptions::default());
    }

    #[test]
    fn custom_values_resolve_only_when_unambiguous() {
        assert_eq!(resolve::<Scope>(Some(Scope::User), &[]), None);
        assert_eq!(resolve(None, &[Some(Scope::Machine)]), Some(Some(Scope::Machine)));
        assert_eq!(resolve(Some(Scope::User), &[Some(Scope::User)]), Some(None));
        assert_eq!(resolve::<Scope>(None, &[None]), Some(None));
    }
}
