//! Request options set through WinGet custom parameters.

use now_policy_api::CustomParameterString;

/// Policy-relevant WinGet options found in custom parameters.
///
/// The WinGet command builder appends custom parameters verbatim, so these options take effect
/// even when the corresponding request field is unset.
/// Long option names are matched ignoring letter case, as WinGet does.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct WingetOptions<'a> {
    pub interactive: bool,
    pub skip_hash_check: bool,
    pub no_upgrade: bool,
    pub uninstall_previous: bool,
    /// Values of `--location` and `-l`; `None` when the value is missing.
    pub locations: Vec<Option<&'a str>>,
}

pub(super) fn winget_options(parameters: &[CustomParameterString]) -> WingetOptions<'_> {
    let mut options = WingetOptions::default();
    // Values stay exactly as WinGet receives them; only option detection ignores leading whitespace.
    let mut parameters = parameters.iter().map(|parameter| parameter.0.as_str());

    while let Some(parameter) = parameters.next() {
        let option = parameter.trim_start();
        let (option, is_long) = if let Some(long) = option.strip_prefix("--") {
            (long, true)
        } else if let Some(short) = option.strip_prefix('-') {
            (short, false)
        } else {
            continue;
        };
        let (name, attached_value) = match option.split_once('=') {
            Some((name, value)) => (name.trim_end(), Some(value)),
            None => (option.trim_end(), None),
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
        } else if is("interactive", Some("i")) {
            options.interactive = true;
        } else if is("ignore-security-hash", None) {
            options.skip_hash_check = true;
        } else if is("no-upgrade", None) {
            options.no_upgrade = true;
        } else if is("uninstall-previous", None) {
            options.uninstall_previous = true;
        }
    }

    options
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
    fn location_values_are_extracted_in_every_accepted_form() {
        for values in [
            &["--location", r"C:\Tools"][..],
            &["--LOCATION", r"C:\Tools"],
            &[r"--location=C:\Tools"],
            &["-l", r"C:\Tools"],
            &[r"-l=C:\Tools"],
        ] {
            let parameters = parameters(values);
            assert_eq!(winget_options(&parameters).locations, [Some(r"C:\Tools")], "{values:?}");
        }
        assert_eq!(winget_options(&parameters(&["--location"])).locations, [None]);

        let raw = parameters(&["--location", "C:\\Tools\n", "-l=C:\\Tools "]);
        assert_eq!(
            winget_options(&raw).locations,
            [Some("C:\\Tools\n"), Some("C:\\Tools ")]
        );
    }

    #[test]
    fn policy_relevant_flags_are_detected() {
        let flags = parameters(&[
            "--Interactive",
            "--ignore-security-hash",
            "--no-upgrade",
            "--uninstall-previous",
        ]);
        let options = winget_options(&flags);
        assert!(options.interactive && options.skip_hash_check && options.no_upgrade && options.uninstall_previous);

        assert!(winget_options(&parameters(&["-i"])).interactive);
        assert_eq!(
            winget_options(&parameters(&["--silent", "--log", r"C:\Temp\log.txt", "-h"])),
            WingetOptions::default()
        );
    }
}
