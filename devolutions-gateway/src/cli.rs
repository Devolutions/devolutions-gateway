//! CLI argument parsing for Devolutions Gateway.

use anyhow::Context as _;

/// The action to perform, derived from CLI arguments.
#[derive(Debug, PartialEq)]
pub enum CliAction {
    ShowHelp,
    RegisterService,
    UnregisterService,
    Run { service_mode: bool },
    ConfigInitOnly,
}

/// Parsed CLI arguments.
#[derive(Debug, PartialEq)]
pub struct CliArgs {
    pub action: CliAction,
    /// Value of `--config-path`, if provided.
    pub config_path: Option<String>,
}

/// Prints the help text to stdout.
#[expect(clippy::print_stdout)]
pub fn print_help(executable: &str) {
    println!(
        r#"HELP:

    Run:
        "{executable}"

    Run as service:
        "{executable}" --service

    Initialize configuration only (will not override existing configuration):
        "{executable}" --config-init-only

    Install service:
        "{executable}" service register

    Uninstall service:
        "{executable}" service unregister

    Options:
        --config-path <CONFIG_PATH>
"#
    );
}

/// Parses CLI arguments from [`std::env::args`].
///
/// Returns the executable name alongside the parsed arguments; the executable
/// is consumed from the iterator here and is needed by [`print_help`].
pub fn parse_args_from_env() -> anyhow::Result<(String, CliArgs)> {
    let mut env_args = std::env::args();
    let executable = env_args
        .next()
        .context("executable name is missing from the environment")?;
    let cli_args = parse_args(env_args)?;
    Ok((executable, cli_args))
}

/// Parses CLI arguments, **not** including the executable name.
///
/// Pass `std::env::args().skip(1)`.
pub fn parse_args(args: impl Iterator<Item = String>) -> anyhow::Result<CliArgs> {
    // Accumulate only what is needed for dispatch: the first two positional
    // arguments (all subcommand patterns use at most two) and the config path.
    struct RawArgs {
        config_path: Option<String>,
        first: Option<String>,
        second: Option<String>,
    }

    let mut raw = RawArgs {
        config_path: None,
        first: None,
        second: None,
    };

    let mut iter = args;

    while let Some(arg) = iter.next() {
        if arg == "--config-path" {
            raw.config_path = Some(iter.next().context("missing value for --config-path")?);
        } else if raw.first.is_none() {
            raw.first = Some(arg);
        } else if raw.second.is_none() {
            raw.second = Some(arg);
        } else {
            anyhow::bail!("unexpected argument: {arg}");
        }
    }

    let action = match raw.first.as_deref() {
        Some("--service") => {
            if let Some(arg) = raw.second {
                anyhow::bail!("unexpected argument: {arg}");
            }
            CliAction::Run { service_mode: true }
        }
        Some("service") => match raw.second.as_deref() {
            Some("register") => CliAction::RegisterService,
            Some("unregister") => CliAction::UnregisterService,
            _ => CliAction::ShowHelp,
        },
        Some("--config-init-only") => {
            if let Some(arg) = raw.second {
                anyhow::bail!("unexpected argument: {arg}");
            }
            CliAction::ConfigInitOnly
        }
        None => CliAction::Run { service_mode: false },
        Some(_) => CliAction::ShowHelp,
    };

    Ok(CliArgs {
        action,
        config_path: raw.config_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> CliArgs {
        parse_args(args.iter().map(|s| s.to_string())).expect("parse_args failed")
    }

    #[test]
    fn no_args_runs_normally() {
        let result = parse(&[]);
        assert_eq!(result.action, CliAction::Run { service_mode: false });
        assert_eq!(result.config_path, None);
    }

    #[test]
    fn service_flag_runs_as_service() {
        let result = parse(&["--service"]);
        assert_eq!(result.action, CliAction::Run { service_mode: true });
    }

    #[test]
    fn service_register() {
        let result = parse(&["service", "register"]);
        assert_eq!(result.action, CliAction::RegisterService);
    }

    #[test]
    fn service_unregister() {
        let result = parse(&["service", "unregister"]);
        assert_eq!(result.action, CliAction::UnregisterService);
    }

    #[test]
    fn service_without_subcommand_shows_help() {
        let result = parse(&["service"]);
        assert_eq!(result.action, CliAction::ShowHelp);
    }

    #[test]
    fn service_unknown_subcommand_shows_help() {
        let result = parse(&["service", "unknown"]);
        assert_eq!(result.action, CliAction::ShowHelp);
    }

    #[test]
    fn unknown_arg_shows_help() {
        let result = parse(&["unknown"]);
        assert_eq!(result.action, CliAction::ShowHelp);
    }

    #[test]
    fn config_init_only() {
        let result = parse(&["--config-init-only"]);
        assert_eq!(result.action, CliAction::ConfigInitOnly);
    }

    #[test]
    fn config_path_is_extracted() {
        let result = parse(&["--config-path", "/some/path"]);
        assert_eq!(result.action, CliAction::Run { service_mode: false });
        assert_eq!(result.config_path, Some("/some/path".to_owned()));
    }

    #[test]
    fn config_path_before_action() {
        let result = parse(&["--config-path", "/some/path", "service", "register"]);
        assert_eq!(result.action, CliAction::RegisterService);
        assert_eq!(result.config_path, Some("/some/path".to_owned()));
    }

    #[test]
    fn config_path_after_action() {
        let result = parse(&["service", "register", "--config-path", "/some/path"]);
        assert_eq!(result.action, CliAction::RegisterService);
        assert_eq!(result.config_path, Some("/some/path".to_owned()));
    }

    #[test]
    fn config_path_missing_value_is_error() {
        let err = parse_args(["--config-path"].iter().map(|s| s.to_string()));
        assert!(err.is_err());
    }

    #[test]
    fn extra_positional_arg_is_error() {
        let err = parse_args(["service", "register", "extra"].iter().map(|s| s.to_string()));
        assert!(err.is_err());
    }

    #[test]
    fn service_flag_with_extra_arg_is_error() {
        let err = parse_args(["--service", "extra"].iter().map(|s| s.to_string()));
        assert!(err.is_err());
    }

    #[test]
    fn config_init_only_with_extra_arg_is_error() {
        let err = parse_args(["--config-init-only", "extra"].iter().map(|s| s.to_string()));
        assert!(err.is_err());
    }
}
