//! The `identity` command.

use std::io::{self, BufRead};

use agent_identity::pending;
use agent_identity::token::Token;
use anyhow::{Context as _, bail};
use devolutions_agent_shared::get_data_dir;
use zeroize::Zeroizing;

use crate::config::ConfHandle;

/// Runs `identity <subcommand>` with the arguments that follow `identity`, and exits with status 1 on failure.
#[expect(clippy::print_stderr, reason = "the command reports its failure to the caller")]
pub fn run(args: &mut dyn Iterator<Item = String>) {
    if let Err(error) = enroll(args) {
        eprintln!("[ERROR] Agent Identity enrollment failed: {error:#}");
        std::process::exit(1);
    }
}

#[expect(clippy::print_stdout, reason = "the command prints the pending-enrollment file path")]
fn enroll(args: &mut dyn Iterator<Item = String>) -> anyhow::Result<()> {
    let subcommand = args.next().context("missing identity subcommand")?;
    if subcommand != "enroll" {
        bail!("unknown identity subcommand");
    }
    require_stdin_argument(args)?;
    let raw = read_token(io::stdin().lock())?;
    let token = Token::parse(&raw)?;
    let conf = ConfHandle::init()?.get_conf();
    let grant_current_user = conf
        .debug
        .identity
        .as_ref()
        .and_then(|settings| settings.acl_grant_current_user)
        .unwrap_or_default();
    let path = pending::write(&get_data_dir(), &token, grant_current_user)?;
    println!("{path}");
    Ok(())
}

/// Accepts only the `-` that follows `identity enroll`, so that a token never appears in a process listing or shell
/// history.
///
/// A refused argument may be a token, so the error never includes it, and it is zeroized when dropped.
fn require_stdin_argument(args: &mut dyn Iterator<Item = String>) -> anyhow::Result<()> {
    let argument = args.next().map(Zeroizing::new);
    let extra = args.next().map(Zeroizing::new);
    match (argument.as_ref().map(|argument| argument.as_str()), extra) {
        (Some("-"), None) => Ok(()),
        (None, _) => bail!("missing `-`: identity enroll reads the enrollment token from standard input"),
        _ => bail!("identity enroll accepts only `-` and reads the enrollment token from standard input"),
    }
}

fn read_token<R: BufRead>(mut input: R) -> anyhow::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    if input.read_line(&mut line).context("read enrollment token from stdin")? == 0 {
        bail!("no enrollment token on stdin");
    }
    let token = Zeroizing::new(line.trim().to_owned());
    if token.is_empty() {
        bail!("enrollment token on stdin is empty");
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const TOKEN: &str = "dvaet1.bag.secret";

    fn check(args: &[&str]) -> anyhow::Result<()> {
        require_stdin_argument(&mut args.iter().map(|arg| (*arg).to_owned()))
    }

    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    #[test]
    fn identity_enroll_accepts_hyphen_alone() {
        check(&["-"]).expect("accept `-`");
    }

    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    #[test]
    fn identity_enroll_without_argument_asks_for_hyphen() {
        let error = check(&[]).expect_err("refuse a missing `-`");
        assert!(format!("{error:#}").contains("`-`"), "{error:#}");
    }

    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    #[rstest]
    #[case::token(&[TOKEN])]
    #[case::token_after_hyphen(&["-", TOKEN])]
    #[case::token_before_hyphen(&[TOKEN, "-"])]
    #[case::token_option(&["--token", TOKEN])]
    fn identity_enroll_refuses_token_argument_without_echoing_it(#[case] args: &[&str]) {
        let error = format!("{:#}", check(args).expect_err("refuse a token argument"));
        assert!(!error.contains(TOKEN), "{error}");
        assert!(error.contains("standard input"), "{error}");
    }

    // oracle: intent devolutions-agent/src/identity/INTENT.md §CLI
    #[test]
    fn stdin_identity_token_trims_whitespace_and_rejects_empty_input() {
        // oracle: mutant keeps the whitespace around the token
        assert_eq!(
            read_token(&b"  dvaet1.bag.secret \r\nsecond line\n"[..])
                .expect("read one token")
                .as_str(),
            "dvaet1.bag.secret"
        );
        assert!(read_token(&b""[..]).is_err());
        assert!(read_token(&b" \t\r\n"[..]).is_err());
    }
}
