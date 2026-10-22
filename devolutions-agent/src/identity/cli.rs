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
    let raw = Zeroizing::new(args.next().context("missing identity enrollment token")?);
    if args.next().is_some() {
        bail!("identity enroll accepts one token");
    }
    let raw = if raw.as_str() == "-" {
        read_token(io::stdin().lock())?
    } else {
        raw
    };
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
    use super::*;

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
