use std::process::ExitStatus;

use anyhow::ensure;
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

use super::process_tree::ProcessTree;
use super::protocol::ProcessCredential;

#[cfg(windows)]
mod windows;

pub(super) enum Child {
    Service(tokio::process::Child),
    #[cfg(windows)]
    Credentialed(windows::Child),
}

impl Child {
    pub(super) async fn spawn(
        mut command: Command,
        credential: Option<ProcessCredential>,
        credential_transport_secure: bool,
    ) -> anyhow::Result<Self> {
        let Some(credential) = credential else {
            return Ok(Self::Service(command.spawn()?));
        };

        ensure!(credential_transport_secure, "credentialed execution requires HTTPS");
        ensure!(cfg!(windows), "credentialed execution is only supported on Windows");
        ensure!(
            !credential.username.trim().is_empty() && !credential.password.is_empty(),
            "credentialed execution requires a username and password"
        );
        ensure!(
            !credential.username.contains('\0')
                && !credential.password.contains('\0')
                && !credential.domain.contains('\0'),
            "credential contains a NUL character"
        );

        #[cfg(windows)]
        {
            use anyhow::Context as _;

            tokio::task::spawn_blocking(move || windows::Child::spawn(command.as_std(), credential))
                .await
                .context("credentialed process creation task failed")?
                .map(Self::Credentialed)
        }

        #[cfg(not(windows))]
        anyhow::bail!("credentialed execution is only supported on Windows")
    }

    pub(super) async fn attach_tree(&mut self) -> anyhow::Result<ProcessTree> {
        match self {
            Self::Service(child) => ProcessTree::attach(child).await,
            #[cfg(windows)]
            Self::Credentialed(child) => child.attach_tree(),
        }
    }

    pub(super) fn id(&self) -> Option<u32> {
        match self {
            Self::Service(child) => child.id(),
            #[cfg(windows)]
            Self::Credentialed(child) => Some(child.id),
        }
    }

    pub(super) fn take_stdin(&mut self) -> Option<ChildStdin> {
        match self {
            Self::Service(child) => child.stdin.take(),
            #[cfg(windows)]
            Self::Credentialed(child) => child.stdin.take(),
        }
    }

    pub(super) fn take_stdout(&mut self) -> Option<ChildStdout> {
        match self {
            Self::Service(child) => child.stdout.take(),
            #[cfg(windows)]
            Self::Credentialed(child) => child.stdout.take(),
        }
    }

    pub(super) fn take_stderr(&mut self) -> Option<ChildStderr> {
        match self {
            Self::Service(child) => child.stderr.take(),
            #[cfg(windows)]
            Self::Credentialed(child) => child.stderr.take(),
        }
    }

    pub(super) fn start_kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Service(child) => child.start_kill(),
            #[cfg(windows)]
            Self::Credentialed(child) => child.start_kill(),
        }
    }

    pub(super) async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match self {
            Self::Service(child) => child.wait().await,
            #[cfg(windows)]
            Self::Credentialed(child) => child.wait().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> ProcessCredential {
        ProcessCredential {
            username: "run-as-user".to_owned(),
            password: "test-only-password".to_owned(),
            domain: ".".to_owned(),
        }
    }

    #[tokio::test]
    async fn credentialed_http_is_rejected_even_on_loopback() {
        let result = Child::spawn(Command::new("must-not-start"), Some(credential()), false).await;
        let error = result.err().expect("plaintext credential request must fail");
        assert_eq!(error.to_string(), "credentialed execution requires HTTPS");
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn credentialed_execution_on_other_platforms_is_rejected() {
        let result = Child::spawn(Command::new("must-not-start"), Some(credential()), true).await;
        let error = result.err().expect("unsupported credential request must fail");
        assert_eq!(error.to_string(), "credentialed execution is only supported on Windows");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn empty_password_is_rejected_before_logon() {
        let mut credential = credential();
        credential.password.clear();
        let result = Child::spawn(Command::new("must-not-start"), Some(credential), true).await;
        let error = result.err().expect("missing password must fail");
        assert_eq!(
            error.to_string(),
            "credentialed execution requires a username and password"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn nul_in_password_is_rejected_instead_of_truncating_it() {
        let mut credential = credential();
        credential.password.push('\0');
        let result = Child::spawn(Command::new("must-not-start"), Some(credential), true).await;
        let error = result.err().expect("NUL in password must fail");
        assert_eq!(error.to_string(), "credential contains a NUL character");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn failed_windows_logon_does_not_start_a_service_identity_process() {
        let mut credential = credential();
        credential.username = format!("psu-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let result = Child::spawn(Command::new("must-not-start"), Some(credential), true).await;
        let error = result.err().expect("nonexistent local account must fail");
        assert!(format!("{error:#}").contains("Windows batch logon failed"));
        assert!(!format!("{error:#}").contains("test-only-password"));
    }
}
