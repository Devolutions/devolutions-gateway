use std::process::ExitStatus;

use anyhow::ensure;
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

use super::ConnectionSecurity;
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
        security: ConnectionSecurity,
    ) -> anyhow::Result<Self> {
        let Some(credential) = credential else {
            return Ok(Self::Service(command.spawn()?));
        };

        ensure!(
            security.permits_credentials(),
            "credentialed execution requires a device-authenticated verified HTTPS connection on Windows"
        );
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
        // UNTESTED: The non-Windows refusal and credential-free paths need Linux/macOS execution.
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
    #[cfg(windows)]
    use ::windows::core::Error as WindowsError;

    use super::*;

    fn security(verified_https: bool) -> ConnectionSecurity {
        ConnectionSecurity {
            authentication: super::super::ConnectionAuthentication::Device,
            verified_https,
        }
    }

    fn credential() -> ProcessCredential {
        ProcessCredential {
            username: "run-as-user".to_owned(),
            password: "test-only-password".to_owned(),
            domain: ".".to_owned(),
        }
    }

    #[tokio::test]
    async fn omitted_credentials_do_not_require_run_as_eligibility() {
        for authentication in [
            super::super::ConnectionAuthentication::AppToken,
            super::super::ConnectionAuthentication::Device,
        ] {
            for verified_https in [false, true] {
                let mut command = if cfg!(windows) {
                    let mut command = Command::new("cmd.exe");
                    command.args(["/c", "exit", "0"]);
                    command
                } else {
                    let mut command = Command::new("/bin/sh");
                    command.args(["-c", "exit 0"]);
                    command
                };
                command.kill_on_drop(true);
                ProcessTree::prepare(&mut command);
                let mut child = Child::spawn(
                    command,
                    None,
                    ConnectionSecurity {
                        authentication,
                        verified_https,
                    },
                )
                .await
                .expect("credential-free launch");
                let tree = child.attach_tree().await.expect("track child");
                assert!(child.wait().await.expect("wait for child").success());
                tree.release();
            }
        }
    }

    #[tokio::test]
    async fn credentialed_http_is_rejected_even_on_loopback() {
        let result = Child::spawn(Command::new("must-not-start"), Some(credential()), security(false)).await;
        let error = result.err().expect("plaintext credential request must fail");
        assert!(!error.to_string().is_empty());
        #[cfg(windows)]
        assert!(
            error.downcast_ref::<WindowsError>().is_none(),
            "must refuse before logon"
        );
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn credentialed_execution_on_other_platforms_is_rejected() {
        let result = Child::spawn(Command::new("must-not-start"), Some(credential()), security(true)).await;
        let error = result.err().expect("unsupported credential request must fail");
        assert!(!error.to_string().is_empty());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn app_token_https_credentials_are_rejected_before_windows_logon() {
        let result = Child::spawn(
            Command::new("must-not-start"),
            Some(credential()),
            ConnectionSecurity {
                authentication: super::super::ConnectionAuthentication::AppToken,
                verified_https: true,
            },
        )
        .await;
        let error = result.err().expect("app-token credential request must fail");
        assert!(!error.to_string().is_empty());
        assert!(
            error.downcast_ref::<WindowsError>().is_none(),
            "must refuse before logon"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn empty_password_is_rejected_before_logon() {
        let mut credential = credential();
        credential.password.clear();
        let result = Child::spawn(Command::new("must-not-start"), Some(credential), security(true)).await;
        let error = result.err().expect("missing password must fail");
        assert!(!error.to_string().is_empty());
        assert!(
            error.downcast_ref::<WindowsError>().is_none(),
            "must validate before logon"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn nul_in_password_is_rejected_instead_of_truncating_it() {
        let mut credential = credential();
        credential.password.push('\0');
        let result = Child::spawn(Command::new("must-not-start"), Some(credential), security(true)).await;
        let error = result.err().expect("NUL in password must fail");
        assert!(!error.to_string().is_empty());
        assert!(
            error.downcast_ref::<WindowsError>().is_none(),
            "must validate before logon"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn failed_windows_logon_does_not_start_a_service_identity_process() {
        let mut credential = credential();
        credential.username = format!("psu-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let result = Child::spawn(Command::new("must-not-start"), Some(credential), security(true)).await;
        let error = result.err().expect("nonexistent local account must fail");
        assert!(error.downcast_ref::<WindowsError>().is_some(), "must fail native logon");
        assert!(!format!("{error:#}").contains("test-only-password"));
    }
}
