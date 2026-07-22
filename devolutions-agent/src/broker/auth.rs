//! Package broker pipe client authentication.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use now_policy_api::{ClientContext, PackageRequest, StatusRequest};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tracing::{debug, warn};
use win_api_wrappers::process::Process;
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

use crate::code_signing::validate_devolutions_authenticode_signature;

#[derive(Clone, Debug)]
pub(crate) struct PipeClient {
    process_id: u32,
    executable_path: PathBuf,
    user: ClientUser,
}

#[derive(Clone, Debug)]
struct ClientUser {
    domain: String,
    name: String,
}

impl PipeClient {
    pub(crate) fn from_connected_pipe(server: &NamedPipeServer) -> anyhow::Result<Self> {
        let process_id = connected_pipe_client_process_id(server).context("failed to query pipe client process id")?;
        let process = Process::get_by_pid(process_id, PROCESS_QUERY_LIMITED_INFORMATION)
            .with_context(|| format!("failed to open pipe client process {process_id}"))?;
        let executable_path = process
            .exe_path()
            .with_context(|| format!("failed to query pipe client process {process_id} executable path"))?;
        let sid = process
            .token(TOKEN_QUERY)
            .with_context(|| format!("failed to open pipe client process {process_id} token"))?
            .sid_and_attributes()
            .with_context(|| format!("failed to query pipe client process {process_id} token user"))?
            .sid;
        let account = sid
            .lookup_account(None)
            .with_context(|| format!("failed to resolve pipe client process {process_id} user"))?;
        let user = ClientUser {
            domain: account.domain_name.to_string_lossy(),
            name: account.name.to_string_lossy(),
        };

        Ok(Self {
            process_id,
            executable_path,
            user,
        })
    }

    pub(crate) fn validate_request(
        &self,
        request: &PackageRequest,
        skip_signature_validation: bool,
    ) -> anyhow::Result<()> {
        self.validate_client_context(&request.client)?;
        self.validate_signature(skip_signature_validation)
    }

    pub(crate) fn validate_status_request(
        &self,
        request: &StatusRequest,
        skip_signature_validation: bool,
    ) -> anyhow::Result<()> {
        self.validate_client_context(&request.client)?;
        self.validate_signature(skip_signature_validation)
    }

    fn validate_client_context(&self, client: &ClientContext) -> anyhow::Result<()> {
        self.validate_effective_user(&client.effective_user)?;
        self.validate_executable_path(&client.client_executable_path)
    }

    fn validate_signature(&self, skip_signature_validation: bool) -> anyhow::Result<()> {
        if skip_signature_validation {
            warn!("DEBUG MODE: Skipping package broker client signature validation");
            return Ok(());
        }

        let thumbprint = validate_devolutions_authenticode_signature(&self.executable_path)?;

        debug!(
            process_id = self.process_id,
            executable = %self.executable_path.display(),
            certificate_thumbprint = %thumbprint,
            "Package broker pipe client authenticated"
        );

        Ok(())
    }

    fn validate_effective_user(&self, effective_user: &str) -> anyhow::Result<()> {
        if same_user(effective_user, &self.user) {
            return Ok(());
        }

        bail!(
            "pipe client user '{}\\{}' does not match request effective_user '{}'",
            self.user.domain,
            self.user.name,
            effective_user
        )
    }

    fn validate_executable_path(&self, requested_executable_path: &str) -> anyhow::Result<()> {
        let requested_path = Path::new(requested_executable_path);
        if !requested_path.is_absolute() {
            bail!("request client executable path is not absolute");
        }

        let actual_path = canonicalize_for_comparison(&self.executable_path).with_context(|| {
            format!(
                "failed to canonicalize pipe client executable path '{}'",
                self.executable_path.display()
            )
        })?;
        let requested_path = canonicalize_for_comparison(requested_path).with_context(|| {
            format!(
                "failed to canonicalize request client executable path '{}'",
                requested_executable_path
            )
        })?;

        if same_windows_path(&actual_path, &requested_path) {
            return Ok(());
        }

        bail!(
            "pipe client executable '{}' does not match request client executable '{}'",
            actual_path.display(),
            requested_path.display()
        )
    }
}

fn connected_pipe_client_process_id(server: &NamedPipeServer) -> anyhow::Result<u32> {
    use std::os::windows::io::AsRawHandle as _;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let mut process_id = 0u32;
    let handle = HANDLE(server.as_raw_handle());

    // SAFETY: `server` is a connected named-pipe server instance and the process id
    // output pointer is valid for the duration of the call.
    unsafe { GetNamedPipeClientProcessId(handle, &mut process_id) }?;

    Ok(process_id)
}

fn same_user(expected: &str, actual: &ClientUser) -> bool {
    let Some((expected_domain, expected_name)) = expected.rsplit_once('\\') else {
        return expected.eq_ignore_ascii_case(&actual.name);
    };

    expected_domain.eq_ignore_ascii_case(&actual.domain) && expected_name.eq_ignore_ascii_case(&actual.name)
}

fn canonicalize_for_comparison(path: &Path) -> anyhow::Result<PathBuf> {
    Ok(std::fs::canonicalize(path)?)
}

fn same_windows_path(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_user() -> ClientUser {
        ClientUser {
            domain: "CONTOSO".to_owned(),
            name: "alice".to_owned(),
        }
    }

    #[test]
    fn same_user_matches_domain_qualified_user() {
        assert!(same_user("contoso\\ALICE", &client_user()));
    }

    #[test]
    fn same_user_matches_unqualified_user() {
        assert!(same_user("ALICE", &client_user()));
    }

    #[test]
    fn same_user_rejects_wrong_domain() {
        assert!(!same_user("FABRIKAM\\alice", &client_user()));
    }
}
