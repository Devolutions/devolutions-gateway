//! Package broker pipe client authentication.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use now_policy_api::{ClientContext, PackageRequest, StatusRequest};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tracing::{debug, warn};
use widestring::U16CString;
use win_api_wrappers::identity::account::lookup_account_by_name;
use win_api_wrappers::identity::sid::Sid;
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
    /// Security identifier of the pipe client process token user, captured at connect.
    sid: Sid,
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
            sid,
            domain: account.domain_name.to_string_lossy(),
            name: account.name.to_string_lossy(),
        };

        Ok(Self {
            process_id,
            executable_path,
            user,
        })
    }

    /// Security identifier of the authenticated pipe client user, captured at connect.
    pub(crate) fn user_sid(&self) -> &Sid {
        &self.user.sid
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

    /// Validate that the request's `effective_user` denotes the authenticated pipe client user.
    ///
    /// The name is resolved to a SID and compared against the SID captured at connect,
    /// so distinct accounts sharing the same name (e.g. `MACHINE\alice` vs `DOMAIN\alice`)
    /// cannot be confused with one another.
    fn validate_effective_user(&self, effective_user: &str) -> anyhow::Result<()> {
        let requested_sid = resolve_account_sid(effective_user)
            .with_context(|| format!("failed to resolve request effective_user '{effective_user}'"))?;

        if requested_sid == self.user.sid {
            return Ok(());
        }

        bail!(
            "pipe client user '{}\\{}' ({}) does not match request effective_user '{}' ({})",
            self.user.domain,
            self.user.name,
            self.user.sid,
            effective_user,
            requested_sid
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

/// Resolve an account name (`DOMAIN\user` or `user`) to its security identifier.
fn resolve_account_sid(account_name: &str) -> anyhow::Result<Sid> {
    let account_name = U16CString::from_str(account_name).context("account name contains an interior NUL character")?;
    let account = lookup_account_by_name(&account_name).context("failed to look up account by name")?;
    Ok(account.sid.clone())
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
    use windows::Win32::Security::{WinLocalSystemSid, WinWorldSid};

    use super::*;

    fn system_sid() -> Sid {
        Sid::from_well_known(WinLocalSystemSid, None).expect("well-known SYSTEM SID")
    }

    /// Host-localized (domain, name) for the LocalSystem account.
    fn system_account_names() -> (String, String) {
        let account = system_sid().lookup_account(None).expect("SYSTEM account lookup");
        (account.domain_name.to_string_lossy(), account.name.to_string_lossy())
    }

    /// Host-localized unqualified name for the Everyone (World) group.
    fn everyone_account_name() -> String {
        Sid::from_well_known(WinWorldSid, None)
            .expect("well-known Everyone SID")
            .lookup_account(None)
            .expect("Everyone account lookup")
            .name
            .to_string_lossy()
    }

    fn system_client() -> PipeClient {
        let (domain, name) = system_account_names();
        PipeClient {
            process_id: 0,
            executable_path: PathBuf::new(),
            user: ClientUser {
                sid: system_sid(),
                domain,
                name,
            },
        }
    }

    #[test]
    fn resolve_account_sid_resolves_qualified_name() {
        let (domain, name) = system_account_names();
        let sid = resolve_account_sid(&format!("{domain}\\{name}")).expect("SYSTEM account should resolve");
        assert_eq!(sid, system_sid());
    }

    #[test]
    fn resolve_account_sid_resolves_unqualified_name() {
        let (_, name) = system_account_names();
        let sid = resolve_account_sid(&name).expect("SYSTEM account should resolve");
        assert_eq!(sid, system_sid());
    }

    #[test]
    fn resolve_account_sid_rejects_unknown_account() {
        assert!(resolve_account_sid("no-such-domain\\no-such-user-a2f6").is_err());
    }

    #[test]
    fn validate_effective_user_accepts_matching_sid() {
        let (domain, name) = system_account_names();
        assert!(
            system_client()
                .validate_effective_user(&format!("{domain}\\{name}"))
                .is_ok()
        );
    }

    #[test]
    fn validate_effective_user_rejects_different_account() {
        // The Everyone group resolves to a different SID than the SYSTEM caller.
        assert!(
            system_client()
                .validate_effective_user(&everyone_account_name())
                .is_err()
        );
    }
}
