//! Package broker pipe client authentication.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use devolutions_agent_shared::windows::code_signing::validate_devolutions_authenticode_signature;
use now_policy_api::{CancelRequest, ClientContext, PackageRequest, StatusRequest};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tracing::{debug, warn};
use widestring::U16CString;
use win_api_wrappers::identity::account::lookup_account_by_name;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::Storage::FileSystem::FILE_ID_INFO;
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

#[derive(Clone, Debug)]
pub(crate) struct PipeClient {
    process_id: u32,
    executable_path: PathBuf,
    /// Security identifier of the pipe client process token user, captured at connect.
    user_sid: Sid,
}

impl PipeClient {
    /// Captures the identity of the process on the other end of a connected pipe instance.
    ///
    /// Deliberately limited to fast, local syscalls (no account-name resolution, which may
    /// hit a domain controller), because it runs before any signature gate and is therefore
    /// unauthenticated work a connection flood can trigger.
    pub(crate) fn from_connected_pipe(server: &NamedPipeServer) -> anyhow::Result<Self> {
        let process_id = connected_pipe_client_process_id(server).context("failed to query pipe client process id")?;
        Self::from_process_id(process_id)
    }

    fn from_process_id(process_id: u32) -> anyhow::Result<Self> {
        let process = Process::get_by_pid(process_id, PROCESS_QUERY_LIMITED_INFORMATION)
            .with_context(|| format!("failed to open pipe client process {process_id}"))?;
        let executable_path = process
            .exe_path()
            .with_context(|| format!("failed to query pipe client process {process_id} executable path"))?;
        let user_sid = process
            .token(TOKEN_QUERY)
            .with_context(|| format!("failed to open pipe client process {process_id} token"))?
            .sid_and_attributes()
            .with_context(|| format!("failed to query pipe client process {process_id} token user"))?
            .sid;

        Ok(Self {
            process_id,
            executable_path,
            user_sid,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_current_process() -> anyhow::Result<Self> {
        Self::from_process_id(std::process::id())
    }

    /// Security identifier of the authenticated pipe client user, captured at connect.
    pub(crate) fn user_sid(&self) -> &Sid {
        &self.user_sid
    }

    pub(crate) fn validate_request(
        &self,
        request: &PackageRequest,
        skip_signature_validation: bool,
    ) -> anyhow::Result<()> {
        self.validate_client_context(&request.client)?;
        self.validate_connection(skip_signature_validation)
    }

    pub(crate) fn validate_status_request(
        &self,
        request: &StatusRequest,
        skip_signature_validation: bool,
    ) -> anyhow::Result<()> {
        self.validate_client_context(&request.client)?;
        self.validate_connection(skip_signature_validation)
    }

    pub(crate) fn validate_cancel_request(
        &self,
        request: &CancelRequest,
        skip_signature_validation: bool,
    ) -> anyhow::Result<()> {
        self.validate_client_context(&request.client)?;
        self.validate_connection(skip_signature_validation)
    }

    fn validate_client_context(&self, client: &ClientContext) -> anyhow::Result<()> {
        self.validate_effective_user(&client.effective_user)?;
        self.validate_executable_path(&client.client_executable_path)
    }

    pub(crate) fn validate_connection(&self, skip_signature_validation: bool) -> anyhow::Result<()> {
        if signature_validation_skipped(skip_signature_validation) {
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

        if requested_sid == self.user_sid {
            return Ok(());
        }

        // Resolve the client account name lazily, only on this rare error path; doing it at
        // connect time would be unauthenticated work triggerable by a connection flood.
        let client_account = self
            .user_sid
            .lookup_account(None)
            .map(|account| {
                format!(
                    "{}\\{}",
                    account.domain_name.to_string_lossy(),
                    account.name.to_string_lossy()
                )
            })
            .unwrap_or_else(|_| String::from("<unresolved>"));

        bail!(
            "pipe client user '{}' ({}) does not match request effective_user '{}' ({})",
            client_account,
            self.user_sid,
            effective_user,
            requested_sid
        )
    }

    fn validate_executable_path(&self, requested_executable_path: &str) -> anyhow::Result<()> {
        let requested_path = Path::new(requested_executable_path);
        if !requested_path.is_absolute() {
            bail!("request client executable path is not absolute");
        }

        let actual_id = file_id(&self.executable_path).with_context(|| {
            format!(
                "failed to query pipe client executable '{}' file identity",
                self.executable_path.display()
            )
        })?;
        let requested_id = file_id(requested_path).with_context(|| {
            format!("failed to query request client executable '{requested_executable_path}' file identity")
        })?;

        if same_file(&actual_id, &requested_id) {
            return Ok(());
        }

        bail!(
            "pipe client executable '{}' does not match request client executable '{}'",
            self.executable_path.display(),
            requested_executable_path
        )
    }
}

/// Returns whether broker client signature validation is skipped.
///
/// The bypass is compile-time gated behind the development-only `dev-skip-broker-signature`
/// cargo feature, which must never be enabled for shipped builds. Without the feature, this
/// always returns `false` and signature validation is unconditionally enforced, no matter
/// what the configuration says.
fn signature_validation_skipped(skip_signature_validation: bool) -> bool {
    cfg!(feature = "dev-skip-broker-signature") && skip_signature_validation
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

/// Queries the volume serial number and 128-bit file ID uniquely identifying the file.
fn file_id(path: &Path) -> anyhow::Result<FILE_ID_INFO> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
        GetFileInformationByHandleEx,
    };

    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .open(path)?;

    let mut info = FILE_ID_INFO::default();

    let info_size = u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits in u32");

    // SAFETY: `file` is an open file handle, and the output pointer points to a
    // properly sized FILE_ID_INFO valid for the duration of the call.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&raw mut info).cast(),
            info_size,
        )
    }?;

    Ok(info)
}

fn same_file(left: &FILE_ID_INFO, right: &FILE_ID_INFO) -> bool {
    left.VolumeSerialNumber == right.VolumeSerialNumber && left.FileId.Identifier == right.FileId.Identifier
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
        PipeClient {
            process_id: 0,
            executable_path: PathBuf::new(),
            user_sid: system_sid(),
        }
    }

    #[cfg(not(feature = "dev-skip-broker-signature"))]
    fn client_user_sid() -> Sid {
        system_client().user_sid
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

    #[test]
    fn file_id_matches_same_file_through_different_paths() {
        let exe = std::env::current_exe().expect("current exe");
        let direct = file_id(&exe).expect("file id via direct path");

        // Build an equivalent path with different casing and a redundant `.` component.
        let mut alternate = exe.parent().expect("exe parent").join(".");
        alternate.push(exe.file_name().expect("exe file name").to_ascii_uppercase());
        let alternate = file_id(&alternate).expect("file id via alternate path");

        assert!(same_file(&direct, &alternate));
    }

    #[test]
    fn file_id_differs_for_distinct_files() {
        let exe = std::env::current_exe().expect("current exe");
        let exe_id = file_id(&exe).expect("exe file id");

        let temp = std::env::temp_dir().join(format!("dgw-agent-file-id-test-{}", std::process::id()));
        std::fs::write(&temp, b"file identity test").expect("write temp file");
        let temp_id = file_id(&temp).expect("temp file id");
        std::fs::remove_file(&temp).expect("remove temp file");

        assert!(!same_file(&exe_id, &temp_id));
    }

    #[cfg(not(feature = "dev-skip-broker-signature"))]
    mod shipping_build {
        use super::*;

        #[test]
        fn signature_validation_is_never_skipped() {
            assert!(!signature_validation_skipped(true));
            assert!(!signature_validation_skipped(false));
        }

        #[test]
        fn validate_signature_is_attempted_even_when_skip_is_requested() {
            // The test binary is not Devolutions-signed, so validation must be attempted and fail
            // even though the configuration requests skipping it.
            let client = PipeClient {
                process_id: std::process::id(),
                executable_path: std::env::current_exe().expect("current test executable path"),
                user_sid: client_user_sid(),
            };

            assert!(client.validate_connection(true).is_err());
        }
    }

    #[cfg(feature = "dev-skip-broker-signature")]
    mod dev_build {
        use super::*;

        #[test]
        fn signature_validation_is_skipped_only_when_requested() {
            assert!(signature_validation_skipped(true));
            assert!(!signature_validation_skipped(false));
        }
    }
}
