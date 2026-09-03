//! Package broker pipe client authentication.

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context as _, bail};
use devolutions_agent_shared::windows::code_signing::validate_devolutions_authenticode_signature;
use now_policy_api::{CancelRequest, ClientContext, PackageRequest, StatusRequest};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tracing::{debug, warn};
use widestring::U16CString;
use win_api_wrappers::identity::account::lookup_account_by_name;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use win_api_wrappers::thread::Thread;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY, WinBuiltinAdministratorsSid};
use windows::Win32::Storage::FileSystem::{FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows::Win32::System::Threading::{PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION};

const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessInstanceIdentity {
    process_id: u32,
    creation_time: SystemTime,
}

#[derive(Clone, Debug)]
pub(crate) struct PipeClient {
    process_id: u32,
    process_creation_time: SystemTime,
    process: Option<Arc<Process>>,
    executable_path: PathBuf,
    executable_file: Option<Arc<File>>,
    /// Security identifier of the pipe client process token user, captured at connect.
    user_sid: Sid,
    /// Whether the pipe client process token is elevated, captured at connect.
    ///
    /// Request fields are never trusted for this: policy management writes require the
    /// actual token state observed on the named-pipe process, not a claim in the request
    /// body.
    is_elevated: bool,
    /// Whether the pipe client process token has the built-in Administrators group
    /// enabled, captured at connect (see [`win_api_wrappers::token::Token::is_member`]).
    is_administrator: bool,
}

impl PipeClient {
    /// Captures the identity of the process on the other end of a connected pipe instance.
    ///
    /// Deliberately limited to fast, local syscalls (no account-name resolution, which may
    /// hit a domain controller), because it runs before any signature gate and is therefore
    /// unauthenticated work a connection flood can trigger.
    pub(crate) fn from_connected_pipe(server: &NamedPipeServer) -> anyhow::Result<Self> {
        let process_id = connected_pipe_client_process_id(server).context("failed to query pipe client process id")?;
        let process = Arc::new(
            Process::get_by_pid(process_id, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
                .with_context(|| format!("failed to open pipe client process {process_id}"))?,
        );
        Self::ensure_process_active(process_id, &process)?;
        let process_instance = process_instance_identity(process_id, &process)?;
        let token = connected_pipe_client_token(server).context("failed to capture pipe client token")?;
        let client = Self::from_process_and_token(process_instance, Arc::clone(&process), token)?;
        let confirmed_process_id =
            connected_pipe_client_process_id(server).context("failed to confirm pipe client process id")?;
        if confirmed_process_id != process_id {
            bail!("pipe client process changed while its identity was captured");
        }
        Self::ensure_process_active(process_id, &process)?;
        let confirmation = Process::get_by_pid(process_id, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
            .with_context(|| format!("failed to reopen pipe client process {process_id}"))?;
        ensure_same_process_instance(process_instance, process_instance_identity(process_id, &confirmation)?)?;
        Ok(client)
    }

    fn ensure_process_active(process_id: u32, process: &Process) -> anyhow::Result<()> {
        match process
            .wait(Some(0))
            .with_context(|| format!("failed to query pipe client process {process_id} state"))?
        {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => bail!("pipe client process {process_id} exited while its identity was captured"),
            status => bail!("unexpected wait status {status:?} for pipe client process {process_id}"),
        }
    }

    #[cfg(test)]
    fn from_process_id(process_id: u32) -> anyhow::Result<Self> {
        let process = Arc::new(
            Process::get_by_pid(process_id, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
                .with_context(|| format!("failed to open pipe client process {process_id}"))?,
        );
        let token = process
            .token(TOKEN_QUERY | TOKEN_DUPLICATE)
            .with_context(|| format!("failed to open pipe client process {process_id} token"))?;
        Self::from_process_and_token(process_instance_identity(process_id, &process)?, process, token)
    }

    fn from_process_and_token(
        process_instance: ProcessInstanceIdentity,
        process: Arc<Process>,
        token: Token,
    ) -> anyhow::Result<Self> {
        let process_id = process_instance.process_id;
        let process_token = process
            .token(TOKEN_QUERY | TOKEN_DUPLICATE)
            .with_context(|| format!("failed to open pipe client process {process_id} token"))?;
        let process_authentication_id = process_token
            .statistics()
            .with_context(|| format!("failed to query pipe client process {process_id} token identity"))?
            .AuthenticationId;
        let connected_authentication_id = token
            .statistics()
            .context("failed to query connected pipe client token identity")?
            .AuthenticationId;
        if process_authentication_id.LowPart != connected_authentication_id.LowPart
            || process_authentication_id.HighPart != connected_authentication_id.HighPart
        {
            bail!("pipe client process token does not match the connected client token");
        }
        let executable_path = process
            .exe_path()
            .with_context(|| format!("failed to query pipe client process {process_id} executable path"))?;
        let executable_file = Arc::new(open_executable_file(&executable_path).with_context(|| {
            format!(
                "failed to retain pipe client executable '{}'",
                executable_path.display()
            )
        })?);
        let user_sid = token
            .sid_and_attributes()
            .with_context(|| format!("failed to query pipe client process {process_id} token user"))?
            .sid;
        let is_elevated = token
            .is_elevated()
            .with_context(|| format!("failed to query pipe client process {process_id} token elevation"))?;
        let administrators_sid =
            Sid::from_well_known(WinBuiltinAdministratorsSid, None).context("resolve Administrators SID")?;
        let is_administrator = token
            .is_member(&administrators_sid)
            .with_context(|| format!("failed to query pipe client process {process_id} Administrators membership"))?;
        let process_user_sid = process_token
            .sid_and_attributes()
            .with_context(|| format!("failed to query pipe client process {process_id} token user"))?
            .sid;
        let process_is_elevated = process_token
            .is_elevated()
            .with_context(|| format!("failed to query pipe client process {process_id} token elevation"))?;
        let process_is_administrator = process_token
            .is_member(&administrators_sid)
            .with_context(|| format!("failed to query pipe client process {process_id} Administrators membership"))?;
        if process_user_sid != user_sid
            || process_is_elevated != is_elevated
            || process_is_administrator != is_administrator
        {
            bail!("pipe client process security context does not match the connected client token");
        }

        Ok(Self {
            process_id,
            process_creation_time: process_instance.creation_time,
            process: Some(process),
            executable_path,
            executable_file: Some(executable_file),
            user_sid,
            is_elevated,
            is_administrator,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_current_process() -> anyhow::Result<Self> {
        Self::from_process_id(std::process::id())
    }

    /// Build a synthetic pipe client claiming an elevated, Administrators-member token
    /// for `user_sid`/`executable_path`, regardless of the real privilege of the process
    /// actually running the test. Used only by tests elsewhere in the crate (e.g.
    /// `server::mod::tests`) that need to exercise post-elevation-gate logic
    /// deterministically -- independent of whether the host actually running the test
    /// suite happens to be elevated (item 23's core concern, applied to unit tests too).
    /// Gated the same way as its only callers: only meaningful with the signature bypass
    /// active (see `server::tests::elevation_gating`'s own module doc comment).
    #[cfg(all(test, feature = "dev-skip-broker-signature"))]
    pub(crate) fn test_elevated_administrator(user_sid: Sid, executable_path: PathBuf) -> Self {
        Self {
            process_id: 0,
            process_creation_time: SystemTime::UNIX_EPOCH,
            process: None,
            executable_path,
            executable_file: None,
            user_sid,
            is_elevated: true,
            is_administrator: true,
        }
    }

    /// Same as [`PipeClient::test_elevated_administrator`], but for a token that is
    /// authenticated yet neither elevated nor an Administrators member: the ordinary,
    /// unprivileged case `AdministratorRequired` must still reject.
    #[cfg(all(test, feature = "dev-skip-broker-signature"))]
    pub(crate) fn test_unelevated(user_sid: Sid, executable_path: PathBuf) -> Self {
        Self {
            process_id: 0,
            process_creation_time: SystemTime::UNIX_EPOCH,
            process: None,
            executable_path,
            executable_file: None,
            user_sid,
            is_elevated: false,
            is_administrator: false,
        }
    }

    /// Security identifier of the authenticated pipe client user, captured at connect.
    pub(crate) fn user_sid(&self) -> &Sid {
        &self.user_sid
    }

    /// File path of the authenticated pipe client executable, captured at connect.
    pub(crate) fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    /// Whether the pipe client presented an elevated, Administrators-member token at
    /// connect. Policy management writes require both; inspection/validation does not.
    pub(crate) fn is_elevated_administrator(&self) -> bool {
        self.is_elevated && self.is_administrator
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
        self.validate_process_instance()?;
        if signature_validation_skipped(skip_signature_validation) {
            warn!("DEBUG MODE: Skipping package broker client signature validation");
            return Ok(());
        }

        let thumbprint = validate_devolutions_authenticode_signature(&self.executable_path)?;

        debug!(
            process_id = self.process_id,
            process_creation_time = ?self.process_creation_time,
            executable = %self.executable_path.display(),
            certificate_thumbprint = %thumbprint,
            "Package broker pipe client authenticated"
        );

        Ok(())
    }

    fn validate_process_instance(&self) -> anyhow::Result<()> {
        let Some(process) = &self.process else {
            return Ok(());
        };

        Self::ensure_process_active(self.process_id, process)?;
        ensure_same_process_instance(
            ProcessInstanceIdentity {
                process_id: self.process_id,
                creation_time: self.process_creation_time,
            },
            process_instance_identity(self.process_id, process)?,
        )
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

        let actual_id = if let Some(executable_file) = &self.executable_file {
            file_id_from_handle(executable_file).context("failed to query retained pipe client executable identity")?
        } else {
            file_id(&self.executable_path).with_context(|| {
                format!(
                    "failed to query pipe client executable '{}' file identity",
                    self.executable_path.display()
                )
            })?
        };
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

fn connected_pipe_client_token(server: &NamedPipeServer) -> anyhow::Result<Token> {
    use std::os::windows::io::AsRawHandle as _;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::RevertToSelf;
    use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;

    struct ImpersonationGuard;

    impl Drop for ImpersonationGuard {
        fn drop(&mut self) {
            // SAFETY: The current thread is impersonating the connected pipe client.
            if revert_failure_requires_abort(unsafe { RevertToSelf() }.is_err()) {
                std::process::abort();
            }
        }
    }

    // SAFETY: `server` is a connected named-pipe server instance.
    unsafe { ImpersonateNamedPipeClient(HANDLE(server.as_raw_handle())) }
        .context("failed to impersonate named-pipe client")?;
    let _guard = ImpersonationGuard;

    Thread::current()
        .token(TOKEN_QUERY | TOKEN_DUPLICATE, true)
        .context("failed to open the impersonated pipe client token")
}

fn revert_failure_requires_abort(revert_failed: bool) -> bool {
    revert_failed
}

fn process_instance_identity(process_id: u32, process: &Process) -> anyhow::Result<ProcessInstanceIdentity> {
    Ok(ProcessInstanceIdentity {
        process_id,
        creation_time: process
            .creation_time()
            .with_context(|| format!("failed to query pipe client process {process_id} creation time"))?,
    })
}

fn ensure_same_process_instance(
    expected: ProcessInstanceIdentity,
    actual: ProcessInstanceIdentity,
) -> anyhow::Result<()> {
    if expected != actual {
        bail!("pipe client process instance changed while its identity was captured");
    }
    Ok(())
}

fn open_executable_file(path: &Path) -> anyhow::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .context("failed to open executable without write or delete sharing")
}

/// Resolve an account name (`DOMAIN\user` or `user`) to its security identifier.
fn resolve_account_sid(account_name: &str) -> anyhow::Result<Sid> {
    let account_name = U16CString::from_str(account_name).context("account name contains an interior NUL character")?;
    let account = lookup_account_by_name(&account_name).context("failed to look up account by name")?;
    Ok(account.sid.clone())
}

/// Queries the volume serial number and 128-bit file ID uniquely identifying the file.
fn file_id(path: &Path) -> anyhow::Result<FILE_ID_INFO> {
    use windows::Win32::Storage::FileSystem::FILE_SHARE_DELETE;

    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .open(path)?;
    file_id_from_handle(&file)
}

fn file_id_from_handle(file: &File) -> anyhow::Result<FILE_ID_INFO> {
    use std::os::windows::io::AsRawHandle as _;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{FileIdInfo, GetFileInformationByHandleEx};

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
    use windows::Win32::Security::WinWorldSid;

    use super::*;
    use crate::test_support::system_sid;

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
            process_creation_time: SystemTime::UNIX_EPOCH,
            process: None,
            executable_path: PathBuf::new(),
            executable_file: None,
            user_sid: system_sid(),
            is_elevated: true,
            is_administrator: true,
        }
    }

    #[tokio::test]
    async fn connected_pipe_identity_uses_the_impersonated_client_token() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        use windows::Win32::Storage::FileSystem::SECURITY_IMPERSONATION;

        let pipe_name = format!(
            r"\\.\pipe\Devolutions.Now.PackageBroker.auth-test.{}",
            uuid::Uuid::new_v4()
        );
        let server = ServerOptions::new().create(&pipe_name).expect("create test pipe");
        let client_task = tokio::spawn(async move {
            ClientOptions::new()
                .security_qos_flags(SECURITY_IMPERSONATION.0)
                .open(&pipe_name)
        });

        server.connect().await.expect("connect test pipe");
        let _client = client_task.await.expect("join test client").expect("open test pipe");

        let expected = PipeClient::from_current_process().expect("capture current process identity");
        let actual = PipeClient::from_connected_pipe(&server).expect("capture connected pipe client identity");

        assert_eq!(actual.process_id, expected.process_id);
        assert_eq!(actual.user_sid, expected.user_sid);
        assert_eq!(actual.is_elevated, expected.is_elevated);
        assert_eq!(actual.is_administrator, expected.is_administrator);
        assert!(
            Thread::current().token(TOKEN_QUERY, true).is_err(),
            "pipe-client impersonation must be reverted before returning"
        );
    }

    #[test]
    fn mismatched_process_creation_time_is_rejected() {
        let expected = ProcessInstanceIdentity {
            process_id: 42,
            creation_time: SystemTime::UNIX_EPOCH,
        };
        let actual = ProcessInstanceIdentity {
            process_id: 42,
            creation_time: SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(100),
        };

        ensure_same_process_instance(expected, actual)
            .expect_err("a recycled PID with a different creation time must be rejected");
    }

    #[test]
    fn failed_impersonation_reversion_requires_abort() {
        assert!(revert_failure_requires_abort(true));
        assert!(!revert_failure_requires_abort(false));
    }

    #[test]
    fn exited_process_cannot_supply_executable_identity() {
        let mut child = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "exit 0"])
            .spawn()
            .expect("start short-lived child");
        let process_id = child.id();
        let process = Process::get_by_pid(process_id, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
            .expect("open child while it is running");
        child.wait().expect("wait for child");

        let error = PipeClient::ensure_process_active(process_id, &process)
            .expect_err("an exited process cannot authenticate a connected pipe client");
        assert!(error.to_string().contains("exited while its identity was captured"));
    }

    #[test]
    fn pipe_client_retains_process_handle_and_rejects_exit() {
        let mut child = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
            .spawn()
            .expect("start child");
        let client = PipeClient::from_process_id(child.id()).expect("capture child identity");
        assert!(
            client.process.is_some(),
            "the exact authenticated process handle must be retained"
        );

        child.kill().expect("terminate child");
        child.wait().expect("wait for child");

        client
            .validate_process_instance()
            .expect_err("an inherited pipe cannot outlive the authenticated process");
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
                process_creation_time: SystemTime::UNIX_EPOCH,
                process: None,
                executable_path: std::env::current_exe().expect("current test executable path"),
                executable_file: None,
                user_sid: client_user_sid(),
                is_elevated: true,
                is_administrator: true,
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
