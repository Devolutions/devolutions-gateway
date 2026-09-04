//! Package broker pipe client authentication.
//!
//! `ProcessImageFileMapping`, retained-handle Authenticode, and current file and ancestor ACL checks authenticate approved image and file provenance when the broker accepts a connection.
//! They do not attest runtime code integrity or prove that the current stream bytes are the bytes originally mapped into the process.
//! The checks reject an untrusted caller that creates an image section and then rewrites the same stream because the retained file or its path fails the trusted-writer policy.
//!
//! Same-integrity injection or hollowing of an approved non-PPL process is outside signed-image authentication.
//! For read, management, and validation operations, controlling that process grants no authority beyond what the same local user can exercise by running signed UniGetUI.
//! Policy replacement independently requires the actual pipe client token to be elevated with the Administrators group enabled.
//! A standard or medium-integrity user who injects a medium-integrity approved process therefore cannot replace policy.
//! SYSTEM and elevated-Administrator injection are inside the policy-write trust boundary.
//! Stronger runtime integrity requires an OS-enforced boundary such as an appropriate WDAC policy or compatible PPL protection levels for the caller and broker.
//!
//! Current ACL verification cannot reconstruct historical write access.
//! The provenance guarantee assumes the approved binary and every ancestor were secure when created and have never been writable by an untrusted principal.
//! After an ACL or path compromise, operators must reinstall or remediate the deployment before trusting it again.
//! Installer and package verification should establish secure deployment, while these checks fail closed on present insecurity.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context as _, bail};
use devolutions_agent_shared::windows::code_signing::validate_devolutions_authenticode_signature_for_file;
use now_policy_api::{CancelRequest, ClientContext, PackageRequest, StatusRequest};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tracing::{debug, warn};
use widestring::U16CString;
use win_api_wrappers::identity::account::lookup_account_by_name;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use win_api_wrappers::thread::Thread;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{GENERIC_READ, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY, WinBuiltinAdministratorsSid};
use windows::Win32::Storage::FileSystem::{
    FILE_EXECUTE, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::Threading::{
    PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

use crate::policy_security::RetainedExecutableSecurity;

const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);
const PROCESS_IDENTITY_ACCESS: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(
    PROCESS_QUERY_INFORMATION.0 | PROCESS_QUERY_LIMITED_INFORMATION.0 | PROCESS_VM_READ.0 | PROCESS_SYNCHRONIZE.0,
);

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
    executable_security: Option<Arc<RetainedExecutableSecurity>>,
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
    /// This unauthenticated identity capture performs blocking process and local-filesystem checks,
    /// so callers must run it as bounded blocking work.
    /// Account-name resolution remains deferred because it may contact a domain controller.
    pub(crate) fn from_connected_pipe(
        server: &NamedPipeServer,
        skip_signature_validation: bool,
    ) -> anyhow::Result<Self> {
        Self::from_connected_pipe_with_security(server, !signature_validation_skipped(skip_signature_validation))
    }

    fn from_connected_pipe_with_security(
        server: &NamedPipeServer,
        enforce_executable_security: bool,
    ) -> anyhow::Result<Self> {
        let process_id = connected_pipe_client_process_id(server).context("failed to query pipe client process id")?;
        let process = Arc::new(
            Process::get_by_pid(process_id, PROCESS_IDENTITY_ACCESS).with_context(|| {
                format!("failed to open pipe client process {process_id} for image identity capture")
            })?,
        );
        Self::ensure_process_active(process_id, &process)?;
        let process_instance = process_instance_identity(process_id, &process)?;
        let token = connected_pipe_client_token(server).context("failed to capture pipe client token")?;
        let client = Self::from_process_and_token(
            process_instance,
            Arc::clone(&process),
            token,
            enforce_executable_security,
        )?;
        let confirmed_process_id =
            connected_pipe_client_process_id(server).context("failed to confirm pipe client process id")?;
        if confirmed_process_id != process_id {
            bail!("pipe client process changed while its identity was captured");
        }
        Self::ensure_process_active(process_id, &process)?;
        let confirmation = Process::get_by_pid(process_id, PROCESS_IDENTITY_ACCESS)
            .with_context(|| format!("failed to reopen pipe client process {process_id}"))?;
        ensure_same_process_instance(process_instance, process_instance_identity(process_id, &confirmation)?)?;
        Ok(client)
    }

    #[cfg(test)]
    fn from_connected_pipe_without_executable_security(server: &NamedPipeServer) -> anyhow::Result<Self> {
        Self::from_connected_pipe_with_security(server, false)
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
            Process::get_by_pid(process_id, PROCESS_IDENTITY_ACCESS).with_context(|| {
                format!("failed to open pipe client process {process_id} for image identity capture")
            })?,
        );
        let token = process
            .token(TOKEN_QUERY | TOKEN_DUPLICATE)
            .with_context(|| format!("failed to open pipe client process {process_id} token"))?;
        Self::from_process_and_token(process_instance_identity(process_id, &process)?, process, token, false)
    }

    #[cfg(test)]
    fn from_process_id_with_security(process_id: u32) -> anyhow::Result<Self> {
        let process = Arc::new(
            Process::get_by_pid(process_id, PROCESS_IDENTITY_ACCESS).with_context(|| {
                format!("failed to open pipe client process {process_id} for image identity capture")
            })?,
        );
        let token = process
            .token(TOKEN_QUERY | TOKEN_DUPLICATE)
            .with_context(|| format!("failed to open pipe client process {process_id} token"))?;
        Self::from_process_and_token(process_instance_identity(process_id, &process)?, process, token, true)
    }

    fn from_process_and_token(
        process_instance: ProcessInstanceIdentity,
        process: Arc<Process>,
        token: Token,
        enforce_executable_security: bool,
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
        let (_image_address, mapped_executable_path) = process
            .main_image_mapped_path()
            .with_context(|| format!("failed to query pipe client process {process_id} mapped executable image"))?;
        if !is_supported_local_image_path(&mapped_executable_path) {
            bail!("pipe client process {process_id} mapped executable is not on a supported local volume");
        }
        let executable_file = Arc::new(open_native_executable_file(&mapped_executable_path).with_context(|| {
            format!(
                "failed to retain pipe client process {process_id} mapped executable '{}'",
                executable_path.display()
            )
        })?);
        process.verify_image_file_mapping(&executable_file).with_context(|| {
            format!("pipe client process {process_id} mapped executable file does not match its image")
        })?;
        let executable_security = enforce_executable_security
            .then(|| {
                crate::policy_security::verify_retained_executable_security(
                    &executable_file,
                    "package broker pipe client executable",
                )
                .with_context(|| {
                    format!(
                        "pipe client process {process_id} executable '{}' failed trusted-writer security validation",
                        executable_path.display()
                    )
                })
            })
            .transpose()?
            .map(Arc::new);
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
        process
            .verify_image_file_mapping(&executable_file)
            .with_context(|| format!("pipe client process {process_id} executable image changed during capture"))?;

        Ok(Self {
            process_id,
            process_creation_time: process_instance.creation_time,
            process: Some(process),
            executable_path,
            executable_file: Some(executable_file),
            executable_security,
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
            executable_security: None,
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
            executable_security: None,
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

        self.executable_security
            .as_ref()
            .context("pipe client executable trusted-writer security guard is not retained")?;
        let executable_file = self
            .executable_file
            .as_deref()
            .context("pipe client executable handle is not retained")?;
        let thumbprint = validate_devolutions_authenticode_signature_for_file(&self.executable_path, executable_file)?;

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
        .access_mode(GENERIC_READ.0 | FILE_READ_ATTRIBUTES.0 | FILE_EXECUTE.0)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .context("failed to open executable without write or delete sharing")
}

fn open_native_executable_file(native_path: &Path) -> anyhow::Result<File> {
    let mut global_root_path = OsString::from(r"\\?\GLOBALROOT");
    global_root_path.push(native_path.as_os_str());
    open_executable_file(Path::new(&global_root_path))
}

fn is_supported_local_image_path(path: &Path) -> bool {
    let path = path.as_os_str().to_string_lossy().to_ascii_lowercase();
    path.starts_with(r"\device\harddiskvolume") || path.starts_with(r"\device\volume{")
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
            executable_security: None,
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
        let actual = PipeClient::from_connected_pipe_without_executable_security(&server)
            .expect("capture connected pipe client identity");

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

    #[test]
    fn process_image_file_mapping_accepts_the_main_image_and_rejects_a_signed_substitute() {
        let process = Process::get_by_pid(std::process::id(), PROCESS_IDENTITY_ACCESS).expect("open current process");
        let executable =
            open_executable_file(&std::env::current_exe().expect("current executable")).expect("open current image");
        process
            .verify_image_file_mapping(&executable)
            .expect("current executable must match its process image");

        let Some(windows_dir) = std::env::var_os("WINDIR") else {
            return;
        };
        let signed_substitute = open_executable_file(&PathBuf::from(windows_dir).join(r"System32\cmd.exe"))
            .expect("open signed substitute");
        process
            .verify_image_file_mapping(&signed_substitute)
            .expect_err("a different signed image mapping must not substitute for the main executable");
    }

    #[test]
    fn mapped_image_path_rejects_network_and_non_volume_devices() {
        assert!(is_supported_local_image_path(Path::new(
            r"\Device\HarddiskVolume3\Program Files\Devolutions\client.exe"
        )));
        assert!(is_supported_local_image_path(Path::new(
            r"\Device\Volume{01234567-89ab-cdef-0123-456789abcdef}\client.exe"
        )));

        for path in [
            r"\Device\Mup\server\share\client.exe",
            r"\Device\LanmanRedirector\server\share\client.exe",
            r"\Device\WebDavRedirector\server\share\client.exe",
            r"\??\UNC\server\share\client.exe",
            r"\\server\share\client.exe",
        ] {
            assert!(!is_supported_local_image_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn retained_executable_handle_rejects_junction_retarget_to_signed_file() {
        use win_api_wrappers::security::crypt::{
            AuthenticodeSignatureStatus, authenticode_status, authenticode_status_for_file,
        };

        let Some(windows_dir) = std::env::var_os("WINDIR") else {
            return;
        };
        let signed_source = PathBuf::from(windows_dir).join(r"System32\cmd.exe");
        let root = tempfile::tempdir().expect("create retarget test directory");
        let unsigned_dir = root.path().join("unsigned");
        let signed_dir = root.path().join("signed");
        std::fs::create_dir(&unsigned_dir).expect("create unsigned directory");
        std::fs::create_dir(&signed_dir).expect("create signed directory");
        let unsigned_file = unsigned_dir.join("client.exe");
        let signed_file = signed_dir.join("client.exe");
        std::fs::copy(std::env::current_exe().expect("current executable"), &unsigned_file)
            .expect("copy unsigned test executable");
        std::fs::copy(signed_source, &signed_file).expect("copy signed system executable");

        let Ok(signed_status) = authenticode_status(&signed_file) else {
            return;
        };
        if !matches!(signed_status.status, AuthenticodeSignatureStatus::Valid) {
            return;
        }
        if authenticode_status(&unsigned_file)
            .is_ok_and(|status| matches!(status.status, AuthenticodeSignatureStatus::Valid))
        {
            return;
        }

        let junction = root.path().join("client-dir");
        create_directory_junction(&junction, &unsigned_dir);
        let aliased_file = junction.join("client.exe");
        let retained_unsigned = open_executable_file(&unsigned_file).expect("retain unsigned executable");

        std::fs::remove_dir(&junction).expect("remove original junction");
        create_directory_junction(&junction, &signed_dir);
        assert!(
            authenticode_status(&aliased_file)
                .is_ok_and(|status| matches!(status.status, AuthenticodeSignatureStatus::Valid)),
            "retargeted path should resolve to the signed control file"
        );

        let retained_status = authenticode_status_for_file(&aliased_file, &retained_unsigned);
        assert!(
            match retained_status {
                Ok(status) => !matches!(status.status, AuthenticodeSignatureStatus::Valid),
                Err(_) => true,
            },
            "signature verification must reject the retained unsigned object despite the retargeted signed path"
        );

        drop(retained_unsigned);
        std::fs::remove_dir(&junction).expect("remove retargeted junction");
    }

    #[test]
    fn process_capture_uses_the_running_image_instead_of_a_signed_path_replacement() {
        let Some(windows_dir) = std::env::var_os("WINDIR") else {
            return;
        };
        let root = tempfile::tempdir().expect("create process image test directory");
        let launch_path = root.path().join("client.exe");
        let mapped_path = root.path().join("mapped-client.exe");
        std::fs::copy(std::env::current_exe().expect("current test executable"), &launch_path)
            .expect("copy unsigned process image");
        let mut child = std::process::Command::new(&launch_path)
            .args(["--exact", "auth::tests::process_reimaging_child", "--ignored"])
            .spawn()
            .expect("start unsigned copied executable");
        let process = Process::get_by_pid(child.id(), PROCESS_IDENTITY_ACCESS).expect("open child process");
        let reported_launch_path = process.exe_path().expect("query reported process path");
        assert!(crate::policy_security::paths_match_case_insensitive(
            &reported_launch_path,
            &launch_path
        ));

        std::fs::rename(&launch_path, &mapped_path).expect("rename the running mapped executable");
        std::fs::copy(PathBuf::from(&windows_dir).join(r"System32\cmd.exe"), &launch_path)
            .expect("place signed executable at cached launch path");

        let path_status = win_api_wrappers::security::crypt::authenticode_status(&reported_launch_path)
            .expect("verify signed path replacement");
        assert!(matches!(
            path_status.status,
            win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::Valid
        ));
        let (_, mapped_native_path) = process
            .main_image_mapped_path()
            .expect("locate the running image section");
        let mapped_candidate =
            open_native_executable_file(&mapped_native_path).expect("open the running image candidate");
        process
            .verify_image_file_mapping(&mapped_candidate)
            .expect("renamed running image must match its process");
        let signed_replacement = open_executable_file(&launch_path).expect("open signed path replacement");
        process
            .verify_image_file_mapping(&signed_replacement)
            .expect_err("signed replacement must not match the process image file mapping");
        let security_error = PipeClient::from_process_id_with_security(child.id())
            .expect_err("a user-writable process image must fail trusted-writer security");
        assert!(
            security_error
                .to_string()
                .contains("trusted-writer security validation"),
            "unexpected security error: {security_error:#}"
        );

        let client = PipeClient::from_process_id(child.id()).expect("capture section-backed process image identity");
        let retained_id = file_id_from_handle(client.executable_file.as_deref().expect("retained executable"))
            .expect("query retained executable identity");

        assert!(same_file(
            &retained_id,
            &file_id(&mapped_path).expect("query running mapped executable identity")
        ));
        assert!(!same_file(
            &retained_id,
            &file_id(&launch_path).expect("query signed replacement executable identity")
        ));
        let retained_status = win_api_wrappers::security::crypt::authenticode_status_for_file(
            client.executable_path(),
            client.executable_file.as_deref().expect("retained executable"),
        );
        assert!(
            match retained_status {
                Ok(status) => !matches!(
                    status.status,
                    win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::Valid
                ),
                Err(_) => true,
            },
            "section-backed verification must reject the unsigned mapped image"
        );

        child.kill().expect("terminate child");
        child.wait().expect("wait for child");
        drop(client);
    }

    #[test]
    fn same_stream_signed_rewrite_passes_class_44_but_fails_caller_security() {
        use std::ffi::c_void;
        use std::io::{Seek as _, SeekFrom, Write as _};
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsRawHandle as _;

        use win_api_wrappers::handle::Handle;
        use windows::Win32::Foundation::{HANDLE, NTSTATUS};
        use windows::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
        use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_ALL_ACCESS};

        const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
        const PAGE_READONLY: u32 = 0x02;
        const SEC_IMAGE: u32 = 0x0100_0000;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtCreateSection(
                section_handle: *mut HANDLE,
                desired_access: u32,
                object_attributes: *const c_void,
                maximum_size: *const i64,
                section_page_protection: u32,
                allocation_attributes: u32,
                file_handle: HANDLE,
            ) -> NTSTATUS;
            fn NtCreateProcessEx(
                process_handle: *mut HANDLE,
                desired_access: u32,
                object_attributes: *const c_void,
                parent_process: HANDLE,
                flags: u32,
                section_handle: HANDLE,
                debug_port: HANDLE,
                exception_port: HANDLE,
                job_member_level: u32,
            ) -> NTSTATUS;
        }

        let Some(windows_dir) = std::env::var_os("WINDIR") else {
            return;
        };
        let root = tempfile::tempdir().expect("create same-stream test directory");
        let image_path = root.path().join("client.exe");
        let signed_bytes =
            std::fs::read(PathBuf::from(windows_dir).join(r"System32\cmd.exe")).expect("read signed control image");
        let mut unsigned_bytes = signed_bytes.clone();
        let dos_stub_byte = unsigned_bytes
            .get_mut(0x40)
            .expect("signed control image must contain a DOS stub");
        *dos_stub_byte ^= 1;
        std::fs::write(&image_path, &unsigned_bytes).expect("write tampered process image");
        assert!(
            !win_api_wrappers::security::crypt::authenticode_status(&image_path).is_ok_and(|status| matches!(
                status.status,
                win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::Valid
            )),
            "the image used to create the process must not retain a valid signature"
        );

        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .open(&image_path)
            .expect("open image stream for the herpaderping control");

        let mut section_handle = HANDLE::default();
        // SAFETY: All optional pointers are null, `writer` supplies a live file handle,
        // and the returned section handle is wrapped immediately.
        unsafe {
            NtCreateSection(
                &mut section_handle,
                SECTION_ALL_ACCESS,
                std::ptr::null(),
                std::ptr::null(),
                PAGE_READONLY,
                SEC_IMAGE,
                HANDLE(writer.as_raw_handle()),
            )
        }
        .ok()
        .expect("create image section from the unsigned stream");
        // SAFETY: NtCreateSection returned an owned section handle.
        let section = unsafe { Handle::new_owned(section_handle) }.expect("retain image section");

        let mut process_handle = HANDLE::default();
        // SAFETY: GetCurrentProcess has no preconditions and returns a pseudo handle.
        let parent_process = unsafe { GetCurrentProcess() };
        // SAFETY: `section` is a live SEC_IMAGE section and the current-process pseudo
        // handle is valid. The returned process handle is wrapped immediately.
        unsafe {
            NtCreateProcessEx(
                &mut process_handle,
                PROCESS_ALL_ACCESS.0,
                std::ptr::null(),
                parent_process,
                0,
                section.raw(),
                HANDLE::default(),
                HANDLE::default(),
                0,
            )
        }
        .ok()
        .expect("create process from the unsigned image section");
        // SAFETY: NtCreateProcessEx returned an owned process handle.
        let process = Process::from(unsafe { Handle::new_owned(process_handle) }.expect("retain created process"));
        drop(section);

        writer.seek(SeekFrom::Start(0)).expect("rewind image stream");
        writer.write_all(&signed_bytes).expect("write signed replacement bytes");
        writer.sync_all().expect("flush signed replacement bytes");
        drop(writer);

        let (_, mapped_native_path) = process
            .main_image_mapped_path()
            .expect("locate the created process image section");
        let candidate = open_native_executable_file(&mapped_native_path).expect("open same-stream candidate");
        process
            .verify_image_file_mapping(&candidate)
            .expect("class 44 must still match the same rewritten file object");
        let path_status = win_api_wrappers::security::crypt::authenticode_status_for_file(&image_path, &candidate)
            .expect("verify signed rewritten stream");
        assert!(matches!(
            path_status.status,
            win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::Valid
        ));

        let error = crate::policy_security::verify_retained_executable_security(
            &candidate,
            "package broker pipe client executable",
        )
        .expect_err("trusted-writer security must reject a user-writable rewritten image");
        assert!(
            error.to_string().contains("is not a trusted principal"),
            "unexpected security error: {error:#}"
        );
    }

    #[test]
    #[ignore = "helper process for the process-reimaging regression"]
    fn process_reimaging_child() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }

    fn create_directory_junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn mklink");
        assert!(
            status.success(),
            "failed to create junction {} -> {}",
            link.display(),
            target.display()
        );
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
            let client = PipeClient::from_current_process().expect("capture current process with executable handle");

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
