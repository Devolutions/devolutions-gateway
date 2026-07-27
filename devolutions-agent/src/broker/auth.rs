//! Package broker pipe client authentication.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use now_policy_api::{ClientContext, PackageRequest, StatusRequest};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tracing::{debug, warn};
use win_api_wrappers::process::Process;
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::Storage::FileSystem::FILE_ID_INFO;
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
}
