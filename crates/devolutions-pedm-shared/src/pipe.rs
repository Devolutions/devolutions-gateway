//! Access rules for the PEDM named pipe, shared by the server and its clients.

use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, IntoRawHandle as _};

use anyhow::{Context as _, bail};
use tokio::net::windows::named_pipe::NamedPipeClient;
use win_api_wrappers::raw::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use win_api_wrappers::raw::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use win_api_wrappers::raw::Win32::Security::{
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use win_api_wrappers::raw::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, READ_CONTROL, SECURITY_IMPERSONATION,
    SYNCHRONIZE,
};

/// Default name of the PEDM pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\DevolutionsPEDM";

/// Access the PEDM server grants to clients, and the access clients request.
///
/// `CreateFileW` always adds `FILE_READ_ATTRIBUTES` and `SYNCHRONIZE`, and [`verify_server`] needs `READ_CONTROL`.
/// It excludes `FILE_APPEND_DATA`, which is `FILE_CREATE_PIPE_INSTANCE` on a pipe, so only the server creates pipe instances.
/// It also excludes `FILE_WRITE_ATTRIBUTES`, since no client changes the pipe read mode.
pub const CLIENT_ACCESS: u32 =
    FILE_READ_DATA.0 | FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0 | READ_CONTROL.0;

/// Open the client end of a PEDM pipe, requesting only [`CLIENT_ACCESS`].
///
/// The server impersonates its clients to act on their behalf, so clients allow the `SecurityImpersonation` level.
/// Call [`verify_server`] before sending anything.
pub fn open_client(pipe_name: &str) -> std::io::Result<NamedPipeClient> {
    let file = OpenOptions::new()
        .access_mode(CLIENT_ACCESS)
        .custom_flags(FILE_FLAG_OVERLAPPED.0)
        .security_qos_flags(SECURITY_IMPERSONATION.0)
        .open(pipe_name)?;

    // SAFETY: The handle is a freshly opened overlapped named pipe client handle,
    // and its ownership is transferred to the returned client.
    unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }
}

/// Check that the pipe server is the PEDM service, before sending anything to it.
///
/// A standard user cannot open the process or token of a LocalSystem service, so the check relies on the pipe owner instead.
/// It must be SYSTEM or the Administrators group: a standard user cannot assign either, and LocalSystem defaults to Administrators.
pub fn verify_server(pipe: &NamedPipeClient) -> anyhow::Result<()> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    // SAFETY: The handle is a valid named pipe handle owned by `pipe`, and the out pointers are valid for writes.
    let result = unsafe {
        GetSecurityInfo(
            HANDLE(pipe.as_raw_handle().cast()),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    result.ok().context("failed to query the PEDM pipe owner")?;

    // SAFETY: On success, `owner` points into `descriptor`, which is still allocated.
    let is_system = unsafe { IsWellKnownSid(owner, WinLocalSystemSid) }.as_bool();
    // SAFETY: Same as above.
    let is_administrators = unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) }.as_bool();

    // SAFETY: On success, `GetSecurityInfo` allocates `descriptor` with `LocalAlloc`, and it is not used afterwards.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };

    if !is_system && !is_administrators {
        bail!("the PEDM pipe server is not trusted because the pipe is not owned by SYSTEM or Administrators");
    }

    Ok(())
}
