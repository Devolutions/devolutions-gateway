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
use win_api_wrappers::raw::Win32::System::Pipes::GetNamedPipeServerProcessId;
use win_api_wrappers::raw::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
};
use win_api_wrappers::raw::core::Owned;
use win_api_wrappers::utils::WideString;

/// Default name of the PEDM pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\DevolutionsPEDM";

/// Name of the Devolutions Agent service, whose process serves the PEDM pipe.
pub const AGENT_SERVICE_NAME: &str = "DevolutionsAgent";

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
/// The pipe must be owned by SYSTEM or Administrators ([`verify_owner`]),
/// and its server must be the process of the Devolutions Agent service ([`verify_server_process`]).
pub fn verify_server(pipe: &NamedPipeClient) -> anyhow::Result<()> {
    verify_owner(pipe)?;
    verify_server_process(pipe, AGENT_SERVICE_NAME)
}

/// Check that the server process of `pipe` is the running process of the `service_name` service.
///
/// A pipe instance shares the security descriptor of its name, so the owner alone does not identify which process created an instance.
/// A standard user cannot open the process or token of a LocalSystem service, but can query the process ID of a service.
pub fn verify_server_process(pipe: &NamedPipeClient, service_name: &str) -> anyhow::Result<()> {
    let server_process_id = server_process_id(pipe)?;
    let service_process_id = service_process_id(service_name)?;

    if server_process_id != service_process_id {
        bail!(
            "the PEDM pipe server is not trusted because it is not the {service_name} service process (server process {server_process_id}, service process {service_process_id})"
        );
    }

    Ok(())
}

/// Return the ID of the process serving the client end of a pipe.
pub fn server_process_id(pipe: &NamedPipeClient) -> anyhow::Result<u32> {
    let mut process_id = 0;

    // SAFETY: The handle is a valid named pipe client handle owned by `pipe`, and `process_id` is valid for writes.
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle().cast()), &mut process_id) }
        .context("failed to query the PEDM pipe server process")?;

    Ok(process_id)
}

/// Return the process ID of a running service.
pub fn service_process_id(service_name: &str) -> anyhow::Result<u32> {
    let service_name_wide = WideString::from(service_name);

    // SAFETY: FFI call with no outstanding preconditions.
    let manager = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT) }
        .context("failed to connect to the service control manager")?;
    // SAFETY: On success, `OpenSCManagerW` returns a handle owned by the caller.
    let manager = unsafe { Owned::new(manager) };

    // SAFETY: `manager` is a valid handle and `service_name_wide` is a valid NUL-terminated UTF-16 string.
    let service = unsafe { OpenServiceW(*manager, service_name_wide.as_pcwstr(), SERVICE_QUERY_STATUS) }
        .with_context(|| format!("failed to open the {service_name} service"))?;
    // SAFETY: On success, `OpenServiceW` returns a handle owned by the caller.
    let service = unsafe { Owned::new(service) };

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0;

    // SAFETY: The slice covers exactly `status`, which is valid for writes and outlives the slice.
    // `SERVICE_STATUS_PROCESS` is plain data, so any bytes written to it form a valid value.
    let buffer =
        unsafe { core::slice::from_raw_parts_mut((&raw mut status).cast::<u8>(), size_of::<SERVICE_STATUS_PROCESS>()) };

    // SAFETY: `service` is a valid handle, and `buffer` is large enough for `SC_STATUS_PROCESS_INFO`.
    unsafe { QueryServiceStatusEx(*service, SC_STATUS_PROCESS_INFO, Some(buffer), &mut bytes_needed) }
        .with_context(|| format!("failed to query the {service_name} service status"))?;

    if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
        bail!("the {service_name} service is not running");
    }

    Ok(status.dwProcessId)
}

/// Check that the pipe is owned by SYSTEM or the Administrators group.
///
/// A standard user cannot assign either owner, and LocalSystem defaults to Administrators.
pub fn verify_owner(pipe: &NamedPipeClient) -> anyhow::Result<()> {
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
