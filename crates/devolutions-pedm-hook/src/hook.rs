use std::path::Path;

use devolutions_pedm_shared::client::models::{LaunchPayload, StartupInfoDto};
use devolutions_pedm_shared::client::{self};
use tracing::error;
use win_api_wrappers::process::Process;
use win_api_wrappers::raw::Win32::Foundation::{ERROR_INVALID_DATA, HWND};
use win_api_wrappers::raw::Win32::System::Rpc::{RPC_ASYNC_STATE, RPC_S_OK, RpcAsyncCompleteCall};
use win_api_wrappers::raw::Win32::System::Threading::{
    CREATE_SUSPENDED, PROCESS_ALL_ACCESS, PROCESS_CREATION_FLAGS, THREAD_ALL_ACCESS,
};
use win_api_wrappers::raw::core::{HRESULT, PCWSTR};
use win_api_wrappers::rpc::{RPC_BINDING_HANDLE, RpcBindingHandle};
use win_api_wrappers::thread::Thread;
use win_api_wrappers::utils::SafeWindowsString;

use anyhow::Result;

use crate::appinfo::{APP_PROCESS_INFORMATION, APP_STARTUP_INFO};

/// In Appinfo.dll, RAiLaunchAdminProcess sets the elevation type to 6.
/// The name is unofficial.
const ELEVATION_TYPE_SUCCESS: u32 = 6;

pub unsafe extern "system" fn rai_launch_admin_process(
    state: *mut RPC_ASYNC_STATE,                       // in, out
    binding: RPC_BINDING_HANDLE,                       // in
    executable_path: PCWSTR,                           // in
    command_line: PCWSTR,                              // in
    start_flags: u32,                                  // in
    creation_flags: u32,                               // in
    working_directory: PCWSTR,                         // in
    window_station: PCWSTR,                            // in
    startup_info: *const APP_STARTUP_INFO,             // in
    hwnd: HWND,                                        // in
    timeout: u32,                                      // in
    process_information: *mut APP_PROCESS_INFORMATION, // out
    elevation_type: *mut u32,                          // out
) {
    // SAFETY: All pointers are assumed valid by the function contract.
    let result = unsafe {
        rai_launch_admin_process_handler(
            state,
            RpcBindingHandle(binding),
            executable_path.to_path_safe().ok().as_deref(),
            command_line.to_string().ok().as_deref(),
            start_flags,
            PROCESS_CREATION_FLAGS(creation_flags),
            working_directory.to_path_safe().ok().as_deref(),
            window_station.to_string().ok().as_deref(),
            &*startup_info,
            hwnd,
            timeout,
            &mut *process_information,
            &mut *elevation_type,
        )
    };

    let reply: i32 = match result {
        Ok(()) => RPC_S_OK.0,
        Err(error) => {
            error!(%error, "Launch admin process failed");
            let win_err = error.root_cause().downcast_ref::<win_api_wrappers::raw::core::Error>();
            match win_err {
                Some(w) => w.code().0,
                None => ERROR_INVALID_DATA.0 as _,
            }
        }
    };

    let status = unsafe { RpcAsyncCompleteCall(state, Some(&reply as *const i32 as _)) };

    if status != RPC_S_OK {
        error!(?status, "RPC error when completing async call");
    }
}

#[expect(clippy::too_many_arguments, reason = "matching Windows API signature")]
fn rai_launch_admin_process_handler(
    _state: *mut RPC_ASYNC_STATE, // in, out
    binding: RpcBindingHandle,    // in
    executable_path: Option<&Path>,
    command_line: Option<&str>,                        // in
    _start_flags: u32,                                 // in
    creation_flags: PROCESS_CREATION_FLAGS,            // in
    working_directory: Option<&Path>,                  // in
    window_station: Option<&str>,                      // in
    startup_info: &APP_STARTUP_INFO,                   // in
    _hwnd: HWND,                                       // in
    _timeout: u32,                                     // in
    process_information: &mut APP_PROCESS_INFORMATION, // out
    elevation_type: &mut u32,                          // out
) -> Result<()> {
    let caller = binding.inquire_caller()?;

    let startup_info = StartupInfoDto {
        desktop: window_station.map(str::to_string),
        title: startup_info.Title.to_string_safe().ok(),
        x: startup_info.X,
        y: startup_info.Y,
        x_size: startup_info.XSize,
        y_size: startup_info.YSize,
        x_count_chars: startup_info.XCountChars,
        y_count_chars: startup_info.YCountChars,
        fill_attribute: startup_info.FillAttribute,
        flags: startup_info.Flags & 0xfffffcff, // as decompiler says (not STARTF_PREVENTPINNING and STARTF_TITLEISAPPID)
        show_window: startup_info.ShowWindow as _,
        parent_pid: Some(caller.client_pid),
    };

    let ctx = binding.impersonate_client()?;

    let proc_info = client::block_req(
        client::client().default_api().launch_post(LaunchPayload {
            executable_path: executable_path.and_then(|x| x.as_os_str().to_str()).map(str::to_owned),
            command_line: command_line.map(str::to_owned),
            creation_flags: (creation_flags | CREATE_SUSPENDED).0,
            working_directory: working_directory
                .and_then(|x| x.as_os_str().to_str())
                .map(str::to_owned),
            startup_info: Some(startup_info),
        }),
    )?;

    drop(ctx);

    let proc_info =
        proc_info.map_err(|x| win_api_wrappers::raw::core::Error::from_hresult(HRESULT(x.win32_error as _)))?;

    let mut process = Process::get_by_pid(proc_info.process_id, PROCESS_ALL_ACCESS)?;
    let mut thread = Thread::get_by_id(proc_info.thread_id, THREAD_ALL_ACCESS)?;

    thread.resume()?;

    process_information.ProcessHandle = process.handle.raw();
    process_information.ThreadHandle = thread.handle.raw();
    process_information.ProcessId = proc_info.process_id;
    process_information.ThreadId = proc_info.thread_id;

    process.handle.leak();
    thread.handle.leak();

    *elevation_type = ELEVATION_TYPE_SUCCESS;

    Ok(())
}
