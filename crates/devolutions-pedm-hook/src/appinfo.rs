use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

use anyhow::{bail, Result};
use retour::GenericDetour;
use win_api_wrappers::{
    raw::{
        core::{GUID, PCWSTR},
        Win32::{
            Foundation::{HANDLE, HWND},
            System::Rpc::{RPC_ASYNC_STATE, RPC_IF_CALLBACK_FN, RPC_SERVER_INTERFACE, RPC_STATUS},
        },
    },
    rpc::RpcServerInterfacePointer,
    win::module_symbol,
};

/// https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/appinfo/appinfo.idl
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct MONITOR_POINT {
    pub MonitorLeft: u32,
    pub MonitorRight: u32,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct APP_STARTUP_INFO {
    pub Title: PCWSTR,
    pub X: u32,
    pub Y: u32,
    pub XSize: u32,
    pub YSize: u32,
    pub XCountChars: u32,
    pub YCountChars: u32,
    pub FillAttribute: u32,
    pub Flags: u32,
    pub ShowWindow: u16,
    pub MonitorPoint: MONITOR_POINT,
}

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct APP_PROCESS_INFORMATION {
    pub ProcessHandle: HANDLE,
    pub ThreadHandle: HANDLE,
    pub ProcessId: u32,
    pub ThreadId: u32,
}

/// Built from https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/appinfo/x64/appinfo64.h
pub type RAiLaunchAdminProcess = extern "C" fn(
    async_handle: *const RPC_ASYNC_STATE,
    binding: *const RPC_SERVER_INTERFACE,
    executable_path: PCWSTR,
    command_line: PCWSTR,
    start_flags: u32,
    creation_flags: u32,
    current_directory: PCWSTR,
    window_station: PCWSTR,
    startup_info: *const APP_STARTUP_INFO,
    window: HWND,
    timeout: u32,
    process_information: *mut APP_PROCESS_INFORMATION,
    elevation_type: *mut u32,
);

static INTERFACE_HANDLES: Mutex<Vec<RpcServerInterfacePointer>> = Mutex::new(Vec::new());

type RpcServerRegisterIfExHook = unsafe extern "system" fn(
    ifspec: *const RPC_SERVER_INTERFACE,
    mgrtypeuuid: *const GUID,
    mgrepv: *const c_void,
    flags: u32,
    maxcalls: u32,
    ifcallback: RPC_IF_CALLBACK_FN,
) -> RPC_STATUS;

pub fn rpc_server_register_if_ex_hook() -> &'static GenericDetour<RpcServerRegisterIfExHook> {
    static HOOK: OnceLock<GenericDetour<RpcServerRegisterIfExHook>> = OnceLock::new();

    HOOK.get_or_init(|| unsafe {
        let orig = module_symbol::<RpcServerRegisterIfExHook>("rpcrt4.dll", "RpcServerRegisterIfEx").unwrap();

        GenericDetour::new(orig, rpc_server_register_if_ex as _).expect("RpcServerRegisterIfEx hook failed")
    })
}

extern "system" fn rpc_server_register_if_ex(
    ifspec: *const RPC_SERVER_INTERFACE,
    mgrtypeuuid: *const GUID,
    mgrepv: *const c_void,
    flags: u32,
    maxcalls: u32,
    ifcallback: RPC_IF_CALLBACK_FN,
) -> RPC_STATUS {
    {
        let mut handles = INTERFACE_HANDLES.lock().unwrap();
        handles.push(RpcServerInterfacePointer {
            raw: unsafe { NonNull::new_unchecked(ifspec.cast_mut()) },
        });
    }

    unsafe { rpc_server_register_if_ex_hook().call(ifspec, mgrtypeuuid, mgrepv, flags, maxcalls, ifcallback) }
}

type FnAiEnableDesktopRpcInterface = unsafe extern "system" fn() -> RPC_STATUS;
pub unsafe fn ai_enable_desktop_rpc_interface() -> RPC_STATUS {
    static FUN: OnceLock<FnAiEnableDesktopRpcInterface> = OnceLock::new();

    let init = || module_symbol::<FnAiEnableDesktopRpcInterface>("appinfo.dll", "AiEnableDesktopRpcInterface").unwrap();

    FUN.get_or_init(init)()
}

type FnAiDisableDesktopRpcInterface = unsafe extern "system" fn();
pub unsafe fn ai_disable_desktop_rpc_interface() {
    static FUN: OnceLock<FnAiDisableDesktopRpcInterface> = OnceLock::new();

    let init =
        || module_symbol::<FnAiDisableDesktopRpcInterface>("appinfo.dll", "AiDisableDesktopRpcInterface").unwrap();

    FUN.get_or_init(init)()
}

pub unsafe fn dump_interfaces() -> Result<Box<[RpcServerInterfacePointer]>> {
    // TODO: This is not clean. Add another mutex to guard the actual handles
    {
        let mut handles = INTERFACE_HANDLES.lock().unwrap();
        handles.clear();
    }

    ai_disable_desktop_rpc_interface();
    if let Err(err) = rpc_server_register_if_ex_hook().enable() {
        let _ = ai_enable_desktop_rpc_interface();
        bail!(err);
    }

    let _ = ai_enable_desktop_rpc_interface();
    if let Err(err) = rpc_server_register_if_ex_hook().disable() {
        bail!(err);
    }

    let mut handles = INTERFACE_HANDLES.lock().unwrap();

    let result = handles.to_vec().into_boxed_slice();
    handles.clear();

    Ok(result)
}
