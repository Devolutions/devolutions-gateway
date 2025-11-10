#![allow(non_snake_case)] // WinAPI naming.

use std::ffi::{OsString, c_void};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use std::{ptr, thread};

use devolutions_pedm_shared::client::models::{LaunchPayload, StartupInfoDto};
use devolutions_pedm_shared::client::{self};
use devolutions_pedm_shared::desktop;
use parking_lot::RwLock;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, Receiver, Sender};
use win_api_wrappers::fs::get_system32_path;
use win_api_wrappers::process::{Module, Process};
use win_api_wrappers::raw::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_FAIL, E_INVALIDARG, E_NOTIMPL, E_POINTER, E_UNEXPECTED,
    ERROR_CANCELLED, HINSTANCE,
};
use win_api_wrappers::raw::Win32::Security::TOKEN_QUERY;
use win_api_wrappers::raw::Win32::System::Com::{CoTaskMemFree, IBindCtx, IClassFactory, IClassFactory_Impl};
use win_api_wrappers::raw::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use win_api_wrappers::raw::Win32::System::Ole::{IObjectWithSite, IObjectWithSite_Impl};
use win_api_wrappers::raw::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use win_api_wrappers::raw::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use win_api_wrappers::raw::Win32::UI::Shell::{
    ECF_DEFAULT, ECS_ENABLED, IEnumExplorerCommand, IExplorerCommand, IExplorerCommand_Impl, IShellItemArray,
    SHStrDupW, SIGDN_FILESYSPATH,
};
use win_api_wrappers::raw::core::{
    BOOL, Error, GUID, HRESULT, IUnknown, IUnknown_Vtbl, Interface, PWSTR, Result, implement, interface,
};
use win_api_wrappers::token::Token;
use win_api_wrappers::user;
use win_api_wrappers::utils::{
    Link, Snapshot, WideString, environment_block, expand_environment, expand_environment_path,
};

const IDS_RUN_ELEVATED: u32 = 150;

struct Channels {
    pub tx: Sender<ChannelCommand>,
    pub rx: Mutex<Receiver<ChannelCommand>>,
}

fn channels() -> &'static Channels {
    static CHANNELS: OnceLock<Channels> = OnceLock::new();
    CHANNELS.get_or_init(|| {
        let (tx, rx) = mpsc::channel(10);

        Channels { tx, rx: Mutex::new(rx) }
    })
}

#[interface("0ba604fd-4a5a-4abb-92b1-09ac5c3bf356")]
unsafe trait IElevationContextMenuCommand: IUnknown {}

#[implement(IElevationContextMenuCommand, IExplorerCommand, IObjectWithSite)]
struct ElevationContextMenuCommand {
    guid: GUID,
    site: RwLock<Option<IUnknown>>,
}

impl ElevationContextMenuCommand {
    pub fn new() -> Self {
        Self {
            guid: IElevationContextMenuCommand::IID,
            site: RwLock::new(None),
        }
    }
}

impl IElevationContextMenuCommand_Impl for ElevationContextMenuCommand_Impl {}

impl IExplorerCommand_Impl for ElevationContextMenuCommand_Impl {
    fn GetTitle(&self, _item_array: windows_core::Ref<'_, IShellItemArray>) -> Result<PWSTR> {
        // SAFETY:
        // `DLL_MODULE` is fully initialized and valid for the lifetime of the DLL in the process,
        // and is not mutated after inital initialization
        let hinstance = unsafe { DLL_MODULE };
        let title = user::load_string(hinstance, IDS_RUN_ELEVATED)?.unwrap_or(String::from("Run elevated"));
        let mut title = WideString::from(title.as_str());
        // SAFETY:
        // - `WideString` guarantees proper UTF-16 encoding and null-termination when calling `as_pwstr`
        // - `title` is derived from a valid Rust `String`, guaranteed by the `unwrap` to a default value above,
        // and as such the result of `as_pwstr` doesn't need to be checked against `PWSTR::null`
        // - Memory allocated by `SHStrDupW` will be properly free'd with `CoTaskMemFree` by the COM runtime
        unsafe { SHStrDupW(title.as_pwstr()) }
    }

    fn GetIcon(&self, _item_array: windows_core::Ref<'_, IShellItemArray>) -> Result<PWSTR> {
        let Ok(module) = Module::current() else {
            return Err(E_FAIL.into());
        };

        let Ok(module_path) = module.file_name() else {
            return Err(E_FAIL.into());
        };

        let Some(module_path) = module_path.to_str() else {
            return Err(E_FAIL.into());
        };

        let icon_path = format!("{module_path},-101"); // current dll path + ",-101" (icon resource id)
        let mut icon_path = WideString::from(icon_path.as_str());

        // SAFETY: WideString holds a null-terminated UTF-16 string, and as_pwstr() returns a valid pointer to it.
        unsafe { SHStrDupW(icon_path.as_pwstr()) }
    }

    fn GetToolTip(&self, _item_array: windows_core::Ref<'_, IShellItemArray>) -> Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetCanonicalName(&self) -> Result<GUID> {
        Ok(self.guid)
    }

    fn GetState(&self, _item_array: windows_core::Ref<'_, IShellItemArray>, _ok_to_be_slow: BOOL) -> Result<u32> {
        Ok(ECS_ENABLED.0 as _)
    }

    fn Invoke(
        &self,
        item_array: windows_core::Ref<'_, IShellItemArray>,
        _bind_ctx: windows_core::Ref<'_, IBindCtx>,
    ) -> Result<()> {
        // SAFETY: `item_array` is valid and `GetCount` has no preconditions.
        if item_array.is_none() || unsafe { item_array.unwrap().GetCount() }? < 1 {
            return Ok(());
        }

        // SAFETY: `item_array` is valid and `GetItemAt` gets first item, which we know exists from the previous check.
        let selection = unsafe { item_array.unwrap().GetItemAt(0) }?;

        let path = {
            // SAFETY: `GetDisplayName` has no preconditions. The string must be freed by `CoTaskMemFree`.
            let raw_path = unsafe { selection.GetDisplayName(SIGDN_FILESYSPATH) }?;
            if raw_path.is_null() {
                return Err(E_POINTER.into());
            }

            // SAFETY: We assume the returned string is valid.
            let path = OsString::from_wide(unsafe { raw_path.as_wide() });

            // SAFETY: `raw_path` is valid.
            unsafe {
                CoTaskMemFree(Some(raw_path.as_ptr().cast()));
            }

            path
        };

        match channels()
            .tx
            .blocking_send(ChannelCommand::Elevate(PathBuf::from(path)))
        {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::from_hresult(E_FAIL)),
        }
    }

    fn GetFlags(&self) -> Result<u32> {
        Ok(ECF_DEFAULT.0 as _)
    }

    fn EnumSubCommands(&self) -> Result<IEnumExplorerCommand> {
        Err(Error::from_hresult(E_NOTIMPL))
    }
}

impl IObjectWithSite_Impl for ElevationContextMenuCommand_Impl {
    fn SetSite(&self, site: windows_core::Ref<'_, windows_core::IUnknown>) -> Result<()> {
        if let Some(site) = site.cloned() {
            self.site.write().replace(site);
            Ok(())
        } else {
            Err(E_FAIL.into())
        }
    }

    fn GetSite(&self, iid: *const GUID, out_site: *mut *mut core::ffi::c_void) -> Result<()> {
        if out_site.is_null() {
            return Err(E_INVALIDARG.into());
        }

        if let Some(site) = self.site.read().as_ref() {
            // SAFETY: `query()` requires `out_site` to be non-null, and it is checked.
            unsafe { site.query(iid, out_site) }.ok()
        } else {
            Err(E_FAIL.into())
        }
    }
}

fn find_main_explorer(session: u32) -> Option<u32> {
    let snapshot = Snapshot::new(TH32CS_SNAPPROCESS, None).ok()?;

    snapshot.process_ids().find_map(|pid| {
        let proc = Process::get_by_pid(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).ok()?;

        if !(proc
            .exe_path()
            .ok()?
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("explorer.exe"))
            && proc.token(TOKEN_QUERY).ok()?.session_id().ok()? == session
            && proc
                .peb()
                .ok()?
                .user_process_parameters()
                .ok()?
                .command_line
                .args()
                .len()
                == 1)
        {
            return None;
        }

        Some(pid)
    })
}

fn resolve_msi(path: &Path) -> Option<LaunchPayload> {
    if !matches!(path.extension().and_then(|e| e.to_str()), Some(ext) if ext.eq_ignore_ascii_case("msi")) {
        return None;
    }

    let system32 = get_system32_path().ok()?;
    let msiexec_path = Path::new(&system32).join("msiexec.exe");

    let environment = environment_block(None, false).ok()?;

    let exe_path = expand_environment_path(&msiexec_path, &environment).ok()?;

    // By inspecting elevated .msi files launched from Explorer, we see that Explorer invokes %systemroot%\system32\msiexec,
    // with the command line "%systemroot%\system32\msiexec" /i "{path-to-msi}".
    // We achieve the same in the PEDM module by using the same command if the file extension is .msi.
    // The .msi extension is already being trapped by the shell extension, but previously we would call
    // CreateProcess on the .msi causing "file is not a valid Win32 executable".
    Some(LaunchPayload {
        executable_path: exe_path.as_os_str().to_str().map(str::to_owned),
        command_line: Some(format!("\"{}\" /i \"{}\"", exe_path.display(), path.display())),
        working_directory: None,
        creation_flags: 0,
        startup_info: None,
    })
}

fn resolve_lnk(path: &Path) -> Option<LaunchPayload> {
    let link = Link::new(path);

    let environment = environment_block(None, false).ok()?;

    let exe_path = expand_environment_path(&link.target_path().ok()?, &environment).ok()?;
    let command_line = link
        .target_args()
        .ok()
        .map(|x| format!("\"{}\" {}", exe_path.display(), expand_environment(&x, &environment)));

    Some(LaunchPayload {
        executable_path: exe_path.as_os_str().to_str().map(str::to_owned),
        command_line,
        working_directory: link
            .target_working_directory()
            .ok()
            .and_then(|x| expand_environment_path(&x, &environment).ok())
            .and_then(|x| x.as_os_str().to_str().map(str::to_owned)),
        creation_flags: 0,
        startup_info: None,
    })
}

fn start_listener() {
    thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build Tokio runtime")
            .block_on(async {
                while let Some(command) = channels().rx.lock().await.recv().await {
                    match command {
                        ChannelCommand::Exit => break,
                        ChannelCommand::Elevate(path) => {
                            let mut payload =
                                resolve_lnk(&path)
                                    .or_else(|| resolve_msi(&path))
                                    .unwrap_or_else(|| LaunchPayload {
                                        executable_path: path.as_os_str().to_str().map(str::to_owned),
                                        command_line: None,
                                        working_directory: None,
                                        creation_flags: 0,
                                        startup_info: None,
                                    });

                            payload.startup_info = Some(StartupInfoDto {
                                parent_pid: find_main_explorer(
                                    Token::current_process_token()
                                        .session_id()
                                        .expect("Session ID not found for current process"),
                                ),
                                ..Default::default()
                            });

                            let err = match client::client().default_api().launch_post(payload).await {
                                Ok(_) => None,
                                Err(x) => match client::conv_resp(x).await {
                                    Ok(x) => {
                                        if x.win32_error == ERROR_CANCELLED.0 {
                                            None
                                        } else {
                                            Some(Error::from_hresult(HRESULT(x.win32_error as _)))
                                        }
                                    }
                                    Err(_) => Some(E_UNEXPECTED.into()),
                                },
                            };

                            if let Some(err) = err {
                                let _ = desktop::launch(&desktop::DesktopMode::Error(err));
                            }
                        }
                    };
                }
            });
    });
}

#[derive(Debug)]
enum ChannelCommand {
    Exit,
    Elevate(PathBuf),
}

static mut DLL_MODULE: HINSTANCE = HINSTANCE(std::ptr::null_mut());

#[unsafe(no_mangle)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            // SAFETY:
            // - `dll_module` is guaranteed by the Windows loader to be the base address of the DLL
            // - `DLL_MODULE` is initialized exactly once: `DLL_PROCESS_ATTACH` is executed in a serialized
            // manner by the Windows loader, so no race condition exists
            // - Access to `DLL_MODULE` is inherently safe because Windows ensures the DLL is full initalized
            // before other threads can execute code in the DLL
            // - `DLL_MODULE` is never mutated after the initial assignment
            // - The module handle remains valid for the entire lifetime of the DLL in the process
            unsafe { DLL_MODULE = dll_module };

            start_listener();

            true
        }
        DLL_PROCESS_DETACH => {
            let _ = channels().tx.blocking_send(ChannelCommand::Exit);

            // Give it enough time to exit.
            thread::sleep(Duration::from_secs(3));
            true
        }
        _ => true,
    }
}

#[implement(IClassFactory)]
struct ElevationContextMenuCommandFactory;

impl IClassFactory_Impl for ElevationContextMenuCommandFactory_Impl {
    fn CreateInstance(
        &self,
        outer: windows_core::Ref<'_, windows_core::IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> Result<()> {
        if object.is_null() {
            return Err(E_INVALIDARG.into());
        }

        // SAFETY: We checked object is non null. We assume it points to a valid address.
        unsafe {
            *object = ptr::null_mut();
        }

        if outer.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        let unk: IUnknown = ElevationContextMenuCommand::new().into();

        // SAFETY: `query()` requires `object` to be non-null, which we check above.
        unsafe { unk.query(iid, object).ok() }
    }

    fn LockServer(&self, _lock: BOOL) -> Result<()> {
        Err(E_NOTIMPL.into())
    }
}

#[unsafe(no_mangle)]
extern "system" fn DllGetClassObject(class_id: *const GUID, iid: *const GUID, out: *mut *mut c_void) -> HRESULT {
    // SAFETY: We assume the argument is the correct type according to the doc.
    let class_id = unsafe { class_id.as_ref() };

    // SAFETY: We assume the argument is the correct type according to the doc.
    let iid = unsafe { iid.as_ref() };

    if out.is_null() {
        return E_INVALIDARG;
    }

    match (iid, class_id) {
        (Some(iid), Some(class_id)) => {
            if *iid != IClassFactory::IID || *class_id != IElevationContextMenuCommand::IID {
                return CLASS_E_CLASSNOTAVAILABLE;
            }

            let factory: IUnknown = ElevationContextMenuCommandFactory.into();

            // SAFETY: `iid` is checked before and is valid. `out` is checked for null in accordance to `.query()`'s safety doc.
            unsafe { factory.query(iid, out) }
        }
        (_, _) => E_INVALIDARG,
    }
}
