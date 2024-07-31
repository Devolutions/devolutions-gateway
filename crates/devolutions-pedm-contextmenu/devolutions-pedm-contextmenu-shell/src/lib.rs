use std::{
    ffi::{c_void, OsString},
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr, thread,
    time::Duration,
};

use devolutions_pedm_shared::{
    client::{
        self,
        models::{LaunchPayload, StartupInfoDto},
    },
    desktop,
};
use parking_lot::RwLock;
use tokio::sync::mpsc::{self, Receiver, Sender};
use win_api_wrappers::{
    raw::{
        core::{implement, interface, w, Error, IUnknown, IUnknown_Vtbl, Interface, Result, GUID, HRESULT, PWSTR},
        Win32::{
            Foundation::{
                BOOL, CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, ERROR_CANCELLED, E_FAIL, E_NOTIMPL,
                E_UNEXPECTED, HINSTANCE,
            },
            Security::TOKEN_QUERY,
            System::{
                Com::{IBindCtx, IClassFactory, IClassFactory_Impl},
                Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                Ole::{IObjectWithSite, IObjectWithSite_Impl},
                SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
                Threading::PROCESS_QUERY_INFORMATION,
            },
            UI::Shell::{
                IEnumExplorerCommand, IExplorerCommand, IExplorerCommand_Impl, IShellItemArray, SHStrDupW, ECF_DEFAULT,
                ECS_ENABLED, SIGDN_FILESYSPATH,
            },
        },
    },
    win::{environment_block, expand_environment, expand_environment_path, Link, Process, Snapshot, Token},
};

static mut MODULE_INSTANCE: HINSTANCE = HINSTANCE(ptr::null_mut());
static mut TX_CHANNEL: Option<Sender<ChannelCommand>> = None;

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
    fn GetTitle(&self, _item_array: Option<&IShellItemArray>) -> Result<PWSTR> {
        unsafe { SHStrDupW(w!("Run as administrator with Devolutions PEDM")) }
    }

    fn GetIcon(&self, _item_array: Option<&IShellItemArray>) -> Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetToolTip(&self, _item_array: Option<&IShellItemArray>) -> Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetCanonicalName(&self) -> Result<GUID> {
        Ok(self.guid)
    }

    fn GetState(&self, _item_array: Option<&IShellItemArray>, _ok_to_be_slow: BOOL) -> Result<u32> {
        Ok(ECS_ENABLED.0 as _)
    }

    fn Invoke(&self, item_array: Option<&IShellItemArray>, _bind_ctx: Option<&IBindCtx>) -> Result<()> {
        if item_array.is_none() || unsafe { item_array.unwrap().GetCount() }? < 1 {
            return Ok(());
        }

        let selection = unsafe { item_array.unwrap().GetItemAt(0) }?;
        let path = unsafe { selection.GetDisplayName(SIGDN_FILESYSPATH) }?;
        let path = OsString::from_wide(unsafe { path.as_wide() });

        match unsafe {
            TX_CHANNEL
                .as_ref()
                .unwrap()
                .blocking_send(ChannelCommand::Elevate(PathBuf::from(path)))
        } {
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
    fn SetSite(&self, site: Option<&IUnknown>) -> Result<()> {
        if let Some(site) = site {
            self.site.write().replace(site.clone());
            Ok(())
        } else {
            Err(E_FAIL.into())
        }
    }

    fn GetSite(&self, iid: *const GUID, out_site: *mut *mut core::ffi::c_void) -> Result<()> {
        if let Some(site) = self.site.read().as_ref() {
            unsafe { site.query(iid, out_site) }.ok()
        } else {
            Err(E_FAIL.into())
        }
    }
}

fn find_main_explorer(session: u32) -> Option<u32> {
    let snapshot = Snapshot::new(TH32CS_SNAPPROCESS, None).ok()?;

    snapshot.process_ids().find_map(|pid| {
        let proc = Process::try_get_by_pid(pid, PROCESS_QUERY_INFORMATION).ok()?;

        if !proc
            .exe_path()
            .ok()?
            .file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("explorer.exe"))
            || proc.token(TOKEN_QUERY).ok()?.session_id().ok()? != session
        {
            return None;
        }

        Some(pid)
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

fn start_listener(mut rx: Receiver<ChannelCommand>) {
    thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                while let Some(command) = rx.recv().await {
                    match command {
                        ChannelCommand::Exit => break,
                        ChannelCommand::Elevate(path) => {
                            let mut payload = resolve_lnk(&path).unwrap_or_else(|| LaunchPayload {
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
                                )
                                .unwrap_or(0),
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

#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            let (tx, rx) = mpsc::channel(10);

            unsafe {
                MODULE_INSTANCE = dll_module;
                TX_CHANNEL = Some(tx);
            }

            start_listener(rx);

            true
        }
        DLL_PROCESS_DETACH => {
            let _ = unsafe { TX_CHANNEL.as_ref().unwrap().blocking_send(ChannelCommand::Exit) };
            thread::sleep(Duration::from_secs(3));
            true
        }
        _ => true,
    }
}

#[implement(IClassFactory)]
struct ElevationContextMenuCommandFactory;

impl IClassFactory_Impl for ElevationContextMenuCommandFactory_Impl {
    fn CreateInstance(&self, outer: Option<&IUnknown>, iid: *const GUID, object: *mut *mut c_void) -> Result<()> {
        unsafe {
            *object = ptr::null_mut();
        }

        if outer.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        let unk: IUnknown = ElevationContextMenuCommand::new().into();

        unsafe { unk.query(iid, object).ok() }
    }

    fn LockServer(&self, _lock: BOOL) -> Result<()> {
        Err(E_NOTIMPL.into())
    }
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllGetClassObject(class_id: *const GUID, iid: *const GUID, out: *mut *mut c_void) -> HRESULT {
    let class_id = &*class_id;
    let iid = &*iid;

    if *iid != IClassFactory::IID || *class_id != IElevationContextMenuCommand::IID {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    let factory: IUnknown = ElevationContextMenuCommandFactory.into();

    factory.query(iid, out)
}

// #[no_mangle]
// #[allow(non_snake_case)]
// extern "system" fn DllCanUnloadNow()  -> HRESULT
// {
//     return Module<InProc>::GetModule().GetObjectCount() == 0 ? S_OK : S_FALSE;
// }

// #[no_mangle]
// #[allow(non_snake_case)]
// extern "system" fn DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _COM_Outptr_ void** instance)  -> HRESULT
// {
//     return Module<InProc>::GetModule().GetClassObject(rclsid, riid, instance);
// }
