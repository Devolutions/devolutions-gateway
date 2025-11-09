#[cfg(target_os = "windows")]
#[path = ""]
mod lib_win {
    #![allow(non_snake_case, non_camel_case_types)] // WinAPI naming.

    pub mod appinfo;
    pub mod hook;

    use std::collections::HashMap;
    use std::sync::OnceLock;
    use std::{mem, thread};

    use anyhow::{Result, bail};

    use parking_lot::Mutex;

    use appinfo::dump_interfaces;
    use hook::rai_launch_admin_process;
    use win_api_wrappers::process::Module;
    use win_api_wrappers::raw::Win32::Foundation::*;
    use win_api_wrappers::raw::Win32::System::Rpc::SERVER_ROUTINE;
    use win_api_wrappers::raw::Win32::System::SystemServices::*;
    use win_api_wrappers::raw::core::GUID;

    fn original_handlers() -> &'static Mutex<HashMap<GUID, Box<[SERVER_ROUTINE]>>> {
        static ORIGINAL_HANDLERS: OnceLock<Mutex<HashMap<GUID, Box<[SERVER_ROUTINE]>>>> = OnceLock::new();
        ORIGINAL_HANDLERS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// GUID obtained from RpcView on the AppInfo service.
    /// Can also be obtained from [here](https://github.com/tyranid/WindowsRpcClients/blob/master/Win10_20H1/appinfo.dll/201ef99a-7fa0-444c-9399-19ba84f12a1a_1.0.cs).
    pub const APPINFO_GUID: GUID = GUID::from_u128(0x201ef99a_7fa0_444c_9399_19ba84f12a1a);

    fn hook() -> Result<()> {
        if Module::from_name("appinfo.dll").is_err() {
            bail!("appinfo.dll not loaded");
        }

        let mut interfaces = unsafe { dump_interfaces() }?;

        let mut origs = original_handlers().lock();
        for interface in interfaces.iter_mut() {
            let handlers = interface.handlers()?;

            origs.insert(interface.id(), handlers);

            if interface.id() == APPINFO_GUID {
                let mut hooks = origs
                    .get(&interface.id())
                    .expect("interface hooks not found")
                    .to_owned();
                hooks[0] = unsafe {
                    mem::transmute::<*const (), Option<unsafe extern "system" fn() -> i32>>(
                        rai_launch_admin_process as *const (),
                    )
                };

                interface.set_handlers(hooks)?;
            }
        }

        Ok(())
    }

    fn unhook() -> Result<()> {
        if Module::from_name("appinfo.dll").is_err() {
            bail!("appinfo.dll not loaded");
        }

        let mut interfaces = unsafe { dump_interfaces() }?;

        let mut origs = original_handlers().lock();
        for interface in interfaces.iter_mut() {
            let handlers = interface.handlers()?;

            origs.insert(interface.id(), handlers);

            if let Some(orig_handlers) = origs.get(&interface.id()) {
                interface.set_handlers(&orig_handlers)?;
            }
        }

        Ok(())
    }

    #[unsafe(no_mangle)]
    extern "system" fn DllMain(_dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
        match call_reason {
            DLL_PROCESS_ATTACH => {
                thread::spawn(|| match hook() {
                    Ok(()) => {}
                    Err(err) => panic!("Got error {}", err),
                });
                true
            }
            DLL_PROCESS_DETACH => unhook().is_ok(),
            _ => true,
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) use lib_win::*;
