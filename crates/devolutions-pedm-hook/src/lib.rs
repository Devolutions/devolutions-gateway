mod appinfo;
mod hook;

use std::{
    collections::HashMap,
    mem,
    sync::{Mutex, OnceLock},
    thread,
};

use anyhow::{bail, Result};

use appinfo::dump_interfaces;
use hook::rai_launch_admin_process;
use win_api_wrappers::{
    raw::{
        core::GUID,
        Win32::{
            Foundation::*,
            System::{Rpc::SERVER_ROUTINE, SystemServices::*},
        },
    },
    win::is_module_loaded,
};

fn original_handlers() -> &'static Mutex<HashMap<GUID, Box<[SERVER_ROUTINE]>>> {
    static ORIGINAL_HANDLERS: OnceLock<Mutex<HashMap<GUID, Box<[SERVER_ROUTINE]>>>> = OnceLock::new();
    ORIGINAL_HANDLERS.get_or_init(|| Mutex::new(HashMap::new()))
}

// fn hooks() -> &'static HashMap<GUID, Box<[ServerRoutinePointer]>> {
//     static HOOKS: OnceLock<HashMap<GUID, Box<[ServerRoutinePointer]>>> = OnceLock::new();
//     HOOKS.get_or_init(|| {
//         let hooks: HashMap<GUID, Box<[ServerRoutinePointer]>> = HashMap::new();

//         hooks
//     })
// }

fn hook() -> Result<()> {
    if !is_module_loaded("appinfo.dll") {
        bail!("appinfo.dll not loaded");
    }

    let mut interfaces = unsafe { dump_interfaces() }?;

    let mut origs = original_handlers().lock().unwrap();
    for interface in interfaces.iter_mut() {
        let handlers = interface.handlers()?;

        origs.insert(interface.id(), handlers);

        if interface.id() == GUID::from("201ef99a-7fa0-444c-9399-19ba84f12a1a") {
            let mut hooks = origs.get(&interface.id()).unwrap().to_owned();
            hooks[0] = unsafe { mem::transmute(rai_launch_admin_process as *const ()) };

            interface.set_handlers(&hooks)?;
        }
    }

    Ok(())
}

fn unhook() -> Result<()> {
    if !is_module_loaded("appinfo.dll") {
        bail!("appinfo.dll not loaded");
    }

    let mut interfaces = unsafe { dump_interfaces() }?;

    let mut origs = original_handlers().lock().unwrap();
    for interface in interfaces.iter_mut() {
        let handlers = interface.handlers()?;

        origs.insert(interface.id(), handlers);

        if let Some(orig_handlers) = origs.get(&interface.id()) {
            interface.set_handlers(&orig_handlers)?;
        }
    }

    Ok(())
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    let status = match call_reason {
        DLL_PROCESS_ATTACH => {
            thread::spawn(|| match hook() {
                Ok(()) => {}
                Err(err) => panic!("Got error {}", err),
            });
            true
        }
        DLL_PROCESS_DETACH => unhook().is_ok(),
        _ => true,
    };

    status
}
