use anyhow::Context;
use dlopen::symbor::{Library, SymBorApi, Symbol};
use dlopen_derive::SymBorApi;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::mem::transmute;
use std::os::raw::c_char;
use std::slice::from_raw_parts;
use std::sync::Arc;
use tap::TapFallible;

#[derive(Debug, PartialEq)]
pub enum PluginCapabilities {
    PacketsParsing = 1,
    Recording = 2,
}

impl TryFrom<u32> for PluginCapabilities {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PluginCapabilities::PacketsParsing),
            2 => Ok(PluginCapabilities::Recording),
            _ => anyhow::bail!("Unknown capability detected {}", value),
        }
    }
}

#[allow(non_snake_case)]
#[derive(SymBorApi)]
pub struct PluginInformationApi<'a> {
    NowPlugin_GetName: Symbol<'a, unsafe extern "C" fn() -> *const c_char>,
    NowPlugin_GetCapabilities: Symbol<'a, unsafe extern "C" fn(size: *mut usize) -> *const u8>,
}

pub struct PluginInformation {
    info: PluginInformationApi<'static>,
    // this field is needed to prove the compiler that info will not outlive the lib
    _lib: Arc<Library>,
}

impl PluginInformation {
    pub fn new(lib: Arc<Library>) -> anyhow::Result<Self> {
        unsafe {
            let lib_load = PluginInformationApi::load(&lib).context("Failed to load plugin information API")?;
            Ok(Self {
                _lib: lib.clone(),
                info: transmute::<PluginInformationApi<'_>, PluginInformationApi<'static>>(lib_load),
            })
        }
    }

    pub fn get_name(&self) -> String {
        let cstr = unsafe { CStr::from_ptr((self.info.NowPlugin_GetName)()) };
        cstr.to_str()
            .tap_err(|e| error!("bad plugin name: {}", e))
            .unwrap_or("")
            .to_owned()
    }

    pub fn get_capabilities(&self) -> Vec<PluginCapabilities> {
        let mut size = 0;

        let capabilities_array = unsafe {
            let ptr: *const u8 = (self.info.NowPlugin_GetCapabilities)((&mut size) as *mut usize);
            from_raw_parts::<u8>(ptr, size)
        };

        let mut capabilities = Vec::with_capacity(size);
        for raw_capability in capabilities_array {
            match PluginCapabilities::try_from(*raw_capability as u32) {
                Ok(capability) => capabilities.push(capability),
                Err(e) => debug!("Unknown capability detected {}", e),
            };
        }

        capabilities
    }
}
