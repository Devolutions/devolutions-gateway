use dlopen::symbor::{SymBorApi, Symbol, Library};
use dlopen_derive::SymBorApi;
use std::{sync::Arc, ffi::CStr, os::raw::c_char, convert::TryFrom};
use slog_scope::{debug, error};

#[derive(Debug, PartialEq)]
pub enum PluginCapabilities {
    PacketsParsing = 1,
    Recording = 2,
}

impl TryFrom<u32> for PluginCapabilities {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PluginCapabilities::PacketsParsing),
            2 => Ok(PluginCapabilities::Recording),
            _ => Err(String::from(format!("Unknown capability detected {}", value))),
        }
    }
}

#[allow(non_snake_case)]
#[derive(SymBorApi)]
pub struct PluginInformationApi<'a> {
    NowPluginGeneral_GetName: Symbol<'a,unsafe extern "C" fn() -> *const c_char>,
    NowPluginGeneral_GetCapabilities: Symbol<'a,unsafe extern "C" fn(size: *mut usize) -> *const u8>,
}

pub struct PluginInformation {
    info: PluginInformationApi<'static>,
    lib: Arc<Library>
}

impl PluginInformation {
    pub fn new(lib: Arc<Library>) -> Self {
        Self {
            lib: lib.clone(),
            info: unsafe {
                let lib = PluginInformationApi::load(&lib).unwrap();
                std::mem::transmute::<PluginInformationApi<'_>, PluginInformationApi<'static>>(lib)
            }
        }
    }

    pub fn get_name(&self) -> String {
        unsafe {
            let cstr = CStr::from_ptr((self.info.NowPluginGeneral_GetName)()) ;
            match cstr.to_str() {
                Ok(result) => result.to_string(),
                Err(e) => {
                    error!("Failed to get the plugin name: {}", e.to_string());
                    String::new()
                }
            }
        }
    }

    pub fn get_capabilities(&self) -> Vec<PluginCapabilities> {
        unsafe {
            let mut size: usize = 0;
            let ptr: *const u8 = (self.info.NowPluginGeneral_GetCapabilities)((&mut size) as *mut usize);
            let mut capabilities: Vec<PluginCapabilities> = Vec::new();
            let capabilities_array =  std::slice::from_raw_parts::<u8>(ptr, size);
            for raw_capability in capabilities_array {
                match PluginCapabilities::try_from(*raw_capability as u32) {
                    Ok(capability) => capabilities.push(capability),
                    Err(e) => debug!("Unknown capability detected {}", e.to_string())
                };
            }

            capabilities
        }
    }
}