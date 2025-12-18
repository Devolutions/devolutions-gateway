use std::convert::TryFrom;
use std::ffi::CStr;
use std::mem::transmute;
use std::os::raw::c_char;
use std::slice::from_raw_parts;
use std::sync::Arc;

use anyhow::Context;
use dlopen::symbor::{Library, SymBorApi, Symbol};
use dlopen_derive::SymBorApi;
use tap::TapFallible;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PluginCapabilities {
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
pub(crate) struct PluginInformationApi<'a> {
    NowPlugin_GetName: Symbol<'a, unsafe extern "C" fn() -> *const c_char>,
    NowPlugin_GetCapabilities: Symbol<'a, unsafe extern "C" fn(size: *mut usize) -> *const u8>,
}

pub(crate) struct PluginInformation {
    info: PluginInformationApi<'static>,
    // This field is needed to make sure that info will not outlive the lib.
    _lib: Arc<Library>,
}

impl PluginInformation {
    pub(crate) fn new(lib: Arc<Library>) -> anyhow::Result<Self> {
        // SAFETY: We assume the API definition we derived is well-formed and valid.
        let api = unsafe { PluginInformationApi::load(&lib).context("failed to load plugin information API")? };

        // SAFETY: We hold a shared-pointer on the library, so it’s fine to uppercast the lifetime.
        let api = unsafe { transmute::<PluginInformationApi<'_>, PluginInformationApi<'static>>(api) };

        Ok(Self { _lib: lib, info: api })
    }

    pub(crate) fn get_name(&self) -> String {
        // SAFETY: FFI call with no outstanding precondition.
        let cstr = unsafe { CStr::from_ptr((self.info.NowPlugin_GetName)()) };
        cstr.to_str()
            .tap_err(|e| error!("bad plugin name: {}", e))
            .unwrap_or("")
            .to_owned()
    }

    pub(crate) fn get_capabilities(&self) -> Vec<PluginCapabilities> {
        let mut size = 0;

        // SAFETY: FFI call with no outstanding precondition.
        let capabilities_array = unsafe {
            let ptr: *const u8 = (self.info.NowPlugin_GetCapabilities)((&mut size) as *mut usize);
            from_raw_parts::<u8>(ptr, size)
        };

        let mut capabilities = Vec::with_capacity(size);
        for raw_capability in capabilities_array {
            match PluginCapabilities::try_from(u32::from(*raw_capability)) {
                Ok(capability) => capabilities.push(capability),
                Err(e) => debug!("Unknown capability detected {}", e),
            };
        }

        capabilities
    }
}
