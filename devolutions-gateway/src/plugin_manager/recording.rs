use std::ffi::CString;
use std::mem::transmute;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::string::FromUtf8Error;
use std::sync::Arc;

use anyhow::Context;
use dlopen::symbor::{Library, SymBorApi, Symbol};
use dlopen_derive::SymBorApi;

use crate::plugin_manager::packets_parsing::ImageUpdate;

pub(crate) type RecordingContext = usize;
const MAX_PATH_LEN: usize = 512;

#[allow(non_snake_case)]
#[derive(SymBorApi)]
pub(crate) struct RecordingApi<'a> {
    NowRecording_New: Symbol<'a, unsafe extern "C" fn() -> RecordingContext>,
    NowRecording_SetSize: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext, width: u32, height: u32)>,
    NowRecording_SetFilename: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext, filename: *mut c_char)>,
    NowRecording_SetDirectory: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext, directory: *mut c_char)>,
    NowRecording_Update: Symbol<
        'a,
        unsafe extern "C" fn(
            ctx: RecordingContext,
            buffer: *mut u8,
            updateX: u32,
            updateY: u32,
            updateWidth: u32,
            updateHeight: u32,
            surfaceStep: u32,
        ),
    >,
    NowRecording_Timeout: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext)>,
    NowRecording_GetTimeout: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext) -> u32>,
    NowRecording_GetPath:
        Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext, path: *mut c_char, size: usize) -> usize>,
    NowRecording_Free: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext)>,
}

pub struct Recorder {
    api: RecordingApi<'static>,
    // this field is needed to prove the compiler that info will not outlive the lib
    _lib: Arc<Library>,
    ctx: RecordingContext,
}

impl Recorder {
    pub fn new(lib: Arc<Library>) -> anyhow::Result<Self> {
        // SAFETY: We assume the API definition we derived is well-formed and valid.
        let api = unsafe { RecordingApi::load(&lib).context("failed to load recording API")? };

        // SAFETY: We hold a shared-pointer on the library, so it’s fine to uppercast the lifetime.
        let api = unsafe { transmute::<RecordingApi<'_>, RecordingApi<'static>>(api) };

        // SAFETY: FFI call with no outstanding precondition.
        let ctx = unsafe { (api.NowRecording_New)() };

        Ok(Self { _lib: lib, api, ctx })
    }

    pub fn update_recording(&self, mut image_data: ImageUpdate) {
        // SAFETY: FFI call with no outstanding precondition.
        unsafe {
            (self.api.NowRecording_Update)(
                self.ctx,
                image_data.image_buff.as_mut_ptr(),
                image_data.update_x,
                image_data.update_y,
                image_data.update_width,
                image_data.update_height,
                image_data.surface_step,
            );
        }
    }

    pub fn set_size(&self, width: u32, height: u32) {
        // SAFETY: FFI call with no outstanding precondition.
        unsafe {
            (self.api.NowRecording_SetSize)(self.ctx, width, height);
        }
    }

    pub fn set_filename(&self, filename: &str) {
        // SAFETY: FFI call with no outstanding precondition.
        unsafe {
            if let Ok(c_str) = CString::new(filename) {
                (self.api.NowRecording_SetFilename)(self.ctx, c_str.into_raw());
            }
        }
    }

    pub fn set_directory(&self, directory: &str) {
        // SAFETY: FFI call with no outstanding precondition.
        unsafe {
            if let Ok(c_str) = CString::new(directory) {
                (self.api.NowRecording_SetDirectory)(self.ctx, c_str.into_raw());
            }
        }
    }

    pub fn timeout(&self) {
        // SAFETY: FFI call with no outstanding precondition.
        unsafe {
            (self.api.NowRecording_Timeout)(self.ctx);
        }
    }

    pub fn get_timeout(&self) -> u32 {
        // SAFETY: FFI call with no outstanding precondition.
        unsafe { (self.api.NowRecording_GetTimeout)(self.ctx) }
    }

    pub fn get_filepath(&self) -> Result<PathBuf, FromUtf8Error> {
        let mut path_array = vec![0; MAX_PATH_LEN];

        // SAFETY: FFI call with no outstanding precondition.
        let path_size = unsafe { (self.api.NowRecording_GetPath)(self.ctx, path_array.as_mut_ptr(), MAX_PATH_LEN) };

        if path_size > MAX_PATH_LEN {
            path_array.resize(path_size, 0);

            // SAFETY: FFI call with no outstanding precondition.
            unsafe {
                (self.api.NowRecording_GetPath)(self.ctx, path_array.as_mut_ptr(), path_array.len());
            }
        }

        // -1 for the last /0 in the cstr
        path_array.truncate(path_size - 1);

        #[allow(clippy::cast_sign_loss)] // Losing the sign of the value on purpose.
        let str_path = String::from_utf8(path_array.iter().map(|element| *element as u8).collect());

        match str_path {
            Ok(path) => Ok(PathBuf::from(path)),
            Err(e) => Err(e),
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        // SAFETY: FFI call with no outstanding precondition.
        unsafe {
            (self.api.NowRecording_Free)(self.ctx);
        }
    }
}
