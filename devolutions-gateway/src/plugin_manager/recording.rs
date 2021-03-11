use crate::plugin_manager::packets_parsing::ImageUpdate;
use dlopen::symbor::{Library, SymBorApi, Symbol};
use dlopen_derive::SymBorApi;
use std::{ffi::CString, os::raw::c_char, sync::Arc};

pub type RecordingContext = usize;

#[allow(non_snake_case)]
#[derive(SymBorApi)]
pub struct RecordingApi<'a> {
    NowRecording_CreateRecordingContext: Symbol<'a, unsafe extern "C" fn() -> RecordingContext>,
    NowRecording_SetSize: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext, width: u32, height: u32)>,
    NowRecording_SetFilename: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext, filename: *mut c_char)>,
    NowRecording_SetDirectory: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext, directory: *mut c_char)>,
    NowRecording_UpdateRecording: Symbol<
        'a,
        unsafe extern "C" fn(
            ctx: RecordingContext,
            buffer: *mut u8,
            updateX: u32,
            updateY: u32,
            updateWidth: u32,
            updateHeight: u32,
            surfaceStep: *const u32,
        ),
    >,
    NowRecording_FreeRecordingContext: Symbol<'a, unsafe extern "C" fn(ctx: RecordingContext)>,
}

pub struct Recorder {
    api: RecordingApi<'static>,
    //this filed is needed to prove the compiler that info will not outlive the lib
    _lib: Arc<Library>,
    ctx: RecordingContext,
}

impl Recorder {
    pub fn new(lib: Arc<Library>) -> Self {
        let api = unsafe {
            let lib = RecordingApi::load(&lib).unwrap();
            std::mem::transmute::<RecordingApi<'_>, RecordingApi<'static>>(lib)
        };
        let ctx = unsafe { (api.NowRecording_CreateRecordingContext)() };

        Self {
            _lib: lib.clone(),
            api,
            ctx,
        }
    }

    pub fn update_recording(&self, mut image_data: ImageUpdate) {
        unsafe {
            (self.api.NowRecording_UpdateRecording)(
                self.ctx,
                image_data.image_buff.as_mut_ptr(),
                image_data.update_x,
                image_data.update_y,
                image_data.update_width,
                image_data.update_height,
                (&mut image_data.surface_step) as *mut u32,
            );
        }
    }

    pub fn set_size(&self, width: u32, height: u32) {
        unsafe {
            (self.api.NowRecording_SetSize)(self.ctx, width, height);
        }
    }

    pub fn set_filename(&self, filename: &str) {
        unsafe {
            if let Ok(c_str) = CString::new(filename) {
                (self.api.NowRecording_SetFilename)(self.ctx, c_str.into_raw());
            }
        }
    }

    pub fn set_directory(&self, directory: &str) {
        unsafe {
            if let Ok(c_str) = CString::new(directory) {
                (self.api.NowRecording_SetDirectory)(self.ctx, c_str.into_raw());
            }
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        unsafe {
            (self.api.NowRecording_FreeRecordingContext)(self.ctx);
        }
    }
}
