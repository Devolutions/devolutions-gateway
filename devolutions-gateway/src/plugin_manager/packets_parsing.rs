use crate::utils::into_other_io_error;
use dlopen::symbor::{Library, SymBorApi, Symbol};
use dlopen_derive::SymBorApi;
use std::io::Error;
use std::mem::transmute;
use std::slice::from_raw_parts;
use std::sync::Arc;

pub type NowPacketParser = usize;

pub struct FrameSize {
    pub width: u32,
    pub height: u32,
}

pub struct ImageUpdate {
    pub update_x: u32,
    pub update_y: u32,
    pub update_width: u32,
    pub update_height: u32,
    pub surface_step: u32,
    pub image_buff: Vec<u8>,
}

#[allow(non_snake_case)]
#[derive(SymBorApi)]
pub struct PacketsParsingApi<'a> {
    NowPacketParser_New: Symbol<'a, unsafe extern "C" fn() -> NowPacketParser>,
    NowPacketParser_GetSize: Symbol<'a, unsafe extern "C" fn(ctx: NowPacketParser, width: *mut u32, height: *mut u32)>,
    NowPacketParser_ParseMessage: Symbol<
        'a,
        unsafe extern "C" fn(
            ctx: NowPacketParser,
            buffer: *const u8,
            len: usize,
            messageType: *mut u32,
            isFromServer: bool,
        ) -> usize,
    >,
    NowPacketParser_GetImage: Symbol<
        'a,
        unsafe extern "C" fn(
            ctx: NowPacketParser,
            updateX: *mut u32,
            updateY: *mut u32,
            updateWidth: *mut u32,
            updateHeight: *mut u32,
            surfaceStep: *mut u32,
            surfaceSize: *mut u32,
        ) -> *mut u8,
    >,
    NowPacketParser_IsMessageConstructed:
        Symbol<'a, unsafe extern "C" fn(ctx: NowPacketParser, isFromServer: bool) -> bool>,
    NowPacketParser_Free: Symbol<'a, unsafe extern "C" fn(ctx: NowPacketParser)>,
}

pub struct PacketsParser {
    api: PacketsParsingApi<'static>,
    // this field is needed to prove the compiler that info will not outlive the lib
    _lib: Arc<Library>,
    ctx: NowPacketParser,
}

impl PacketsParser {
    pub const NOW_CAPABILITIES_MSG_ID: u32 = 5;
    pub const NOW_SURFACE_MSG_ID: u32 = 65;
    pub const NOW_UPDATE_MSG_ID: u32 = 66;

    pub fn new(lib: Arc<Library>) -> Result<Self, Error> {
        unsafe {
            if let Ok(lib_load) = PacketsParsingApi::load(&lib) {
                let api = transmute::<PacketsParsingApi<'_>, PacketsParsingApi<'static>>(lib_load);
                let ctx = (api.NowPacketParser_New)();

                return Ok(Self { _lib: lib, api, ctx });
            }
        }

        Err(into_other_io_error(String::from(
            "Failed to load api for recording plugin!",
        )))
    }

    pub fn get_size(&self) -> FrameSize {
        let mut width = 0;
        let mut height = 0;
        unsafe {
            (self.api.NowPacketParser_GetSize)(self.ctx, (&mut width) as *mut u32, (&mut height) as *mut u32);
        }

        FrameSize { width, height }
    }

    pub fn parse_message(&self, buffer: &[u8], len: usize, is_from_server: bool) -> (usize, u32) {
        let mut message_id = 0;
        let res = unsafe {
            (self.api.NowPacketParser_ParseMessage)(
                self.ctx,
                buffer.as_ptr(),
                len,
                (&mut message_id) as *mut u32,
                is_from_server,
            )
        };
        (res, message_id)
    }

    pub fn is_message_constructed(&self, is_from_server: bool) -> bool {
        unsafe { (self.api.NowPacketParser_IsMessageConstructed)(self.ctx, is_from_server) }
    }

    pub fn get_image_data(&self) -> ImageUpdate {
        let mut update_x = 0;
        let mut update_y = 0;
        let mut update_width = 0;
        let mut update_height = 0;
        let mut surface_step = 0;
        let mut surface_size: u32 = 0;
        let mut image_buff = Vec::new();

        let raw_image_buf = unsafe {
            let ptr: *const u8 = (self.api.NowPacketParser_GetImage)(
                self.ctx,
                (&mut update_x) as *mut u32,
                (&mut update_y) as *mut u32,
                (&mut update_width) as *mut u32,
                (&mut update_height) as *mut u32,
                (&mut surface_step) as *mut u32,
                (&mut surface_size) as *mut u32,
            );

            from_raw_parts::<u8>(ptr, surface_size as usize)
        };

        image_buff.extend_from_slice(raw_image_buf);
        ImageUpdate {
            update_x,
            update_y,
            update_height,
            update_width,
            surface_step,
            image_buff,
        }
    }
}

impl Drop for PacketsParser {
    fn drop(&mut self) {
        unsafe {
            (self.api.NowPacketParser_Free)(self.ctx);
        }
    }
}
