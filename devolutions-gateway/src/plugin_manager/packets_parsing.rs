use dlopen::symbor::{Library, SymBorApi, Symbol};
use dlopen_derive::SymBorApi;
use std::sync::Arc;

pub type NowPacketsParsing = usize;

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
    NowWaykPacketsParsing_CreateParsingContext: Symbol<'a, unsafe extern "C" fn() -> NowPacketsParsing>,
    NowWaykPacketsParsing_GetSize:
        Symbol<'a, unsafe extern "C" fn(ctx: NowPacketsParsing, width: *mut u32, height: *mut u32)>,
    NowWaykPacketsParsing_ParseMessage: Symbol<
        'a,
        unsafe extern "C" fn(
            ctx: NowPacketsParsing,
            buffer: *const u8,
            len: usize,
            messageType: *mut u32,
            isFromServer: bool,
        ) -> usize,
    >,
    NowWaykPacketsParsing_GetImageBuff: Symbol<
        'a,
        unsafe extern "C" fn(
            ctx: NowPacketsParsing,
            updateX: *mut u32,
            updateY: *mut u32,
            updateWidth: *mut u32,
            updateHeight: *mut u32,
            surfaceStep: *mut u32,
            surfaceSize: *mut u32,
        ) -> *mut u8,
    >,
    NowWaykPacketsParsing_IsMessageConstructed: Symbol<'a, unsafe extern "C" fn(ctx: NowPacketsParsing) -> bool>,
    NowWaykPacketsParsing_FreeParsingContext: Symbol<'a, unsafe extern "C" fn(ctx: NowPacketsParsing)>,
}

pub struct PacketsParser {
    api: PacketsParsingApi<'static>,
    //this filed is needed to prove the compiler that info will not outlive the lib
    _lib: Arc<Library>,
    ctx: NowPacketsParsing,
}

impl PacketsParser {
    pub const NOW_CAPABILITIES_MSG_ID: u32 = 5;
    pub const NOW_SURFACE_MSG_ID: u32 = 65;
    pub const NOW_UPDATE_MSG_ID: u32 = 66;

    pub fn new(lib: Arc<Library>) -> Self {
        let api = unsafe {
            let lib = PacketsParsingApi::load(&lib).unwrap();
            std::mem::transmute::<PacketsParsingApi<'_>, PacketsParsingApi<'static>>(lib)
        };
        let ctx = unsafe { (api.NowWaykPacketsParsing_CreateParsingContext)() };

        Self {
            _lib: lib.clone(),
            api,
            ctx,
        }
    }

    pub fn get_size(&self) -> FrameSize {
        unsafe {
            let mut width: u32 = 0;
            let mut height: u32 = 0;
            (self.api.NowWaykPacketsParsing_GetSize)(self.ctx, (&mut width) as *mut u32, (&mut height) as *mut u32);
            FrameSize { width, height }
        }
    }

    pub fn parse_message(&self, buffer: &[u8], len: usize, is_from_server: bool) -> (usize, u32) {
        unsafe {
            let mut message_id: u32 = 0;
            let res = (self.api.NowWaykPacketsParsing_ParseMessage)(
                self.ctx,
                buffer.as_ptr(),
                len,
                (&mut message_id) as *mut u32,
                is_from_server,
            );
            (res, message_id)
        }
    }

    pub fn is_message_constructed(&self) -> bool {
        unsafe { (self.api.NowWaykPacketsParsing_IsMessageConstructed)(self.ctx) }
    }

    pub fn get_image_data(&self) -> ImageUpdate {
        unsafe {
            let mut update_x: u32 = 0;
            let mut update_y: u32 = 0;
            let mut update_width: u32 = 0;
            let mut update_height: u32 = 0;
            let mut surface_step: u32 = 0;
            let mut surface_size: u32 = 0;
            let ptr: *const u8 = (self.api.NowWaykPacketsParsing_GetImageBuff)(
                self.ctx,
                (&mut update_x) as *mut u32,
                (&mut update_y) as *mut u32,
                (&mut update_width) as *mut u32,
                (&mut update_height) as *mut u32,
                (&mut surface_step) as *mut u32,
                (&mut surface_size) as *mut u32,
            );

            let mut image_buff: Vec<u8> = Vec::new();
            let raw_image_buf = std::slice::from_raw_parts::<u8>(ptr, surface_size as usize);
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
}

impl Drop for PacketsParser {
    fn drop(&mut self) {
        unsafe {
            (self.api.NowWaykPacketsParsing_FreeParsingContext)(self.ctx);
        }
    }
}
