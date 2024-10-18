//! WIP: This file is copied from MSRDPEX project

use crate::config::ConfHandle;
use windows::core::PCSTR;
use windows::Win32::Foundation::{
    DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_IO_PENDING, HANDLE, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::RemoteDesktop::{
    WTSFreeMemory, WTSVirtualChannelClose, WTSVirtualChannelOpenEx, WTSVirtualChannelQuery, WTSVirtualFileHandle,
    CHANNEL_FLAG_LAST, CHANNEL_PDU_HEADER, WTS_CHANNEL_OPTION_DYNAMIC, WTS_CURRENT_SESSION, WTS_VIRTUAL_CLASS,
};
use windows::Win32::System::Threading::{CreateEventW, GetCurrentProcess, WaitForSingleObject, INFINITE};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

const CHANNEL_PDU_LENGTH: usize = 1024;

pub fn loop_dvc(config: ConfHandle) {
    if !config.get_conf().debug.enable_unstable {
        debug!("DVC loop is disabled");
        return;
    }

    info!("Starting DVC loop");

    let channel_name = "DvcSample";
    match open_virtual_channel(channel_name) {
        Ok(h_file) => {
            info!("Virtual channel opened");

            if let Err(error) = handle_virtual_channel(h_file) {
                error!(%error, "DVC handling falied");
            }
        }
        Err(error) => {
            error!(%error, "Failed to open virtual channel");
            // NOTE: Not exiting the program here, as it is not the main functionality
        }
    }

    info!("DVC loop finished");
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
#[allow(clippy::undocumented_unsafe_blocks)]
fn open_virtual_channel(channel_name: &str) -> windows::core::Result<HANDLE> {
    unsafe {
        let channel_name_wide = PCSTR::from_raw(channel_name.as_ptr());
        let h_wts_handle = WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, channel_name_wide, WTS_CHANNEL_OPTION_DYNAMIC)
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        let mut vc_file_handle_ptr: *mut HANDLE = std::ptr::null_mut();
        let mut len: u32 = 0;
        let wts_virtual_class: WTS_VIRTUAL_CLASS = WTSVirtualFileHandle;
        WTSVirtualChannelQuery(
            h_wts_handle,
            wts_virtual_class,
            &mut vc_file_handle_ptr as *mut _ as *mut _,
            &mut len,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        let mut new_handle: HANDLE = HANDLE::default();
        let _duplicate_result = DuplicateHandle(
            GetCurrentProcess(),
            *vc_file_handle_ptr,
            GetCurrentProcess(),
            &mut new_handle,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        );

        WTSFreeMemory(vc_file_handle_ptr as *mut core::ffi::c_void);
        let _ = WTSVirtualChannelClose(h_wts_handle);

        Ok(new_handle)
    }
}

#[allow(clippy::multiple_unsafe_ops_per_block)]
#[allow(clippy::undocumented_unsafe_blocks)]
fn write_virtual_channel_message(h_file: HANDLE, cb_size: u32, buffer: *const u8) -> windows::core::Result<()> {
    unsafe {
        let buffer_slice = std::slice::from_raw_parts(buffer, cb_size as usize);
        let mut dw_written: u32 = 0;
        WriteFile(h_file, Some(buffer_slice), Some(&mut dw_written), None)
    }
}

#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_ptr_alignment)]
#[allow(clippy::ptr_offset_with_cast)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::multiple_unsafe_ops_per_block)]
#[allow(clippy::undocumented_unsafe_blocks)]
fn handle_virtual_channel(h_file: HANDLE) -> windows::core::Result<()> {
    unsafe {
        let mut read_buffer = [0u8; CHANNEL_PDU_LENGTH];
        let mut overlapped = OVERLAPPED::default();
        let mut dw_read: u32 = 0;

        let cmd = "whoami\0";
        let cb_size = cmd.len() as u32;
        write_virtual_channel_message(h_file, cb_size, cmd.as_ptr())?;

        let h_event = CreateEventW(None, false, false, None)?;
        overlapped.hEvent = h_event;

        loop {
            // Notice the wrapping of parameters in Some()
            let result = ReadFile(
                h_file,
                Some(&mut read_buffer),
                Some(&mut dw_read),
                Some(&mut overlapped),
            );

            if let Err(e) = result {
                if GetLastError() == WIN32_ERROR(ERROR_IO_PENDING.0) {
                    let _dw_status = WaitForSingleObject(h_event, INFINITE);
                    if GetOverlappedResult(h_file, &overlapped, &mut dw_read, false).is_err() {
                        return Err(windows::core::Error::from_win32());
                    }
                } else {
                    return Err(e);
                }
            }

            info!("read {} bytes", dw_read);

            let packet_size = dw_read as usize - std::mem::size_of::<CHANNEL_PDU_HEADER>();
            let p_data = read_buffer
                .as_ptr()
                .offset(std::mem::size_of::<CHANNEL_PDU_HEADER>() as isize);

            info!(
                ">> {}",
                std::str::from_utf8(std::slice::from_raw_parts(p_data, packet_size)).unwrap_or("Invalid UTF-8")
            );

            if dw_read == 0
                || ((*(p_data.offset(-(std::mem::size_of::<CHANNEL_PDU_HEADER>() as isize))
                    as *const CHANNEL_PDU_HEADER))
                    .flags
                    & CHANNEL_FLAG_LAST)
                    != 0
            {
                break;
            }
        }

        Ok(())
    }
}
