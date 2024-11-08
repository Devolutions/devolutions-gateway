use windows::core::Owned;
use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows::Win32::System::RemoteDesktop::{
    WTSFreeMemory, WTSVirtualChannelClose, WTSVirtualChannelOpenEx, WTSVirtualChannelQuery, WTSVirtualFileHandle,
    WTS_CHANNEL_OPTION_DYNAMIC, WTS_CURRENT_SESSION,
};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::utils::AnsiString;

/// RAII wrapper for WTS virtual channel handle.
pub struct WTSVirtualChannel(HANDLE);

impl WTSVirtualChannel {
    /// # Safety
    /// `handle` must be a valid handle returned from `WTSVirtualChannelOpenEx`.
    pub unsafe fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn open_dvc(name: &str) -> anyhow::Result<Self> {
        let channel_name = AnsiString::from(name);

        // SAFETY: Channel name is always a valid pointer to a null-terminated string.
        let raw_wts_handle = unsafe {
            WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, channel_name.as_pcstr(), WTS_CHANNEL_OPTION_DYNAMIC)
        }?;

        // SAFETY: `WTSVirtualChannelOpenEx` always returns a valid handle on success.
        Ok(unsafe { Self::new(raw_wts_handle) })
    }

    pub fn query_file_handle(&self) -> anyhow::Result<Owned<HANDLE>> {
        let mut channel_file_handle_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;

        // SAFETY: It is safe to call `WTSVirtualChannelQuery` with valid channel and
        // destination pointers.
        unsafe {
            WTSVirtualChannelQuery(
                self.0,
                WTSVirtualFileHandle,
                &mut channel_file_handle_ptr as *mut _,
                &mut len,
            )
        }?;

        // SAFETY: `channel_file_handle_ptr` is always a valid pointer to a handle on success.
        let channel_file_handle_ptr = unsafe { WTSMemory::new(channel_file_handle_ptr) };

        if len != u32::try_from(size_of::<HANDLE>()).expect("HANDLE always fits into u32") {
            return Err(anyhow::anyhow!("Failed to query DVC channel file handle"));
        }

        let mut raw_handle = HANDLE::default();

        // SAFETY: `GetCurrentProcess` is always safe to call.
        let current_process = unsafe { GetCurrentProcess() };

        // SAFETY: `lptargetprocesshandle` is valid and points to `raw_handle` declared above,
        // therefore it is safe to call.
        unsafe {
            DuplicateHandle(
                current_process,
                channel_file_handle_ptr.as_handle(),
                current_process,
                &mut raw_handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )?;
        };

        // SAFETY: Handle returned from `DuplicateHandle` is always valid if the function succeeds.
        let owned_handle = unsafe { Owned::new(raw_handle) };

        Ok(owned_handle)
    }
}

impl Drop for WTSVirtualChannel {
    fn drop(&mut self) {
        // SAFETY: `Ok` value returned from `WTSVirtualChannelOpenEx` is always a valid handle.
        if let Err(error) = unsafe { WTSVirtualChannelClose(self.0) } {
            error!(%error, "Failed to close WTS virtual channel handle");
        }
    }
}

/// RAII wrapper for WTS memory handle.
struct WTSMemory(*mut core::ffi::c_void);

impl WTSMemory {
    /// # Safety
    /// `ptr` must be a valid pointer to a handle returned from `WTSVirtualChannelQuery`.
    unsafe fn new(ptr: *mut core::ffi::c_void) -> Self {
        Self(ptr)
    }

    fn as_handle(&self) -> HANDLE {
        if self.0.is_null() {
            return HANDLE::default();
        }

        // SAFETY: `self.0` is always a valid pointer to a handle if constructed properly,
        // therefore it is safe to dereference it.
        HANDLE(unsafe { *(self.0 as *mut *mut std::ffi::c_void) })
    }
}

impl Drop for WTSMemory {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }

        // SAFETY: No preconditions.
        unsafe { WTSFreeMemory(self.0) }
    }
}

impl Default for WTSMemory {
    fn default() -> Self {
        Self(std::ptr::null_mut())
    }
}
