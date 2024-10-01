use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::RemoteDesktop::{WTSFreeMemory, WTSVirtualChannelClose};

/// RAII wrapper for WTS virtual channel handle.
pub struct WTSVirtualChannel(HANDLE);

impl WTSVirtualChannel {
    /// # Safety
    /// `handle` must be a valid handle returned from `WTSVirtualChannelOpenEx`.
    pub unsafe fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
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
pub struct WTSMemory(*mut core::ffi::c_void);

impl WTSMemory {
    /// # Safety
    /// `ptr` must be a valid pointer to a handle returned from `WTSVirtualChannelQuery`.
    pub unsafe fn new(ptr: *mut core::ffi::c_void) -> Self {
        Self(ptr)
    }

    pub fn raw(&self) -> *mut core::ffi::c_void {
        self.0
    }

    pub fn as_handle(&self) -> HANDLE {
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
