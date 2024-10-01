use std::sync::Arc;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateEventW, SetEvent};

use crate::handle::Handle;

/// RAII wrapper for WinAPI event handle.
#[derive(Debug, Clone)]
pub struct Event {
    handle: Arc<Handle>,
}

impl Event {
    pub fn new_unnamed() -> anyhow::Result<Self> {
        // SAFETY: No preconditions.
        let raw_handle = unsafe { CreateEventW(None, false, false, None) }?;

        // SAFETY: `CreateEventW` always returns a valid handle on success.
        let handle = unsafe { Handle::new_owned(raw_handle) }?;

        Ok(Self {
            handle: Arc::new(handle),
        })
    }

    pub fn raw(&self) -> HANDLE {
        self.handle.raw()
    }

    pub fn set(&self) -> anyhow::Result<()> {
        // SAFETY: No preconditions.
        unsafe {
            SetEvent(self.handle.raw())?;
        }
        Ok(())
    }
}
