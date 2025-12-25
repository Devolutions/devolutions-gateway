use std::sync::Arc;

use anyhow::bail;
use windows::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent, WaitForSingleObject};

use crate::Error;
use crate::handle::Handle;
use crate::utils::WideString;

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

    pub fn new_named(name: &str, manual_reset: bool, initial_state: bool) -> anyhow::Result<Self> {
        let name_wide = WideString::from(name);

        // SAFETY: name_wide is a valid null-terminated UTF-16 string
        let raw_handle = unsafe {
            CreateEventW(
                None,                  // Default security
                manual_reset,          // Manual or auto-reset
                initial_state,         // Initially signaled or not
                name_wide.as_pcwstr(), // Event name
            )
        }?;

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

    pub fn wait(&self, timeout_ms: Option<u32>) -> anyhow::Result<()> {
        // SAFETY: No preconditions.
        let status = unsafe { WaitForSingleObject(self.handle.raw(), timeout_ms.unwrap_or(INFINITE)) };

        match status {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => bail!("Timeout waiting for event"),
            WAIT_FAILED => bail!(Error::last_error()),
            _ => bail!("Unexpected wait result"),
        }
    }
}
