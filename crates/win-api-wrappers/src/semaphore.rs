use std::sync::Arc;

use crate::handle::Handle;
use anyhow::Context;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateSemaphoreW, ReleaseSemaphore};

/// RAII wrapper for WinAPI semaphore handle.
#[derive(Debug, Clone)]
pub struct Semaphore {
    handle: Arc<Handle>,
}

impl Semaphore {
    pub fn new_unnamed(initial_count: u32, maximum_count: u32) -> anyhow::Result<Self> {
        if maximum_count == 0 {
            anyhow::bail!("Maximum count must be greater than 0");
        }

        if initial_count > maximum_count {
            anyhow::bail!("Initial count must be less than or equal to maximum count");
        }

        let initial_count = i32::try_from(initial_count).context("Semaphore initial count is too large")?;

        let maximum_count = i32::try_from(maximum_count).context("Semaphore maximum count is too large")?;

        // SAFETY: All parameters are checked for validity above:
        // - initial_count is always <= maximum_count.
        // - maximum_count is always > 0.
        // - all values are positive.
        let raw_handle = unsafe { CreateSemaphoreW(None, initial_count, maximum_count, None) }?;

        // SAFETY: We own the handle and it is guaranteed to be valid.
        let handle = unsafe { Handle::new_owned(raw_handle) }?;

        Ok(Self {
            handle: Arc::new(handle),
        })
    }

    pub fn raw(&self) -> HANDLE {
        self.handle.raw()
    }

    pub fn release(&self, release_count: u32) -> anyhow::Result<u32> {
        let release_count = i32::try_from(release_count).context("Semaphore release count is too large")?;

        if release_count == 0 {
            anyhow::bail!("Semaphore release count must be greater than 0");
        }

        let mut previous_count = 0;
        // SAFETY: All parameters are checked for validity above:
        // - release_count >= 0.
        // - lpPreviousCount points to valid stack memory.
        // - handle is valid and owned by this struct.
        unsafe {
            ReleaseSemaphore(self.handle.raw(), release_count, Some(&mut previous_count))?;
        }
        Ok(previous_count.try_into().expect("Semaphore count is negative"))
    }
}
