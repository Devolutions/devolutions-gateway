use std::fmt::Debug;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, IntoRawHandle, OwnedHandle};

use anyhow::Result;

use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows::Win32::System::Threading::GetCurrentProcess;

#[derive(Debug, Clone)]
pub struct Handle {
    raw: HANDLE,
    owned: bool,
}

// SAFETY: A `HANDLE` is, by definition, thread safe.
unsafe impl Send for Handle {}

// SAFETY: A `HANDLE` is simply an integer, no dereferencing is done.
unsafe impl Sync for Handle {}

impl Handle {
    pub fn new(handle: HANDLE, owned: bool) -> Self {
        Self { raw: handle, owned }
    }

    pub fn raw(&self) -> HANDLE {
        self.raw
    }

    pub fn as_raw_ref(&self) -> &HANDLE {
        &self.raw
    }

    pub fn leak(&mut self) {
        self.owned = false;
    }

    pub fn try_clone(&self) -> Result<Self> {
        // SAFETY: No preconditions. Always a valid handle.
        let current_process = unsafe { GetCurrentProcess() };
        let mut duplicated = HANDLE::default();

        // SAFETY: `current_process` is valid. No preconditions. Returned handle is closed with its RAII wrapper.
        unsafe {
            DuplicateHandle(
                current_process,
                self.raw(),
                current_process,
                &mut duplicated,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )?;
        }

        Ok(duplicated.into())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: No preconditions and handle is assumed to be valid if owned (we assume it is not a pseudohandle).
            let _ = unsafe { CloseHandle(self.raw) };
        }
    }
}

impl From<HANDLE> for Handle {
    fn from(value: HANDLE) -> Self {
        Self::new(value, true)
    }
}

impl TryFrom<&BorrowedHandle<'_>> for Handle {
    type Error = anyhow::Error;

    fn try_from(value: &BorrowedHandle<'_>) -> Result<Self, Self::Error> {
        let handle = Handle {
            raw: HANDLE(value.as_raw_handle().cast()),
            owned: false,
        };

        Self::try_clone(&handle)
    }
}

impl TryFrom<BorrowedHandle<'_>> for Handle {
    type Error = anyhow::Error;

    fn try_from(value: BorrowedHandle<'_>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl From<OwnedHandle> for Handle {
    fn from(handle: OwnedHandle) -> Self {
        Self::from(HANDLE(handle.into_raw_handle().cast()))
    }
}

pub trait HandleWrapper {
    fn handle(&self) -> &Handle;
}
