use std::fmt::Debug;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, IntoRawHandle, OwnedHandle};

use windows::Win32::Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, E_HANDLE, HANDLE};
use windows::Win32::System::Threading::GetCurrentProcess;

// TODO: Use/implement AsHandle and AsRawHandle as appropriate

/// A wrapper around a Windows [`HANDLE`].
///
/// Whenever possible, you should use [`BorrowedHandle`] or [`OwnedHandle`] instead.
/// Those are safer to use.
#[derive(Debug, Clone)]
pub struct Handle {
    raw: HANDLE,
    owned: bool,
}

// SAFETY: A `HANDLE` is, by definition, thread safe.
unsafe impl Send for Handle {}

// SAFETY: A `HANDLE` is simply an integer, no dereferencing is done.
unsafe impl Sync for Handle {}

/// The `Drop` implementation is assuming we constructed the `Handle` object in
/// a sane way to call `CloseHandle`, but there is no way for us to verify that
/// the handle is actually owned outside of the callsite. Conceptually, calling
/// `Handle::new_owned(handle)` or `Handle::new(handle, true)` is like calling the
/// unsafe function `CloseHandle` and thus must inherit its safety preconditions.
impl Handle {
    /// Wraps a Windows [`HANDLE`].
    ///
    /// # Safety
    ///
    /// When `owned` is `true`:
    ///
    /// - `handle` is a valid handle to an open object.
    /// - `handle` is not a pseudohandle.
    /// - The caller is actually responsible for closing the `HANDLE` when the value goes out of scope.
    ///
    /// When `owned` is `false`: no outstanding precondition.
    pub unsafe fn new(handle: HANDLE, owned: bool) -> Result<Self, crate::Error> {
        if handle.is_invalid() || handle.0.is_null() {
            return Err(crate::Error::from_hresult(E_HANDLE));
        }

        Ok(Self { raw: handle, owned })
    }

    /// Wraps an owned Windows [`HANDLE`].
    ///
    /// # Safety
    ///
    /// - `handle` is a valid handle to an open object.
    /// - `handle` is not a pseudohandle.
    /// - The caller is actually responsible for closing the `HANDLE` when the value goes out of scope.
    pub unsafe fn new_owned(handle: HANDLE) -> Result<Self, crate::Error> {
        // SAFETY: Same preconditions as the called function.
        unsafe { Self::new(handle, true) }
    }

    /// Wraps a pseudo Windows [`HANDLE`].
    ///
    /// # Safety
    ///
    /// - The caller should ensure that `handle` is a pseudo handle, as its validity is not checked.
    pub unsafe fn new_pseudo_handle(handle: HANDLE) -> Self {
        Self {
            raw: handle,
            owned: false,
        }
    }
}

impl Handle {
    /// Wraps a borrowed Windows [`HANDLE`].
    ///
    /// Always use this when knowing statically that the handle is never owned.
    pub fn new_borrowed(handle: HANDLE) -> Result<Self, crate::Error> {
        // SAFETY: It’s safe to wrap a non-owning Handle as we’ll not call `CloseHandle` on it.
        unsafe { Self::new(handle, false) }
    }

    pub fn raw(&self) -> HANDLE {
        self.raw
    }

    pub fn raw_as_ref(&self) -> &HANDLE {
        &self.raw
    }

    pub fn leak(&mut self) {
        self.owned = false;
    }

    pub fn try_clone(&self) -> anyhow::Result<Self> {
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

        // SAFETY: The duplicated handle is owned by us.
        let handle = unsafe { Self::new_owned(duplicated)? };

        Ok(handle)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: `self.raw` is a valid handle to an open object by construction.
            //    It’s also safe to close it ourselves when `self.owned` is true per contract.
            let _ = unsafe { CloseHandle(self.raw) };
        }
    }
}

// TODO: make this return a borrowed `Handle`.

impl TryFrom<&BorrowedHandle<'_>> for Handle {
    type Error = anyhow::Error;

    fn try_from(value: &BorrowedHandle<'_>) -> anyhow::Result<Self, Self::Error> {
        let handle = Self {
            raw: HANDLE(value.as_raw_handle().cast()),
            owned: false,
        };

        handle.try_clone()
    }
}

impl TryFrom<BorrowedHandle<'_>> for Handle {
    type Error = anyhow::Error;

    fn try_from(value: BorrowedHandle<'_>) -> anyhow::Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl From<OwnedHandle> for Handle {
    fn from(handle: OwnedHandle) -> Self {
        Self {
            raw: HANDLE(handle.into_raw_handle().cast()),
            owned: true,
        }
    }
}

pub trait HandleWrapper {
    fn handle(&self) -> &Handle;
}
