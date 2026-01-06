use std::ffi::c_void;
use std::fmt::Debug;

use anyhow::{Result, bail};
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::TOKEN_ACCESS_MASK;
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, GetCurrentThread, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenThread, OpenThreadToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ResumeThread, SuspendThread, THREAD_ACCESS_RIGHTS, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use crate::Error;
use crate::handle::{Handle, HandleWrapper};
use crate::process::Process;
use crate::token::Token;

#[derive(Debug)]
pub struct Thread {
    pub handle: Handle,
}

impl From<Handle> for Thread {
    fn from(handle: Handle) -> Self {
        Self { handle }
    }
}

impl Thread {
    pub fn get_by_id(id: u32, desired_access: THREAD_ACCESS_RIGHTS) -> Result<Self> {
        // SAFETY: No preconditions.
        let handle = unsafe { OpenThread(desired_access, false, id)? };

        // SAFETY: The handle is owned by us, we opened the resource above.
        let handle = unsafe { Handle::new_owned(handle)? };

        Ok(Self::from(handle))
    }

    pub fn current() -> Self {
        // SAFETY: No preconditions. Returns a pseudohandle, thus not owning it.
        let handle = unsafe { GetCurrentThread() };
        let handle = Handle::new_borrowed(handle).expect("always valid");

        Self::from(handle)
    }

    pub fn join(&self, timeout_ms: Option<u32>) -> Result<()> {
        // SAFETY: No preconditions.
        let result = unsafe { WaitForSingleObject(self.handle.raw(), timeout_ms.unwrap_or(INFINITE)) };

        match result {
            WAIT_OBJECT_0 => Ok(()),
            _ => bail!(Error::last_error()),
        }
    }

    pub fn suspend(&self) -> Result<()> {
        // SAFETY: No preconditions.
        if unsafe { SuspendThread(self.handle.raw()) } == u32::MAX {
            bail!(Error::last_error())
        } else {
            Ok(())
        }
    }

    pub fn resume(&self) -> Result<()> {
        // SAFETY: No preconditions.
        if unsafe { ResumeThread(self.handle.raw()) } == u32::MAX {
            bail!(Error::last_error())
        } else {
            Ok(())
        }
    }

    pub fn token(&self, desired_access: TOKEN_ACCESS_MASK, open_as_self: bool) -> Result<Token> {
        let mut handle = HANDLE::default();

        // SAFETY: Returned handle must be closed, which is done in its RAII wrapper.
        unsafe { OpenThreadToken(self.handle.raw(), desired_access, open_as_self, &mut handle) }?;

        // SAFETY: We own the handle.
        let handle = unsafe { Handle::new_owned(handle)? };

        Ok(Token::from(handle))
    }
}

impl HandleWrapper for Thread {
    fn handle(&self) -> &Handle {
        &self.handle
    }
}

pub struct ThreadAttributeList(Vec<u8>);

impl<'a> ThreadAttributeList {
    pub fn with_count(count: u32) -> Result<ThreadAttributeList> {
        // The output has a variable size.
        // Therefore, we must call InitializeProcThreadAttributeList once with a zero-size, and check for the ERROR_INSUFFICIENT_BUFFER status.
        // At this point, we call InitializeProcThreadAttributeList again with a buffer of the correct size.

        let mut required_size = 0;

        // SAFETY: No preconditions.
        let res = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut required_size) };

        let Err(err) = res else {
            anyhow::bail!("first call to InitializeProcThreadAttributeList did not fail")
        };

        // SAFETY: FFI call with no outstanding precondition.
        if unsafe { windows::Win32::Foundation::GetLastError() }
            != windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER
        {
            return Err(anyhow::Error::new(err).context(
                "first call to InitializeProcThreadAttributeList did not fail with ERROR_INSUFFICIENT_BUFFER",
            ));
        }

        let mut allocated_length = required_size;
        let mut buf = vec![0; allocated_length];

        // SAFETY: `lpAttributeList` points to a buffer of the `out_size`.
        unsafe {
            InitializeProcThreadAttributeList(
                Some(LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr().cast())),
                count,
                None,
                &mut allocated_length,
            )?;
        };

        debug_assert_eq!(allocated_length, required_size);

        Ok(ThreadAttributeList(buf))
    }

    pub fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.0.as_mut_ptr().cast())
    }

    pub fn update(&mut self, attribute: &'a ThreadAttributeType<'a>) -> Result<()> {
        // SAFETY: List must be initialized with `InitializeProcThreadAttributeList`, which is done in `ThreadAttributeList::with_count`.
        // Value must persists until list is dropped.
        unsafe {
            Ok(UpdateProcThreadAttribute(
                self.raw(),
                0,
                attribute.attribute() as usize,
                Some(attribute.value()),
                attribute.size(),
                None,
                None,
            )?)
        }
    }
}

impl Drop for ThreadAttributeList {
    fn drop(&mut self) {
        // SAFETY: List must be initialized with `InitializeProcThreadAttributeList`, which is done in `ThreadAttributeList::with_count`.
        unsafe { DeleteProcThreadAttributeList(self.raw()) };
    }
}

pub enum ThreadAttributeType<'a> {
    ParentProcess(&'a Process),
    ExtendedFlags(u32),
    HandleList(Vec<HANDLE>),
}

impl ThreadAttributeType<'_> {
    pub fn attribute(&self) -> u32 {
        match self {
            ThreadAttributeType::ParentProcess(_) => PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            ThreadAttributeType::ExtendedFlags(_) => 0x60001,
            ThreadAttributeType::HandleList(_) => PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        }
    }

    pub fn value(&self) -> *const c_void {
        match self {
            ThreadAttributeType::ParentProcess(p) => p.handle.raw_as_ref() as *const _ as *const c_void,
            ThreadAttributeType::ExtendedFlags(v) => &v as *const _ as *const c_void,
            ThreadAttributeType::HandleList(h) => h.as_ptr().cast(),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            ThreadAttributeType::ParentProcess(_) => size_of::<HANDLE>(),
            ThreadAttributeType::ExtendedFlags(_) => size_of::<u32>(),
            ThreadAttributeType::HandleList(h) => size_of::<HANDLE>() * h.len(),
        }
    }
}
