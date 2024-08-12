use std::ffi::c_void;
use std::fmt::Debug;
use std::mem::{self};

use anyhow::{bail, Result};

use crate::handle::{Handle, HandleWrapper};
use crate::process::Process;
use crate::token::Token;
use crate::Error;
use windows::Win32::Foundation::{E_HANDLE, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::TOKEN_ACCESS_MASK;
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, GetCurrentThread, InitializeProcThreadAttributeList, OpenThread, OpenThreadToken,
    ResumeThread, SuspendThread, UpdateProcThreadAttribute, WaitForSingleObject, INFINITE,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    THREAD_ACCESS_RIGHTS,
};

#[derive(Debug)]
pub struct Thread {
    pub handle: Handle,
}

impl Thread {
    pub fn try_with_handle(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            bail!(Error::from_hresult(E_HANDLE))
        } else {
            Ok(Self { handle: handle.into() })
        }
    }

    pub fn try_get_by_id(id: u32, desired_access: THREAD_ACCESS_RIGHTS) -> Result<Self> {
        // SAFETY: No preconditions.
        let handle = unsafe { OpenThread(desired_access, false, id) }?;

        Self::try_with_handle(handle)
    }

    pub fn current() -> Self {
        Self {
            // SAFETY: No preconditions. Returns a pseudohandle, thus not owning it.
            handle: Handle::new(unsafe { GetCurrentThread() }, false),
        }
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
        let mut handle = Default::default();

        // SAFETY: Returned handle must be closed, which is done in its RAII wrapper.
        unsafe { OpenThreadToken(self.handle.raw(), desired_access, open_as_self, &mut handle) }?;

        Token::try_with_handle(handle)
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
        let mut out_size = 0;

        // SAFETY: No preconditions.
        let _ = unsafe {
            InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST::default(), count, 0, &mut out_size)
        };

        let mut buf = vec![0; out_size];

        // SAFETY: `lpAttributeList` points to a buffer of the `out_size`.
        unsafe {
            InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr().cast()),
                count,
                0,
                &mut out_size,
            )?;
        };

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
            ThreadAttributeType::ParentProcess(p) => p.handle.as_raw_ref() as *const _ as *const c_void,
            ThreadAttributeType::ExtendedFlags(v) => &v as *const _ as *const c_void,
            ThreadAttributeType::HandleList(h) => h.as_ptr().cast(),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            ThreadAttributeType::ParentProcess(_) => mem::size_of::<HANDLE>(),
            ThreadAttributeType::ExtendedFlags(_) => mem::size_of::<u32>(),
            ThreadAttributeType::HandleList(h) => mem::size_of::<HANDLE>() * h.len(),
        }
    }
}
