use std::collections::HashMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fmt::Debug;
use std::io::{Read, Write};
use std::mem::{self, MaybeUninit};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{ptr, slice};

use anyhow::{bail, Result};

use crate::handle::{Handle, HandleWrapper};
use crate::process::Process;
use crate::security::acl::{RawSecurityAttributes, SecurityAttributes};
use crate::thread::Thread;
use crate::token::Token;
use crate::Error;
use windows::core::{Interface, PCSTR, PCWSTR, PSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, E_INVALIDARG, E_POINTER, HANDLE, HLOCAL, MAX_PATH, UNICODE_STRING};
use windows::Win32::Security::{
    RevertToSelf, SecurityIdentification, TokenPrimary, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS,
};
use windows::Win32::Storage::FileSystem::{CreateDirectoryW, FlushFileBuffers, ReadFile, WriteFile};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER, COINIT, COINIT_MULTITHREADED,
    STGM_READ,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, CREATE_TOOLHELP_SNAPSHOT_FLAGS, PROCESSENTRY32,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS,
    PAGE_READWRITE,
};
use windows::Win32::System::Pipes::{
    CreatePipe, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient, PeekNamedPipe,
};
use windows::Win32::UI::Controls::INFOTIPSIZE;
use windows::Win32::UI::Shell::{CommandLineToArgvW, IShellLinkW, ShellLink, SLGP_SHORTPATH, SLR_NO_UI};

pub trait SafeWindowsString {
    fn to_string_safe(&self) -> Result<String>;
    fn to_os_string_safe(&self) -> Result<OsString>;
    fn to_path_safe(&self) -> Result<PathBuf>;
}

macro_rules! impl_safe_win_string {
    ($t:ty) => {
        impl SafeWindowsString for $t {
            fn to_string_safe(&self) -> Result<String> {
                if self.is_null() {
                    bail!(Error::from_hresult(E_POINTER))
                } else {
                    // SAFETY: pointer is non null as requested by `to_string()`'s safety requirements.
                    unsafe { Ok(self.to_string()?) }
                }
            }

            fn to_os_string_safe(&self) -> Result<OsString> {
                self.to_string_safe().map(|s| s.into())
            }

            fn to_path_safe(&self) -> Result<PathBuf> {
                self.to_os_string_safe().map(|x| x.into())
            }
        }
    };
}

impl_safe_win_string!(PWSTR);
impl_safe_win_string!(PSTR);
impl_safe_win_string!(PCWSTR);
impl_safe_win_string!(PCSTR);

#[derive(Default)]
pub struct AnsiString(pub Option<Vec<u8>>);

impl AnsiString {
    pub fn as_pcstr(&self) -> PCSTR {
        self.0
            .as_ref()
            .map(|x| PCSTR::from_raw(x.as_ptr()))
            .unwrap_or_else(PCSTR::null)
    }

    pub fn as_pstr(&mut self) -> PSTR {
        self.0
            .as_mut()
            .map(|x| PSTR::from_raw(x.as_mut_ptr()))
            .unwrap_or_else(PSTR::null)
    }
}

impl<T: ?Sized + AsRef<OsStr>> From<&T> for AnsiString {
    fn from(value: &T) -> Self {
        let mut buf = value.as_ref().as_encoded_bytes().to_vec();
        buf.push(0);
        Self(Some(buf))
    }
}

impl FromStr for AnsiString {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut buf = s.as_bytes().to_vec();
        buf.push(0);
        Ok(Self(Some(buf)))
    }
}

impl From<String> for AnsiString {
    fn from(value: String) -> Self {
        Self::from(&value)
    }
}

impl<T> From<Option<T>> for AnsiString
where
    T: for<'a> Into<&'a str>,
{
    fn from(value: Option<T>) -> Self {
        value.map(|x| AnsiString::from(x.into())).unwrap_or_default()
    }
}

#[derive(Default, Debug)]
pub struct WideString(pub Option<Vec<u16>>);

impl WideString {
    pub fn as_pcwstr(&self) -> PCWSTR {
        self.0
            .as_ref()
            .map(|x| PCWSTR::from_raw(x.as_ptr()))
            .unwrap_or_else(PCWSTR::null)
    }

    pub fn as_pwstr(&mut self) -> PWSTR {
        self.0
            .as_mut()
            .map(|x| PWSTR::from_raw(x.as_mut_ptr()))
            .unwrap_or_else(PWSTR::null)
    }

    pub fn as_unicode_string(&self) -> Result<UNICODE_STRING> {
        Ok(UNICODE_STRING {
            Length: self
                .0
                .as_ref()
                .and_then(|x| x.split_last())
                .map(|x| mem::size_of_val(x.1))
                .unwrap_or(0)
                .try_into()?,
            MaximumLength: self
                .0
                .as_ref()
                .map(|x| mem::size_of_val(x.as_slice()))
                .unwrap_or(0)
                .try_into()?,
            Buffer: PWSTR(self.as_pcwstr().0.cast_mut()),
        })
    }
}

impl<T: ?Sized + AsRef<OsStr>> From<&T> for WideString {
    fn from(value: &T) -> Self {
        let mut buf = value.as_ref().encode_wide().collect::<Vec<_>>();
        buf.push(0);
        Self(Some(buf))
    }
}

impl FromStr for WideString {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let mut buf = s.encode_utf16().collect::<Vec<_>>();
        buf.push(0);
        Ok(Self(Some(buf)))
    }
}

impl From<String> for WideString {
    fn from(value: String) -> Self {
        Self::from(&value)
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct CommandLine(pub Vec<String>);

impl CommandLine {
    pub fn new(args: Vec<String>) -> Self {
        Self(args)
    }

    pub fn from_command_line(command_line: &str) -> Self {
        let command_line = WideString::from(command_line);
        let mut arg_cnt = 0;

        // SAFETY: `command_line` is valid and NUL terminated. `raw_args` will point to memory allocated by `LocalAlloc`.
        let raw_args = unsafe { CommandLineToArgvW(command_line.as_pcwstr(), &mut arg_cnt) };

        let arg_cnt = usize::try_from(arg_cnt).unwrap_or_default();

        // If we get an error, no args.
        if raw_args.is_null() {
            return Self(vec![]);
        }

        // SAFETY: We assume that if the address is valid and the function did not have an error, arg_cnt will be valid.
        let args = unsafe { slice::from_raw_parts(raw_args, arg_cnt) }
            .iter()
            .filter_map(|x| x.to_string_safe().ok())
            .collect::<Vec<_>>();

        // SAFETY: No preconditions. `raw_args` is valid and must be freed.
        let _ = unsafe { LocalFree(HLOCAL(raw_args.cast())) };

        Self(args)
    }

    /// Encodes an argument array to a command line string for Windows.
    ///
    /// Loosely based off of https://learn.microsoft.com/en-us/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way.
    pub fn to_command_line(&self) -> String {
        let mut command_line = String::new();

        let mut it = self.0.iter().peekable();
        while let Some(arg) = it.next() {
            if !arg.is_empty() && !arg.contains(char::is_whitespace) {
                command_line.push_str(arg);
            } else {
                command_line.push('"');

                let mut chars = arg.chars().peekable();
                let mut backslashes = 0;
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if chars.peek().is_some() {
                                backslashes += 1
                            } else {
                                std::iter::repeat('\\')
                                    .take(backslashes * 2)
                                    .for_each(|x| command_line.push(x));

                                backslashes = 0;
                            }
                        }
                        '"' => {
                            std::iter::repeat('\\')
                                .take(backslashes * 2 + 1)
                                .for_each(|x| command_line.push(x));

                            command_line.push('"');
                            backslashes = 0;
                        }
                        x => {
                            std::iter::repeat('\\')
                                .take(backslashes)
                                .for_each(|x| command_line.push(x));

                            command_line.push(x);
                            backslashes = 0;
                        }
                    }
                }

                command_line.push('"');
            }

            if it.peek().is_some() {
                command_line.push(' ');
            }
        }

        command_line
    }

    pub fn args(&self) -> &Vec<String> {
        &self.0
    }
}

impl From<&str> for CommandLine {
    fn from(value: &str) -> Self {
        Self::from_command_line(value)
    }
}

pub struct Allocation<'a> {
    pub address: *mut c_void,
    pub process: &'a Process,
}

impl<'a> Allocation<'a> {
    pub fn try_new(process: &'a Process, size: usize) -> Result<Self> {
        // SAFETY: No preconditions. We assume caller needs the allocation in RW only.
        let address = unsafe {
            VirtualAllocEx(
                process.handle.raw(),
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if address.is_null() {
            bail!(Error::last_error());
        }

        Ok(Allocation { address, process })
    }
}

impl Drop for Allocation<'_> {
    fn drop(&mut self) {
        // SAFETY: We assume the caller has removed any reference to data inside the buffer.
        let _ = unsafe { VirtualFreeEx(self.process.handle.raw(), self.address, 0, MEM_RELEASE) };
    }
}

/// Sets the memory protection of an address.
///
/// # Safety
///
/// `addr` must not point to neighboring code, as if permissions are set incorrectly a crash or UB will occur.
pub unsafe fn set_memory_protection(
    addr: *const c_void,
    size: usize,
    prot: PAGE_PROTECTION_FLAGS,
) -> Result<PAGE_PROTECTION_FLAGS> {
    let mut old_prot = Default::default();

    // SAFETY: `addr` is valid by safety of function. No preconditions.
    unsafe { VirtualProtect(addr, size, prot, &mut old_prot) }?;

    Ok(old_prot)
}

pub fn serialize_environment(environment: &HashMap<String, String>) -> Result<Vec<u16>> {
    let mut serialized = Vec::new();

    for (k, v) in environment.iter() {
        if k.contains('=') {
            bail!(Error::from_hresult(E_INVALIDARG));
        }

        serialized.extend(k.encode_utf16());
        serialized.extend("=".encode_utf16());
        serialized.extend(v.encode_utf16());
        serialized.push(0);
    }

    serialized.push(0);

    Ok(serialized)
}

pub fn environment_block(token: Option<&Token>, inherit: bool) -> Result<HashMap<String, String>> {
    let mut blocks = Vec::new();

    let mut raw_blocks: *const u16 = ptr::null_mut();

    // SAFETY: After a successful invocation, `raw_blocks` will be a pointer to a newly allocated buffer
    // that contains a list of NUL terminated strings and ends with an extra NUL byte.
    // We can safely cast a *const to a *mut as we have no intention of modifying the data under the pointer.
    unsafe {
        CreateEnvironmentBlock(
            &mut raw_blocks as *mut _ as *mut *mut c_void,
            token.map(|x| x.handle().raw()).unwrap_or_default(),
            inherit,
        )?;
    }

    let mut cur_char_ptr = raw_blocks;

    // SAFETY: `cur_char` only increments by one. This means it will always be at maximum one byte beyond the last string.
    // This means the address it points to will always be valid.
    while unsafe { cur_char_ptr.read() } != 0 {
        let mut block = Vec::new();

        loop {
            // SAFETY: If `cur_char` indexes to a zero value, we break out. This ensures the previous check will always be safe.
            // This iteration will always stop on the first zero. This means on each string, or on the before to last zero byte.
            let cur_char = unsafe { cur_char_ptr.read() };

            // SAFETY: Since we are not dereferencing, it is safe to increment it even if we go beyond the before to last zero byte.
            cur_char_ptr = unsafe { cur_char_ptr.add(1) };

            if cur_char == 0 {
                break;
            }

            block.push(cur_char);
        }

        blocks.push(block);
    }

    // SAFETY: No preconditions. Here, `raw_blocks` is a valid allocation.
    unsafe { DestroyEnvironmentBlock(raw_blocks.cast())? };

    let mut env_block = HashMap::new();

    for block in blocks.iter() {
        let block = String::from_utf16(block)?;

        let (k, v) = block.split_once('=').ok_or_else(|| Error::from_hresult(E_INVALIDARG))?;

        env_block.insert(k.to_owned(), v.to_owned());
    }

    Ok(env_block)
}

pub fn expand_environment(src: &str, environment: &HashMap<String, String>) -> String {
    let mut expanded = String::with_capacity(src.len());

    // For strings such as "%MyVar%MyVar%", only the first occurence should be replaced.
    let mut last_replaced = false;

    let mut it = src.split('%').peekable();

    if let Some(first) = it.next() {
        expanded.push_str(first);
    }

    while let Some(segment) = it.next() {
        let var_value = environment.get(segment);

        match (last_replaced, it.peek(), var_value) {
            (true, Some(_), Some(var_value)) => {
                expanded.push_str(var_value);
                last_replaced = true;
            }
            (_, _, _) => {
                if !last_replaced {
                    expanded.push('%');
                }

                expanded.push_str(segment);
                last_replaced = false;
            }
        }
    }

    expanded
}

pub fn expand_environment_path(src: &Path, environment: &HashMap<String, String>) -> Result<PathBuf> {
    Ok(PathBuf::from_str(&expand_environment(
        src.as_os_str()
            .to_str()
            .ok_or_else(|| Error::from_hresult(E_INVALIDARG))?,
        environment,
    ))?)
}

pub struct Snapshot {
    handle: Handle,
}

pub struct ProcessIdIterator<'a> {
    snapshot: &'a Snapshot,
    is_first: bool,
    entry: PROCESSENTRY32,
}

impl<'a> ProcessIdIterator<'a> {
    fn new(snapshot: &'a Snapshot) -> Self {
        Self {
            snapshot,
            is_first: true,
            entry: PROCESSENTRY32 {
                dwSize: size_of_u32::<PROCESSENTRY32>(),
                ..Default::default()
            },
        }
    }
}

impl Iterator for ProcessIdIterator<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let iter_fn = if self.is_first {
            self.is_first = false;
            Process32First
        } else {
            Process32Next
        };

        // SAFETY: Only precondition is entry's `dwSize` being set correctly, which is done in `ProcessIdIterator::new`.
        unsafe { iter_fn(self.snapshot.handle.raw(), &mut self.entry) }.ok()?;

        Some(self.entry.th32ProcessID)
    }
}

impl Snapshot {
    pub fn new(flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, process_id: Option<u32>) -> Result<Self> {
        // SAFETY: No preconditions. Flags or process ID cannot create scenarios where unsafe behavior happens.
        let handle = unsafe { CreateToolhelp32Snapshot(flags, process_id.unwrap_or(0))? };

        Ok(Self {
            handle: Handle::new(handle, true),
        })
    }

    pub fn process_ids(&self) -> ProcessIdIterator<'_> {
        ProcessIdIterator::new(self)
    }
}

pub struct ComContext;

impl ComContext {
    pub fn try_new(coinit: COINIT) -> Result<Self> {
        // SAFETY: Must not be called from `DllMain`. Can be called multiple times on a thread.
        unsafe { CoInitializeEx(None, coinit) }.ok()?;

        Ok(Self)
    }
}

impl Drop for ComContext {
    fn drop(&mut self) {
        // SAFETY: Must be called once for each `CoInitializeEx`.
        unsafe { CoUninitialize() };
    }
}

pub struct Link {
    path: PathBuf,
}

impl Link {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_owned() }
    }

    fn with_instance<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&IShellLinkW) -> Result<T>,
    {
        let _ctx = ComContext::try_new(COINIT_MULTITHREADED)?;

        // SAFETY: Must be called within COM context.
        let inst: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }?;
        let mut persist_file = MaybeUninit::<IPersistFile>::zeroed();

        // SAFETY: Must be called within COM context. `persist_file` is valid and correctly sized.
        unsafe { inst.query(&IPersistFile::IID, persist_file.as_mut_ptr().cast()) }.ok()?;

        // SAFETY: We assume that `.query` initializes `persist_file`.
        let persist_file = unsafe { persist_file.assume_init() };

        let raw_path = WideString::from(&self.path);

        // SAFETY: Must be called within COM context. `raw_path` is valid and NUL terminated.
        unsafe { persist_file.Load(raw_path.as_pcwstr(), STGM_READ) }?;

        // SAFETY: Must be called within COM context.
        unsafe { inst.Resolve(None, SLR_NO_UI.0 as u32) }?;

        f(&inst)
    }

    pub fn target_path(&self) -> Result<PathBuf> {
        self.with_instance(|link| {
            let mut target = vec![0; MAX_PATH as usize];

            // SAFETY: No preconditions. Path is copied to `target`.
            unsafe { link.GetPath(target.as_mut_slice(), ptr::null_mut(), SLGP_SHORTPATH.0 as u32) }?;

            Ok(PathBuf::from(OsString::from_wide(nul_slice_wide_str(&target))))
        })
    }

    pub fn target_args(&self) -> Result<String> {
        self.with_instance(|link| {
            let mut target = vec![0; std::cmp::max(INFOTIPSIZE as usize, MAX_PATH as usize)];

            // SAFETY: No preconditions. Arguments is copied to `target`.
            unsafe { link.GetArguments(target.as_mut_slice()) }?;

            Ok(String::from_utf16(nul_slice_wide_str(&target))?)
        })
    }

    pub fn target_working_directory(&self) -> Result<PathBuf> {
        self.with_instance(|link| {
            let mut target = vec![0; MAX_PATH as usize];

            // SAFETY: No preconditions. Path is copied to `target` and truncated afterwards.
            unsafe { link.GetWorkingDirectory(target.as_mut_slice()) }?;

            Ok(PathBuf::from(OsString::from_wide(nul_slice_wide_str(&target))))
        })
    }
}

pub fn create_directory(path: &Path, security_attributes: &SecurityAttributes) -> Result<()> {
    let path = WideString::from(path);

    let security_attributes = RawSecurityAttributes::try_from(security_attributes)?;

    // SAFETY: `path` is NUL terminated. We assume `security_attributes` is well constructed.
    unsafe { CreateDirectoryW(path.as_pcwstr(), Some(security_attributes.as_raw())) }?;

    Ok(())
}

pub struct Pipe {
    pub handle: Handle,
}

impl Pipe {
    /// Creates an anonymous pipe. Returns (rx, tx)
    pub fn new_anonymous(security_attributes: Option<&SecurityAttributes>, size: u32) -> Result<(Self, Self)> {
        let (mut rx, mut tx) = (HANDLE::default(), HANDLE::default());

        let security_attributes = security_attributes.map(RawSecurityAttributes::try_from).transpose()?;

        // SAFETY: No preconditions. `rx` and `tx` are valid out params.
        unsafe {
            CreatePipe(
                &mut rx,
                &mut tx,
                security_attributes.as_ref().map(|x| x.as_raw() as *const _),
                size,
            )
        }?;

        Ok((Self { handle: rx.into() }, Self { handle: tx.into() }))
    }

    /// Peeks the contents of the pipe in `data`, while returning the amount of bytes available on the pipe.
    pub fn peek(&self, data: Option<&mut [u8]>) -> Result<u32> {
        let mut available = 0;
        let size = data
            .as_ref()
            .map(|b| b.len().try_into())
            .transpose()?
            .unwrap_or_default();

        // SAFETY: No preconditions. The buffer is valid and its size is in bytes.
        unsafe {
            PeekNamedPipe(
                self.handle.raw(),
                data.map(|b| b.as_mut_ptr().cast()),
                size,
                None,
                Some(&mut available),
                None,
            )?;
        }

        Ok(available)
    }

    pub fn impersonate_client(&self) -> Result<NamedPipeImpersonation<'_>> {
        NamedPipeImpersonation::try_new(self)
    }

    pub fn client_primary_token(&self) -> Result<Token> {
        let _ctx = self.impersonate_client()?;

        Thread::current().token(TOKEN_ALL_ACCESS, true)?.duplicate(
            TOKEN_ACCESS_MASK(0),
            None,
            SecurityIdentification,
            TokenPrimary,
        )
    }

    pub fn client_process_id(&self) -> Result<u32> {
        let mut pid = 0u32;

        // SAFETY: Only precondition is for the handle to be created by `CreateNamedPipe`. Will fail otherwise.
        unsafe { GetNamedPipeClientProcessId(self.handle.raw(), &mut pid) }?;

        Ok(pid)
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_bytes = 0;

        // SAFETY: No preconditions. Will only fail if handle does not have GENERIC_READ.
        unsafe {
            ReadFile(self.handle.raw(), Some(buf), Some(&mut read_bytes), None)?;
        }

        Ok(read_bytes as usize)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written_bytes = 0;

        // SAFETY: No preconditions. Will only fail if handle does not have GENERIC_WRITE.
        unsafe {
            WriteFile(self.handle.raw(), Some(buf), Some(&mut written_bytes), None)?;
        }

        Ok(written_bytes as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // SAFETY: No preconditions. Will only fail if handle does not have GENERIC_WRITE.
        unsafe {
            FlushFileBuffers(self.handle.raw())?;
        }

        Ok(())
    }
}

impl HandleWrapper for Pipe {
    fn handle(&self) -> &Handle {
        &self.handle
    }
}

#[macro_export]
macro_rules! create_impersonation_context {
    ($name:ident, $underlying:ident, $impersonate:ident) => {
        pub struct $name<'a> {
            _handle: &'a $underlying,
        }

        impl<'a> $name<'a> {
            fn try_new(handle: &'a $underlying) -> Result<Self> {
                // SAFETY: No preconditions and handle is valid.
                unsafe { $impersonate(handle.handle().raw()) }?;

                Ok(Self { _handle: handle })
            }
        }

        impl Drop for $name<'_> {
            fn drop(&mut self) {
                // SAFETY: Must be called after a call to `ImpersonateNamedPipeClient` or friends.
                // Panic on fail, or rest of code will run in context of user.
                if unsafe { RevertToSelf() }.is_err() {
                    panic!("failed to revert to context of current thread");
                }
            }
        }
    };
}

create_impersonation_context!(NamedPipeImpersonation, Pipe, ImpersonateNamedPipeClient);

/// Creates a slice from a pointer. Returns an empty slice on NULL.
///
/// # Safety
///
/// - data must point to len consecutive properly initialized values of type T.
/// - The memory referenced by the returned slice must not be mutated for the duration of lifetime 'a, except inside an UnsafeCell.
pub(crate) unsafe fn slice_from_ptr<'a, T>(data: *const T, len: usize) -> &'a [T] {
    if data.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: `data` is non NULL and `len` is not 0.
        unsafe { slice::from_raw_parts(data, len) }
    }
}

pub fn nul_slice_wide_str(slice: &[u16]) -> &[u16] {
    let last_idx = slice
        .iter()
        .enumerate()
        .filter(|(_, x)| **x == 0)
        .map(|(i, _)| i)
        .next()
        .unwrap_or(slice.len());

    &slice[..last_idx]
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn size_of_u32<T>() -> u32 {
    mem::size_of::<T>() as u32
}
