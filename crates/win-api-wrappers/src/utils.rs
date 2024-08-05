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

use crate::error::Error;
use crate::handle::{Handle, HandleWrapper};
use crate::process::Process;
use crate::security::acl::{RawSecurityAttributes, SecurityAttributes};
use crate::thread::Thread;
use crate::token::Token;
use windows::core::{Interface, PCSTR, PCWSTR, PSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, E_INVALIDARG, E_POINTER, HANDLE, HLOCAL, MAX_PATH, UNICODE_STRING,
};
use windows::Win32::Security::{
    RevertToSelf, SecurityIdentification, TokenPrimary, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS,
};
use windows::Win32::Storage::FileSystem::{CreateDirectoryW, FlushFileBuffers, ReadFile, WriteFile};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
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
            .map(|x| PCSTR::from_raw(x.as_ptr() as _))
            .unwrap_or_else(PCSTR::null)
    }

    pub fn as_pstr(&mut self) -> PSTR {
        self.0
            .as_ref()
            .map(|x| PSTR::from_raw(x.as_ptr() as _))
            .unwrap_or_else(PSTR::null)
    }
}

impl From<&str> for AnsiString {
    fn from(value: &str) -> Self {
        let mut buf = value.as_bytes().to_vec();
        buf.push(0);
        AnsiString(Some(buf))
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
            .map(|x| PCWSTR::from_raw(x.as_ptr() as _))
            .unwrap_or_else(PCWSTR::null)
    }

    pub fn as_pwstr(&mut self) -> PWSTR {
        self.0
            .as_ref()
            .map(|x| PWSTR::from_raw(x.as_ptr() as _))
            .unwrap_or_else(PWSTR::null)
    }

    pub fn as_unicode_string(&self) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: self
                .0
                .as_ref()
                .and_then(|x| x.split_last())
                .map(|x| mem::size_of_val(x.1))
                .unwrap_or(0) as _,
            MaximumLength: self.0.as_ref().map(|x| mem::size_of_val(x.as_slice())).unwrap_or(0) as _,
            Buffer: PWSTR(self.as_pcwstr().0.cast_mut()),
        }
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

        let raw_args = unsafe { CommandLineToArgvW(command_line.as_pcwstr(), &mut arg_cnt) };

        // If we get an error, no args.
        if raw_args.is_null() {
            return Self(vec![]);
        }

        let args = unsafe { slice::from_raw_parts(raw_args, arg_cnt as _) }
            .iter()
            .filter_map(|x| x.to_string_safe().ok())
            .collect::<Vec<_>>();

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

impl<'a> Drop for Allocation<'a> {
    fn drop(&mut self) {
        let _ = unsafe { VirtualFreeEx(self.process.handle.raw(), self.address, 0, MEM_RELEASE) };
    }
}

pub unsafe fn set_memory_protection(
    addr: *const (),
    size: usize,
    prot: PAGE_PROTECTION_FLAGS,
) -> Result<PAGE_PROTECTION_FLAGS> {
    let mut old_prot = Default::default();
    VirtualProtect(addr as _, size, prot, &mut old_prot)?;
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

    unsafe {
        let mut raw_blocks: *mut u16 = ptr::null_mut();

        CreateEnvironmentBlock(
            &mut raw_blocks as *mut _ as _,
            token.map(|x| x.handle().raw()).unwrap_or_default(),
            inherit,
        )?;

        let mut i = 0;
        while raw_blocks.add(i).read() != 0 {
            let mut block = Vec::new();

            loop {
                let cur_val = raw_blocks.add(i).read();
                i += 1;

                if cur_val == 0 {
                    break;
                }

                block.push(cur_val);
            }

            blocks.push(block);
        }

        DestroyEnvironmentBlock(raw_blocks as *mut _ as _)?;
    };

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
        if !last_replaced && it.peek().is_some() && var_value.is_some() {
            expanded.push_str(var_value.unwrap());
            last_replaced = true;
        } else {
            if !last_replaced {
                expanded.push('%');
            }

            expanded.push_str(segment);
            last_replaced = false;
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
    handle: HANDLE,
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
                dwSize: mem::size_of::<PROCESSENTRY32>() as _,
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

        unsafe { iter_fn(self.snapshot.handle, &mut self.entry) }.ok()?;

        Some(self.entry.th32ProcessID)
    }
}

impl Snapshot {
    pub fn new(flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, process_id: Option<u32>) -> Result<Self> {
        Ok(Self {
            handle: unsafe { CreateToolhelp32Snapshot(flags, process_id.unwrap_or(0))? },
        })
    }

    pub fn process_ids(&self) -> ProcessIdIterator {
        ProcessIdIterator::new(self)
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
        self.handle = HANDLE::default();
    }
}

pub fn com_call<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    }

    let r = f();

    unsafe {
        CoUninitialize();
    }

    r
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
        com_call(|| unsafe {
            let inst: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            let mut persist_file = MaybeUninit::<IPersistFile>::zeroed();

            inst.query(&IPersistFile::IID, persist_file.as_mut_ptr() as _).ok()?;

            let persist_file = persist_file.assume_init();

            let raw_path = WideString::from(&self.path);
            persist_file.Load(raw_path.as_pcwstr(), STGM_READ)?;

            inst.Resolve(None, SLR_NO_UI.0 as _)?;

            f(&inst)
        })
    }

    pub fn target_path(&self) -> Result<PathBuf> {
        self.with_instance(|link| {
            let mut target = vec![0; MAX_PATH as _];
            unsafe { link.GetPath(target.as_mut_slice(), ptr::null_mut(), SLGP_SHORTPATH.0 as _) }?;

            if let Some(idx) = target
                .iter()
                .enumerate()
                .filter(|(_, x)| **x == 0)
                .map(|(i, _)| i)
                .next()
            {
                target.truncate(idx);
            }

            Ok(PathBuf::from(OsString::from_wide(&target)))
        })
    }

    pub fn target_args(&self) -> Result<String> {
        self.with_instance(|link| {
            let mut target = vec![0; std::cmp::max(INFOTIPSIZE as _, MAX_PATH as _)];
            unsafe { link.GetArguments(target.as_mut_slice()) }?;

            if let Some(idx) = target
                .iter()
                .enumerate()
                .filter(|(_, x)| **x == 0)
                .map(|(i, _)| i)
                .next()
            {
                target.truncate(idx);
            }

            Ok(String::from_utf16(&target)?)
        })
    }

    pub fn target_working_directory(&self) -> Result<PathBuf> {
        self.with_instance(|link| {
            let mut target = vec![0; MAX_PATH as _];
            unsafe { link.GetWorkingDirectory(target.as_mut_slice()) }?;

            if let Some(idx) = target
                .iter()
                .enumerate()
                .filter(|(_, x)| **x == 0)
                .map(|(i, _)| i)
                .next()
            {
                target.truncate(idx);
            }

            Ok(PathBuf::from(OsString::from_wide(&target)))
        })
    }
}

pub fn create_directory(path: &Path, security_attributes: &SecurityAttributes) -> Result<()> {
    let path = WideString::from(path);

    let security_attributes = RawSecurityAttributes::try_from(security_attributes)?;

    unsafe { CreateDirectoryW(path.as_pcwstr(), Some(security_attributes.raw())) }?;

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

        unsafe {
            CreatePipe(
                &mut rx,
                &mut tx,
                security_attributes.as_ref().map(|x| x.raw() as _),
                size,
            )
        }?;
        Ok((Self { handle: rx.into() }, Self { handle: tx.into() }))
    }

    pub fn peek(&self, data: Option<&mut [u8]>) -> Result<u32> {
        let mut available = 0;
        let size = data.as_ref().map(|b| b.len() as _).unwrap_or_default();

        unsafe {
            PeekNamedPipe(
                self.handle.raw(),
                data.map(|b| b.as_mut_ptr() as _),
                size,
                None,
                Some(&mut available),
                None,
            )?;
        }

        Ok(available)
    }

    pub fn impersonate_client<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        unsafe { ImpersonateNamedPipeClient(self.handle.raw()) }?;

        let r = f();

        unsafe { RevertToSelf() }?;

        r
    }

    pub fn client_primary_token(&self) -> Result<Token> {
        self.impersonate_client(|| {
            Thread::current().token(TOKEN_ALL_ACCESS, true)?.duplicate(
                TOKEN_ACCESS_MASK(0),
                None,
                SecurityIdentification,
                TokenPrimary,
            )
        })
    }

    pub fn client_process_id(&self) -> Result<u32> {
        let mut pid = 0u32;
        unsafe {
            GetNamedPipeClientProcessId(self.handle.raw(), &mut pid)?;
        }

        Ok(pid)
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read_bytes = 0;
        unsafe {
            ReadFile(self.handle.raw(), Some(buf), Some(&mut read_bytes), None)?;
        }

        Ok(read_bytes as _)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written_bytes = 0;
        unsafe {
            WriteFile(self.handle.raw(), Some(buf), Some(&mut written_bytes), None)?;
        }

        Ok(written_bytes as _)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        unsafe {
            FlushFileBuffers(self.handle.raw())?;
        }

        Ok(())
    }
}
