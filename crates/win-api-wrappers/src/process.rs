use std::collections::HashMap;
use std::ffi::{c_void, OsString};
use std::fmt::Debug;
use std::mem::{self};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::{ptr, slice};

use anyhow::{bail, Result};

use crate::handle::{Handle, HandleWrapper};
use crate::security::acl::{RawSecurityAttributes, SecurityAttributes};
use crate::thread::Thread;
use crate::token::Token;
use crate::undoc::{NtQueryInformationProcess, ProcessBasicInformation, RTL_USER_PROCESS_PARAMETERS};
use crate::utils::{serialize_environment, Allocation, AnsiString, CommandLine, WideString};
use crate::Error;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    FreeLibrary, ERROR_INCORRECT_SIZE, E_HANDLE, HANDLE, HMODULE, MAX_PATH, WAIT_EVENT, WAIT_FAILED,
};
use windows::Win32::Security::TOKEN_ACCESS_MASK;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GetProcAddress, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CreateRemoteThread, GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, LPTHREAD_START_ROUTINE, PEB, PROCESS_ACCESS_RIGHTS,
    PROCESS_BASIC_INFORMATION, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_WIN32, STARTUPINFOEXW,
    STARTUPINFOW, STARTUPINFOW_FLAGS,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD;

use super::utils::{size_of_u32, ComContext};

#[derive(Debug)]
pub struct Process {
    pub handle: Handle,
}

impl Process {
    pub fn try_get_by_pid(pid: u32, desired_access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        // SAFETY: No preconditions. Handle is closed with RAII wrapper.
        let handle = unsafe { OpenProcess(desired_access, false, pid) }?;

        Ok(Self { handle: handle.into() })
    }

    pub fn try_with_handle(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            bail!(Error::from_hresult(E_HANDLE))
        } else {
            Ok(Self { handle: handle.into() })
        }
    }

    pub fn exe_path(&self) -> Result<PathBuf> {
        let mut path = Vec::with_capacity(MAX_PATH as usize);

        let mut status;
        let mut length;
        loop {
            length = u32::try_from(path.capacity())?;

            // SAFETY: `path` always has capacity of `length`.
            status = unsafe {
                QueryFullProcessImageNameW(
                    self.handle.raw(),
                    PROCESS_NAME_WIN32,
                    windows::core::PWSTR(path.as_mut_ptr()),
                    &mut length,
                )
            };

            // Break if successful or if path is becoming too big.
            if status.is_ok() || path.capacity() > u16::MAX as usize {
                break;
            }

            // Double the capacity each time
            path.reserve(path.capacity());
        }

        status?;

        // SAFETY: We assume `QueryFullProcessImageNameW` will set `length` to be less than or equal to its input value.
        // This guarantees the length will fit in the vec's capacity.
        unsafe { path.set_len(length as usize) };

        Ok(OsString::from_wide(&path).into())
    }

    pub fn inject_dll(&self, path: &Path) -> Result<()> {
        let path = WideString::from(path).0.expect("WideString::from failed");

        // SAFETY: Aligning a continuous `u16` vector to a continuous `u8` slice has no undefined data.
        let path_bytes = unsafe { path.align_to::<u8>().1 };

        let allocation = self.allocate(path_bytes.len())?;

        // SAFETY: Writing to a new allocation is safe, even in our process.
        // The allocation is at least as big as the data provided.
        unsafe { self.write_memory(path_bytes, allocation.address) }?;

        let load_library = Module::from_name("kernel32.dll")?.resolve_symbol("LoadLibraryW")?;

        let thread = self.create_thread(
            // SAFETY: `LoadLibraryW` fits the type. It takes one argument that is the name of the library.
            Some(unsafe {
                mem::transmute::<*const c_void, unsafe extern "system" fn(*mut c_void) -> u32>(load_library)
            }),
            Some(allocation.address),
        )?;

        thread.join(None)?;

        Ok(())
    }

    pub fn create_thread(
        &self,
        start_address: LPTHREAD_START_ROUTINE,
        parameter: Option<*const c_void>,
    ) -> Result<Thread> {
        let mut thread_id: u32 = 0;

        // SAFETY: We assume `start_address` points to a valid and executable memory address.
        // No preconditions.
        let handle = unsafe {
            CreateRemoteThread(
                self.handle.raw(),
                None,
                0,
                start_address,
                parameter,
                0,
                Some(&mut thread_id),
            )
        };

        Thread::try_with_handle(handle?)
    }

    pub fn allocate(&self, size: usize) -> Result<Allocation<'_>> {
        Allocation::try_new(self, size)
    }

    /// Writes a buffer to a process' memory.
    ///
    /// # Safety
    ///
    /// - [`address`, `address` + `data.len()`] should be accessible and writeable.
    /// - `address` should not be the currently executing code.
    pub unsafe fn write_memory(&self, data: &[u8], address: *mut c_void) -> Result<()> {
        // SAFETY: Based on the security requirements of the function, the span of `address` until `address + data.len()` should be valid and writeable.
        unsafe { WriteProcessMemory(self.handle.raw(), address, data.as_ptr().cast(), data.len(), None) }?;

        Ok(())
    }

    pub fn current_process() -> Self {
        Self {
            // SAFETY: `GetCurrentProcess()` has no preconditions and always returns a valid handle.
            handle: Handle::new(unsafe { GetCurrentProcess() }, false),
        }
    }

    pub fn token(&self, desired_access: TOKEN_ACCESS_MASK) -> Result<Token> {
        let mut handle = Default::default();

        // SAFETY: No preconditions. Returned handle will be closed with its RAII wrapper.
        unsafe { OpenProcessToken(self.handle.raw(), desired_access, &mut handle) }?;

        Token::try_with_handle(handle)
    }

    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<WAIT_EVENT> {
        // SAFETY: No preconditions.
        let status = unsafe { WaitForSingleObject(self.handle.raw(), timeout_ms.unwrap_or(INFINITE)) };

        match status {
            WAIT_FAILED => bail!(Error::last_error()),
            w => Ok(w),
        }
    }

    pub fn exit_code(&self) -> Result<u32> {
        let mut exit_code = 0u32;

        // SAFETY: No preconditions.
        unsafe { GetExitCodeProcess(self.handle.raw(), &mut exit_code) }?;

        Ok(exit_code)
    }

    pub fn query_basic_information(&self) -> Result<PROCESS_BASIC_INFORMATION> {
        let mut basic_info = PROCESS_BASIC_INFORMATION::default();

        // SAFETY: No preconditions.
        unsafe {
            NtQueryInformationProcess(
                self.handle.raw(),
                ProcessBasicInformation,
                &mut basic_info as *mut _ as *mut _,
                size_of_u32::<PROCESS_BASIC_INFORMATION>(),
                None,
            )
        }?;

        Ok(basic_info)
    }

    pub fn peb(&self) -> Result<Peb<'_>> {
        let basic_info = self.query_basic_information()?;

        Ok(Peb {
            process: self,
            address: basic_info.PebBaseAddress,
        })
    }

    /// Reads process memory at a specified address into a buffer.
    /// The buffer is not read.
    /// Returns the number of bytes read.
    ///
    /// # Safety
    ///
    /// - [`address`, `address + data.len()`] must be valid and readable.
    pub unsafe fn read_memory(&self, address: *const c_void, data: &mut [u8]) -> Result<usize> {
        let mut bytes_read = 0;

        // SAFETY: Based on the security requirements of the function, the span of `address` until `address + data.len()` should be valid and readable.
        unsafe {
            ReadProcessMemory(
                self.handle.raw(),
                address,
                data.as_mut_ptr().cast(),
                data.len(),
                Some(&mut bytes_read),
            )
        }?;

        Ok(bytes_read)
    }

    /// Reads a stucture from process memory at a specified address.
    ///
    /// # Safety
    ///
    /// - `address` must point to a valid and correctly sized instance of the structure.
    pub unsafe fn read_struct<T: Sized>(&self, address: *const c_void) -> Result<T> {
        let mut buf = vec![0; mem::size_of::<T>()];

        // SAFETY: Based on the security requirements of the function, the `address` should
        // point to a valid and correctly sized instance of `T`.
        let read = unsafe { self.read_memory(address, buf.as_mut_slice()) }?;

        if buf.len() == read {
            // SAFETY: We assume the buffer is a valid `T`.
            Ok(unsafe { buf.as_ptr().cast::<T>().read() })
        } else {
            bail!(Error::from_win32(ERROR_INCORRECT_SIZE))
        }
    }

    /// Reads a continous array of a structure from process memory at a specified address.
    ///
    /// # Safety
    ///
    /// - `address` must point to a continuous array of valid and correctly sized instances of the structure.
    pub unsafe fn read_array<T: Sized>(&self, address: *const T, count: usize) -> Result<Vec<T>> {
        let mut buf = Vec::with_capacity(count);

        // SAFETY: The address is valid and the size is valid. We will never read this data.
        let data = unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr(), buf.capacity()) };

        // SAFETY: Array is continuous in memory, so it is safe to cast to a continuous `u8` array.
        // However, we assume that the data will be alined as `Vec` wants.
        let data = unsafe { data.align_to_mut::<u8>().1 };

        // SAFETY: `read_memory` does not read `data`, so we can safely pass an unitialized buffer.
        let read_bytes = unsafe { self.read_memory(address.cast(), data) }?;

        if count * mem::size_of::<T>() == read_bytes {
            // SAFETY: Buffer can hold `count` items and was filled up to that point.
            unsafe { buf.set_len(count) };

            Ok(buf)
        } else {
            bail!(Error::from_win32(ERROR_INCORRECT_SIZE))
        }
    }
}

impl HandleWrapper for Process {
    fn handle(&self) -> &Handle {
        &self.handle
    }
}

pub fn shell_execute(
    path: &Path,
    command_line: &CommandLine,
    working_directory: &Path,
    verb: &str,
    show_cmd: SHOW_WINDOW_CMD,
) -> Result<Process> {
    let path = WideString::from(path);
    let command_line = WideString::from(command_line.to_command_line());
    let working_directory = WideString::from(working_directory);
    let verb = WideString::from(verb);

    let mut exec_info = SHELLEXECUTEINFOW {
        cbSize: size_of_u32::<SHELLEXECUTEINFOW>(),
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpFile: path.as_pcwstr(),
        lpParameters: command_line.as_pcwstr(),
        lpDirectory: working_directory.as_pcwstr(),
        lpVerb: verb.as_pcwstr(),
        nShow: show_cmd.0,
        ..Default::default()
    };

    let _ctx = ComContext::try_new(COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)?;

    // SAFETY: Must be called with COM context initialized.
    unsafe { ShellExecuteExW(&mut exec_info) }?;

    Process::try_with_handle(exec_info.hProcess)
}

pub struct Peb<'a> {
    process: &'a Process,
    /// Although it is a pointer, it might not be in our process.
    address: *const PEB,
}

impl Peb<'_> {
    pub fn raw(&self) -> Result<PEB> {
        // SAFETY: We assume `address` points to a valid `PEB` in the target process.
        unsafe { self.process.read_struct::<PEB>(self.address.cast()) }
    }

    pub fn user_process_parameters(&self) -> Result<UserProcessParameters> {
        let raw_peb = self.raw()?;

        // SAFETY: We assume `raw_peb`'s `ProcessParameters` is valid.
        let raw_params = unsafe {
            self.process
                .read_struct::<RTL_USER_PROCESS_PARAMETERS>(raw_peb.ProcessParameters.cast())?
        };

        // SAFETY: We assume `raw_params.ImagePathName` is truthful and valid.
        let image_path_name = unsafe {
            self.process.read_array(
                raw_params.ImagePathName.Buffer.as_ptr(),
                raw_params.ImagePathName.Length as usize / mem::size_of::<u16>(),
            )?
        };

        // SAFETY: We assume `raw_params.CommandLine` is truthful and valid.
        let command_line = unsafe {
            self.process.read_array(
                raw_params.CommandLine.Buffer.as_ptr(),
                raw_params.CommandLine.Length as usize / mem::size_of::<u16>(),
            )?
        };

        // SAFETY: We assume `raw_params.DesktopInfo` is truthful and valid.
        let desktop = unsafe {
            self.process.read_array(
                raw_params.DesktopInfo.Buffer.as_ptr(),
                raw_params.DesktopInfo.Length as usize / mem::size_of::<u16>(),
            )?
        };

        // SAFETY: We assume `raw_params.CurrentDirectory` is truthful and valid.
        let working_directory = unsafe {
            self.process.read_array(
                raw_params.CurrentDirectory.DosPath.Buffer.as_ptr(),
                raw_params.CurrentDirectory.DosPath.Length as usize / mem::size_of::<u16>(),
            )?
        };

        Ok(UserProcessParameters {
            image_path_name: OsString::from_wide(&image_path_name).into(),
            command_line: CommandLine::from_command_line(&String::from_utf16(&command_line)?),
            desktop: String::from_utf16(&desktop)?,
            working_directory: OsString::from_wide(&working_directory).into(),
        })
    }
}

pub struct UserProcessParameters {
    pub image_path_name: PathBuf,
    pub command_line: CommandLine,
    pub desktop: String,
    pub working_directory: PathBuf,
}

#[derive(Debug, Default)]
pub struct StartupInfo {
    pub reserved: WideString,
    pub desktop: WideString,
    pub title: WideString,
    pub x: u32,
    pub y: u32,
    pub x_size: u32,
    pub y_size: u32,
    pub x_count_chars: u32,
    pub y_count_chars: u32,
    pub fill_attribute: u32,
    pub flags: STARTUPINFOW_FLAGS,
    pub show_window: u16,
    pub reserved2: Option<Vec<u8>>,
    pub std_input: HANDLE,
    pub std_output: HANDLE,
    pub std_error: HANDLE,
    pub attribute_list: Option<Option<LPPROC_THREAD_ATTRIBUTE_LIST>>,
}

impl StartupInfo {
    pub fn as_raw(&mut self) -> Result<STARTUPINFOEXW> {
        Ok(STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: if self.attribute_list.is_some() {
                    size_of_u32::<STARTUPINFOEXW>()
                } else {
                    size_of_u32::<STARTUPINFOW>()
                },
                lpReserved: self.reserved.as_pwstr(),
                lpDesktop: self.desktop.as_pwstr(),
                lpTitle: self.title.as_pwstr(),
                dwX: self.x,
                dwY: self.y,
                dwXSize: self.x_size,
                dwYSize: self.y_size,
                dwXCountChars: self.x_count_chars,
                dwYCountChars: self.y_count_chars,
                dwFillAttribute: self.fill_attribute,
                dwFlags: self.flags,
                wShowWindow: self.show_window,
                cbReserved2: u16::try_from(self.reserved2.as_ref().map(|x| x.len()).unwrap_or(0))?,
                lpReserved2: self
                    .reserved2
                    .as_ref()
                    .map(|x| x.as_ptr().cast_mut())
                    .unwrap_or(ptr::null_mut()),
                hStdInput: self.std_input,
                hStdOutput: self.std_output,
                hStdError: self.std_error,
            },
            lpAttributeList: self.attribute_list.unwrap_or_default().unwrap_or_default(),
        })
    }
}

pub struct Module {
    handle: HMODULE,
}

impl Module {
    pub fn from_name(name: &str) -> windows::core::Result<Self> {
        let name = WideString::from(name);
        let mut handle = HMODULE::default();

        // SAFETY: No preconditions. Name is valid and null terminated.
        unsafe { GetModuleHandleExW(0, name.as_pcwstr(), &mut handle) }?;

        Ok(Self { handle })
    }

    pub fn from_ref<T>(address: &T) -> Result<Self> {
        let mut handle = HMODULE::default();

        // SAFETY: No preconditions.
        // Address can be passed as char pointer because of `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS` flag.
        unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                PCWSTR(address as *const _ as *const u16),
                &mut handle,
            )
        }?;

        Ok(Self { handle })
    }

    pub fn current() -> Result<Self> {
        static VAL: u8 = 0;
        Self::from_ref(&VAL)
    }

    pub fn file_name(&self) -> Result<PathBuf> {
        let mut buf = vec![0; MAX_PATH as usize];

        // SAFETY: No preconditions. `buf` is large enough and handle is valid.
        let size = unsafe { GetModuleFileNameW(self.handle, &mut buf) } as usize;
        if size == 0 {
            bail!(Error::last_error());
        }

        buf.truncate(size);

        Ok(OsString::from_wide(&buf).into())
    }

    pub fn resolve_symbol(&self, symbol: &str) -> windows::core::Result<*const c_void> {
        let symbol = AnsiString::from(symbol);

        // SAFETY: No preconditions. Both handle and symbol are valid.
        match unsafe { GetProcAddress(self.handle, symbol.as_pcstr()) } {
            // Function pointer is wanted.
            #[allow(clippy::fn_to_numeric_cast_any)]
            Some(func) => Ok(func as *const c_void),
            None => Err(windows::core::Error::from_win32()),
        }
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: Only constructors are GetModuleHandleExW without the GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT flag.
        // This means the reference count is incremented, making the handle valid for at least the lifetime of the object.
        // This also means we must free it.
        let _ = unsafe { FreeLibrary(self.handle) };
    }
}

#[derive(Debug)]
pub struct ProcessInformation {
    pub process: Process,
    pub thread: Thread,
    pub process_id: u32,
    pub thread_id: u32,
}

// Goal is to wrap `CreateProcessAsUserW`, which has a lot of arguments.
#[allow(clippy::too_many_arguments)]
pub fn create_process_as_user(
    token: Option<&Token>,
    application_name: Option<&Path>,
    command_line: Option<&CommandLine>,
    process_attributes: Option<&SecurityAttributes>,
    thread_attributes: Option<&SecurityAttributes>,
    inherit_handles: bool,
    creation_flags: PROCESS_CREATION_FLAGS,
    environment: Option<&HashMap<String, String>>,
    current_directory: Option<&Path>,
    startup_info: &mut StartupInfo,
) -> Result<ProcessInformation> {
    let application_name = application_name.map(WideString::from).unwrap_or_default();
    let current_directory = current_directory.map(WideString::from).unwrap_or_default();

    let environment = environment.map(serialize_environment).transpose()?;

    let mut command_line = command_line
        .map(CommandLine::to_command_line)
        .map(WideString::from)
        .unwrap_or_default();

    let mut creation_flags = creation_flags | CREATE_UNICODE_ENVIRONMENT;
    if startup_info.attribute_list.is_some() {
        creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    let mut raw_process_information = PROCESS_INFORMATION::default();

    let process_attributes = process_attributes.map(RawSecurityAttributes::try_from).transpose()?;
    let thread_attributes = thread_attributes.map(RawSecurityAttributes::try_from).transpose()?;

    // SAFETY: No preconditions. All buffers are valid.
    unsafe {
        CreateProcessAsUserW(
            token.map(|x| x.handle().raw()).unwrap_or_default(),
            application_name.as_pcwstr(),
            command_line.as_pwstr(),
            process_attributes.as_ref().map(|x| x.as_raw() as *const _),
            thread_attributes.as_ref().map(|x| x.as_raw() as *const _),
            inherit_handles,
            creation_flags,
            environment.as_ref().map(|x| x.as_ptr().cast()),
            current_directory.as_pcwstr(),
            &startup_info.as_raw()?.StartupInfo,
            &mut raw_process_information,
        )
    }?;

    Ok(ProcessInformation {
        process: Process::try_with_handle(raw_process_information.hProcess)?,
        thread: Thread::try_with_handle(raw_process_information.hThread)?,
        process_id: raw_process_information.dwProcessId,
        thread_id: raw_process_information.dwThreadId,
    })
}
