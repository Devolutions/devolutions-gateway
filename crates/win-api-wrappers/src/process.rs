use std::collections::HashMap;
use std::ffi::{c_void, CString, OsString};
use std::fmt::Debug;
use std::mem::{self};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::{ptr, slice};

use anyhow::{bail, Result};

use crate::error::Error;
use crate::handle::{Handle, HandleWrapper};
use crate::security::acl::{RawSecurityAttributes, SecurityAttributes};
use crate::thread::Thread;
use crate::token::Token;
use crate::undoc::{NtQueryInformationProcess, ProcessBasicInformation, RTL_USER_PROCESS_PARAMETERS};
use crate::utils::{serialize_environment, Allocation, AnsiString, CommandLine, WideString};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    FreeLibrary, ERROR_INCORRECT_SIZE, E_HANDLE, HANDLE, HMODULE, MAX_PATH, WAIT_EVENT, WAIT_FAILED,
};
use windows::Win32::Security::TOKEN_ACCESS_MASK;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
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

#[derive(Debug)]
pub struct Process {
    pub handle: Handle,
}

impl Process {
    pub fn try_get_by_pid(pid: u32, desired_access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
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
        let mut path = Vec::with_capacity(MAX_PATH as _);

        let mut status;
        let mut length;
        loop {
            length = path.capacity() as u32;
            status = unsafe {
                QueryFullProcessImageNameW(
                    self.handle.raw(),
                    PROCESS_NAME_WIN32,
                    windows::core::PWSTR(path.as_mut_ptr()),
                    &mut length,
                )
            };

            if status.is_ok() || path.capacity() > u16::MAX as _ {
                break;
            }

            path.reserve(path.capacity());
        }

        status?;

        path.shrink_to(length as _);
        unsafe { path.set_len(path.capacity()) };

        Ok(OsString::from_wide(&path).into())
    }

    pub fn inject_dll(&self, path: &Path) -> Result<()> {
        let path = unsafe { CString::from_vec_unchecked(path.as_os_str().as_encoded_bytes().to_vec()) };
        let path_bytes = path.to_bytes_with_nul();

        let allocation = self.allocate(path_bytes.len())?;

        unsafe { self.write_memory(path_bytes, allocation.address) }?;

        let load_library = Module::from_name("kernel32.dll")?.resolve_symbol("LoadLibraryA")?;

        let thread = self.create_thread(
            Some(unsafe { mem::transmute::<_, unsafe extern "system" fn(*mut c_void) -> u32>(load_library) }),
            Some(allocation.address),
        )?;

        thread.join()?;

        Ok(())
    }

    pub fn create_thread(
        &self,
        start_address: LPTHREAD_START_ROUTINE,
        parameter: Option<*const c_void>,
    ) -> Result<Thread> {
        let mut thread_id: u32 = 0;
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

    pub fn allocate(&self, size: usize) -> Result<Allocation> {
        Allocation::try_new(self, size)
    }

    pub unsafe fn write_memory(&self, data: &[u8], address: *mut c_void) -> Result<()> {
        unsafe { WriteProcessMemory(self.handle.raw(), address, data.as_ptr() as _, data.len(), None) }?;

        Ok(())
    }

    pub fn current_process() -> Self {
        Self {
            handle: Handle::new(unsafe { GetCurrentProcess() }, false),
        }
    }

    pub fn token(&self, desired_access: TOKEN_ACCESS_MASK) -> Result<Token> {
        let mut handle = Default::default();

        unsafe { OpenProcessToken(self.handle.raw(), desired_access, &mut handle) }?;

        Token::try_with_handle(handle)
    }

    pub fn wait(&self, timeout_ms: Option<u32>) -> Result<WAIT_EVENT> {
        let status = unsafe { WaitForSingleObject(self.handle.raw(), timeout_ms.unwrap_or(INFINITE)) };

        match status {
            WAIT_FAILED => bail!(Error::last_error()),
            w => Ok(w),
        }
    }

    pub fn exit_code(&self) -> Result<u32> {
        let mut exit_code = 0u32;
        unsafe { GetExitCodeProcess(self.handle.raw(), &mut exit_code) }?;

        Ok(exit_code)
    }

    pub fn query_basic_information(&self) -> Result<PROCESS_BASIC_INFORMATION> {
        let mut basic_info = PROCESS_BASIC_INFORMATION::default();
        unsafe {
            NtQueryInformationProcess(
                self.handle.raw(),
                ProcessBasicInformation,
                &mut basic_info as *mut _ as _,
                mem::size_of_val(&basic_info) as _,
                None,
            )?;
        }

        Ok(basic_info)
    }

    pub fn peb(&self) -> Result<Peb> {
        let basic_info = self.query_basic_information()?;

        Ok(Peb {
            process: self,
            address: basic_info.PebBaseAddress as _,
        })
    }

    pub fn read_memory(&self, address: usize, data: &mut [u8]) -> Result<usize> {
        let mut bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                self.handle.raw(),
                address as _,
                data.as_mut_ptr() as _,
                data.len(),
                Some(&mut bytes_read),
            )?;
        }

        Ok(bytes_read)
    }

    pub unsafe fn read_struct<T: Sized>(&self, address: usize) -> Result<T> {
        let mut buf = vec![0; mem::size_of::<T>()];

        let read = self.read_memory(address, buf.as_mut_slice())?;

        if buf.len() == read {
            Ok(buf.as_ptr().cast::<T>().read())
        } else {
            bail!(Error::from_win32(ERROR_INCORRECT_SIZE))
        }
    }

    pub unsafe fn read_array<T: Sized>(&self, count: usize, address: usize) -> Result<Vec<T>> {
        let mut buf = Vec::with_capacity(count);

        let read_bytes = self.read_memory(
            address,
            slice::from_raw_parts_mut(buf.as_mut_ptr() as _, buf.capacity() * mem::size_of::<T>()),
        )?;

        if count * mem::size_of::<T>() == read_bytes {
            buf.set_len(count);

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
        cbSize: mem::size_of::<SHELLEXECUTEINFOW>() as _,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpFile: path.as_pcwstr(),
        lpParameters: command_line.as_pcwstr(),
        lpDirectory: working_directory.as_pcwstr(),
        lpVerb: verb.as_pcwstr(),
        nShow: show_cmd.0,
        ..Default::default()
    };

    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).ok()?;

        ShellExecuteExW(&mut exec_info)?;
    }

    Process::try_with_handle(exec_info.hProcess)
}

pub struct Peb<'a> {
    pub process: &'a Process,
    pub address: usize,
}

impl Peb<'_> {
    pub unsafe fn raw(&self) -> Result<PEB> {
        self.process.read_struct::<PEB>(self.address)
    }

    pub fn user_process_parameters(&self) -> Result<UserProcessParameters> {
        let raw_peb = unsafe { self.raw()? };

        let raw_params = unsafe {
            self.process
                .read_struct::<RTL_USER_PROCESS_PARAMETERS>(raw_peb.ProcessParameters as _)?
        };

        let image_path_name = unsafe {
            self.process.read_array::<u16>(
                raw_params.ImagePathName.Length as usize / mem::size_of::<u16>(),
                raw_params.ImagePathName.Buffer.as_ptr() as _,
            )?
        };

        let command_line = unsafe {
            self.process.read_array::<u16>(
                raw_params.CommandLine.Length as usize / mem::size_of::<u16>(),
                raw_params.CommandLine.Buffer.as_ptr() as _,
            )?
        };

        let desktop = unsafe {
            self.process.read_array::<u16>(
                raw_params.DesktopInfo.Length as usize / mem::size_of::<u16>(),
                raw_params.DesktopInfo.Buffer.as_ptr() as _,
            )?
        };

        let working_directory = unsafe {
            self.process.read_array::<u16>(
                raw_params.CurrentDirectory.DosPath.Length as usize / mem::size_of::<u16>(),
                raw_params.CurrentDirectory.DosPath.Buffer.as_ptr() as _,
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
    pub unsafe fn as_raw(&mut self) -> STARTUPINFOEXW {
        STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: if self.attribute_list.is_some() {
                    mem::size_of::<STARTUPINFOEXW>()
                } else {
                    mem::size_of::<STARTUPINFOW>()
                } as _,
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
                cbReserved2: self.reserved2.as_ref().map(|x| x.len()).unwrap_or(0) as _,
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
        }
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
        unsafe {
            GetModuleHandleExW(0, name.as_pcwstr(), &mut handle)?;
        }

        Ok(Self { handle })
    }

    pub fn from_ref<T>(address: &T) -> Result<Self> {
        let mut handle = HMODULE::default();

        // SAFETY: No preconditions.
        // Address can be passed as char pointer because of `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS` flag.
        unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                PCWSTR(address as *const _ as _),
                &mut handle,
            )?;
        }

        Ok(Self { handle })
    }

    pub fn current() -> Result<Self> {
        static VAL: u8 = 0;
        Self::from_ref(&VAL)
    }

    pub fn file_name(&self) -> Result<PathBuf> {
        let mut buf = vec![0; MAX_PATH as _];

        // SAFETY: No preconditions. `buf` is large enough and handle is valid.
        let size = unsafe { GetModuleFileNameW(self.handle, &mut buf) } as _;
        if size == 0 {
            bail!(Error::last_error());
        }

        // SAFETY: Return value is the number of characters (not bytes) copied without NUL terminator.
        // TWe assume that this is less than or equal to the size of the passed in vector.
        unsafe {
            buf.set_len(size);
        }

        Ok(OsString::from_wide(&buf).into())
    }

    pub fn resolve_symbol(&self, symbol: &str) -> windows::core::Result<*const c_void> {
        let symbol = AnsiString::from(symbol);

        // SAFETY: No preconditions. Both handle and symbol are valid.
        match unsafe { GetProcAddress(self.handle, symbol.as_pcstr()) } {
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

    unsafe {
        CreateProcessAsUserW(
            token.map(|x| x.handle().raw()).unwrap_or_default(),
            application_name.as_pcwstr(),
            command_line.as_pwstr(),
            process_attributes.as_ref().map(|x| x.raw() as _),
            thread_attributes.as_ref().map(|x| x.raw() as _),
            inherit_handles,
            creation_flags,
            environment.as_ref().map(|x| x.as_ptr() as _),
            current_directory.as_pcwstr(),
            &startup_info.as_raw().StartupInfo,
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
