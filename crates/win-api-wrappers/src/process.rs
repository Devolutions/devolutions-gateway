use std::collections::HashMap;
use std::ffi::{OsString, c_void};
use std::fmt::Debug;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::{ptr, slice};

use anyhow::{Context, Result, bail};
use tracing::{error, warn};
use windows::Win32::Foundation::{
    E_INVALIDARG, ERROR_INCORRECT_SIZE, ERROR_NO_MORE_FILES, FreeLibrary, HANDLE, HMODULE, HWND, LPARAM, MAX_PATH,
    WAIT_EVENT, WAIT_FAILED, WPARAM,
};
use windows::Win32::Security::{TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GetModuleFileNameW, GetModuleHandleExW, GetProcAddress,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateRemoteThread, EXTENDED_STARTUPINFO_PRESENT,
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST,
    LPTHREAD_START_ROUTINE, OpenProcess, OpenProcessToken, PEB, PROCESS_ACCESS_RIGHTS, PROCESS_BASIC_INFORMATION,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_WIN32, PROCESS_TERMINATE, QueryFullProcessImageNameW,
    STARTUPINFOEXW, STARTUPINFOW, STARTUPINFOW_FLAGS, TerminateProcess, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostThreadMessageW, SHOW_WINDOW_CMD,
};
use windows::core::{BOOL, PCWSTR};

use crate::Error;
use crate::handle::{Handle, HandleWrapper};
use crate::security::attributes::SecurityAttributes;
use crate::security::privilege::{self, ScopedPrivileges};
use crate::thread::Thread;
use crate::token::Token;
use crate::undoc::{NtQueryInformationProcess, ProcessBasicInformation, RTL_USER_PROCESS_PARAMETERS};
use crate::utils::{Allocation, AnsiString, ComContext, CommandLine, WideString, u32size_of};

#[derive(Debug)]
pub struct Process {
    // Handle is closed with RAII wrapper.
    pub handle: Handle,
}

impl From<Handle> for Process {
    fn from(handle: Handle) -> Self {
        Self { handle }
    }
}

impl Process {
    pub fn get_by_pid(pid: u32, desired_access: PROCESS_ACCESS_RIGHTS) -> Result<Self> {
        // SAFETY: FFI call with no outstanding precondition.
        let handle = unsafe { OpenProcess(desired_access, false, pid) }?;

        // SAFETY: The handle is owned by us, we opened the process above.
        let handle = unsafe { Handle::new_owned(handle)? };

        Ok(Self { handle })
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
                core::mem::transmute::<*const c_void, unsafe extern "system" fn(*mut c_void) -> u32>(load_library)
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
        let handle = unsafe {
            CreateRemoteThread(
                self.handle.raw(),
                None,
                0,
                start_address,
                parameter,
                0,
                Some(&mut thread_id),
            )?
        };

        // SAFETY: The handle is owned by us, we opened the resource above.
        let handle = unsafe { Handle::new_owned(handle) }?;

        Ok(Thread::from(handle))
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
        // SAFETY: `GetCurrentProcess()` has no preconditions and always returns
        // a valid pseudo handle.
        let handle = unsafe { GetCurrentProcess() };

        // SAFETY: The handle returned by `GetCurrentProcess` is a pseudo handle.
        let handle = unsafe { Handle::new_pseudo_handle(handle) };

        Self { handle }
    }

    pub fn token(&self, desired_access: TOKEN_ACCESS_MASK) -> Result<Token> {
        let mut handle = HANDLE::default();

        // SAFETY: No preconditions. Returned handle will be closed with its RAII wrapper.
        unsafe { OpenProcessToken(self.handle.raw(), desired_access, &mut handle) }?;

        // SAFETY: We own the handle.
        let handle = unsafe { Handle::new_owned(handle)? };

        Ok(Token::from(handle))
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
                u32size_of::<PROCESS_BASIC_INFORMATION>(),
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

    /// Reads a structure from process memory at a specified address.
    ///
    /// # Safety
    ///
    /// - `address` must point to a valid and correctly sized instance of the structure.
    pub unsafe fn read_struct<T: Sized>(&self, address: *const c_void) -> Result<T> {
        let mut buf = vec![0; size_of::<T>()];

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

    /// Reads a continuous array of a structure from process memory at a specified address.
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

        // SAFETY: `read_memory` does not read `data`, so we can safely pass an uninitialized buffer.
        let read_bytes = unsafe { self.read_memory(address.cast(), data) }?;

        if count * size_of::<T>() == read_bytes {
            // SAFETY: Buffer can hold `count` items and was filled up to that point.
            unsafe { buf.set_len(count) };

            Ok(buf)
        } else {
            bail!(Error::from_win32(ERROR_INCORRECT_SIZE))
        }
    }

    /// Terminates the process and provides the exit code.
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        // SAFETY: FFI call with no outstanding preconditions.
        unsafe { TerminateProcess(self.handle.raw(), exit_code) }?;

        Ok(())
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
        cbSize: u32size_of::<SHELLEXECUTEINFOW>(),
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

    // SAFETY: We are responsibles for closing the handle.
    let handle = unsafe { Handle::new_owned(exec_info.hProcess)? };

    Ok(Process::from(handle))
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
                raw_params.ImagePathName.Length as usize / size_of::<u16>(),
            )?
        };

        // SAFETY: We assume `raw_params.CommandLine` is truthful and valid.
        let command_line = unsafe {
            self.process.read_array(
                raw_params.CommandLine.Buffer.as_ptr(),
                raw_params.CommandLine.Length as usize / size_of::<u16>(),
            )?
        };

        // SAFETY: We assume `raw_params.DesktopInfo` is truthful and valid.
        let desktop = unsafe {
            self.process.read_array(
                raw_params.DesktopInfo.Buffer.as_ptr(),
                raw_params.DesktopInfo.Length as usize / size_of::<u16>(),
            )?
        };

        // SAFETY: We assume `raw_params.CurrentDirectory` is truthful and valid.
        let working_directory = unsafe {
            self.process.read_array(
                raw_params.CurrentDirectory.DosPath.Buffer.as_ptr(),
                raw_params.CurrentDirectory.DosPath.Length as usize / size_of::<u16>(),
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
                    u32size_of::<STARTUPINFOEXW>()
                } else {
                    u32size_of::<STARTUPINFOW>()
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
        let size = unsafe { GetModuleFileNameW(Some(self.handle), &mut buf) } as usize;
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
            // This cast is intended. See also: https://github.com/rust-lang/rust-clippy/issues/12638
            #[expect(clippy::fn_to_numeric_cast_any)]
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

pub struct ProcessEntry32Iterator {
    snapshot_handle: Handle,
    process_entry: PROCESSENTRY32W,
    first: bool,
}

impl ProcessEntry32Iterator {
    pub fn new() -> Result<Self> {
        // SAFETY: `CreateToolhelp32Snapshot` call is always safe to call and returns a
        // valid handle on success.
        let raw_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;

        // SAFETY: `Handle::new` is safe to call because the `raw_handle` is valid.
        let snapshot_handle = unsafe {
            Handle::new_owned(raw_handle).expect("BUG: handle should be valid after CreateToolhelp32Snapshot call")
        };

        // SAFETY: It is safe to zero out the structure as it is a simple POD type.
        let mut process_entry: PROCESSENTRY32W = unsafe { core::mem::zeroed() };
        process_entry.dwSize = size_of::<PROCESSENTRY32W>()
            .try_into()
            .expect("BUG: PROCESSENTRY32W size always fits in u32");

        Ok(ProcessEntry32Iterator {
            snapshot_handle,
            process_entry,
            first: true,
        })
    }
}

impl Iterator for ProcessEntry32Iterator {
    type Item = ProcessEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let result = if self.first {
            // SAFETY: `windows` library ensures that `snapshot` handle is correct on creation,
            // therefore it is safe to call Process32First.
            unsafe { Process32FirstW(self.snapshot_handle.raw(), &mut self.process_entry as *mut _) }
        } else {
            // SAFETY: `Process32Next` is safe to call because the `snapshot_handle` is valid while it
            // is owned by the iterator.
            unsafe { Process32NextW(self.snapshot_handle.raw(), &mut self.process_entry as *mut _) }
        };

        match result {
            Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => None,
            Err(error) => {
                error!(%error, "Failed to iterate over processes");
                None
            }
            Ok(()) => {
                self.first = false;
                Some(ProcessEntry(self.process_entry))
            }
        }
    }
}

pub struct ProcessEntry(PROCESSENTRY32W);

impl ProcessEntry {
    pub fn process_id(&self) -> u32 {
        self.0.th32ProcessID
    }

    pub fn executable_name(&self) -> Result<String> {
        // NOTE: If for some reason szExeFile all 260 bytes filled and there is no null terminator,
        // then the executable name will be truncated.
        let exe_name_length = self
            .0
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .context("executable name null terminator not found")?;

        let name = String::from_utf16(&self.0.szExeFile[..exe_name_length])
            .context("invalid executable name UTF16 encoding")?;

        Ok(name)
    }
}

enum ProcessEnvironment {
    OsDefined(*const c_void),
    Custom(Vec<u16>),
}

impl ProcessEnvironment {
    fn as_mut_ptr(&self) -> Option<*const c_void> {
        match self {
            ProcessEnvironment::OsDefined(ptr) => Some(*ptr),
            ProcessEnvironment::Custom(vec) => Some(vec.as_ptr() as *const _),
        }
    }
}

impl Drop for ProcessEnvironment {
    fn drop(&mut self) {
        if let ProcessEnvironment::OsDefined(block) = self {
            // SAFETY: `ProcessEnvironment` is a private enum, and we ensured that `block` will only
            // ever hold pointers returned by `CreateEnvironmentBlock` in the current module.
            unsafe {
                if !block.is_null()
                    && let Err(error) = DestroyEnvironmentBlock(*block)
                {
                    warn!(%error, "Failed to destroy environment block");
                }
            };
        }
    }
}

// Goal is to wrap `CreateProcessAsUserW`, which has a lot of arguments.
#[expect(clippy::too_many_arguments)]
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

    let environment = if let Some(env) = environment {
        ProcessEnvironment::Custom(serialize_environment(env)?)
    } else {
        let mut environment: *mut c_void = ptr::null_mut();

        if let Some(token) = token {
            // SAFETY: As per `CreateEnvironmentBlock` documentation: We must specify
            // `CREATE_UNICODE_ENVIRONMENT` and call `DestroyEnvironmentBlock` after
            // `CreateProcessAsUser` call.
            // - `CREATE_UNICODE_ENVIRONMENT` is always set unconditionally.
            // - `DestroyEnvironmentBlock` is called in the `ProcessEnvironment` destructor.
            //
            // Therefore, all preconditions are met to safely call `CreateEnvironmentBlock`.
            unsafe { CreateEnvironmentBlock(&mut environment, Some(token.handle().raw()), false) }?;
        }

        ProcessEnvironment::OsDefined(environment.cast_const())
    };

    let mut command_line = command_line
        .map(CommandLine::to_command_line)
        .map(WideString::from)
        .unwrap_or_default();

    let mut creation_flags = creation_flags | CREATE_UNICODE_ENVIRONMENT;
    if startup_info.attribute_list.is_some() {
        creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    let mut raw_process_information = PROCESS_INFORMATION::default();

    // SAFETY: FFI call with no outstanding precondition.
    unsafe {
        CreateProcessAsUserW(
            token.map(|x| x.handle().raw()),
            application_name.as_pcwstr(),
            Some(command_line.as_pwstr()),
            process_attributes.map(|x| x.as_ptr()),
            thread_attributes.map(|x| x.as_ptr()),
            inherit_handles,
            creation_flags,
            environment.as_mut_ptr(),
            current_directory.as_pcwstr(),
            &startup_info.as_raw()?.StartupInfo,
            &mut raw_process_information,
        )
    }?;

    // SAFETY: The handle is owned by us, we opened the resource above.
    let process = unsafe { Handle::new_owned(raw_process_information.hProcess).map(Process::from)? };

    // SAFETY: The handle is owned by us, we opened the resource above.
    let thread = unsafe { Handle::new_owned(raw_process_information.hThread).map(Thread::from)? };

    Ok(ProcessInformation {
        process,
        thread,
        process_id: raw_process_information.dwProcessId,
        thread_id: raw_process_information.dwThreadId,
    })
}

fn serialize_environment(environment: &HashMap<String, String>) -> Result<Vec<u16>> {
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

/// Starts new process in the specified session. Note that this function requires the current
/// process to have `SYSTEM`-level permissions. Use with caution.
#[expect(clippy::too_many_arguments)]
pub fn create_process_in_session(
    session_id: u32,
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
    let mut current_process_token = Process::current_process().token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;

    // (needs investigation) Setting all of these at once fails and crashes the process.
    // In `wayk-agent` project they are set one by one.
    let mut _priv_tcb = ScopedPrivileges::enter(&mut current_process_token, &[privilege::SE_TCB_NAME])?;
    let mut _priv_primary = ScopedPrivileges::enter(_priv_tcb.token_mut(), &[privilege::SE_ASSIGNPRIMARYTOKEN_NAME])?;
    let _priv_quota = ScopedPrivileges::enter(_priv_primary.token_mut(), &[privilege::SE_INCREASE_QUOTA_NAME])?;

    let mut session_token = Token::for_session(session_id)?;

    session_token.set_session_id(session_id)?;
    session_token.set_ui_access(1)?;

    create_process_as_user(
        Some(&session_token),
        application_name,
        command_line,
        process_attributes,
        thread_attributes,
        inherit_handles,
        creation_flags,
        environment,
        current_directory,
        startup_info,
    )
}

pub fn is_process_running(process_name: &str) -> Result<bool> {
    is_process_running_impl(process_name, None)
}

pub fn is_process_running_in_session(process_name: &str, session_id: u32) -> Result<bool> {
    is_process_running_impl(process_name, Some(session_id))
}

fn is_process_running_impl(process_name: &str, session_id: Option<u32>) -> Result<bool> {
    for process in ProcessEntry32Iterator::new()? {
        if let Some(session_id) = session_id {
            let actual_session = match process_id_to_session(process.process_id()) {
                Ok(session) => session,
                Err(_) => {
                    continue;
                }
            };

            if session_id != actual_session {
                continue;
            }
        }

        if str::eq_ignore_ascii_case(process.executable_name()?.as_str(), process_name) {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn terminate_process_by_name(process_name: &str) -> Result<bool> {
    terminate_process_by_name_impl(process_name, None)
}

pub fn terminate_process_by_name_in_session(process_name: &str, session_id: u32) -> Result<bool> {
    terminate_process_by_name_impl(process_name, Some(session_id))
}

fn terminate_process_by_name_impl(process_name: &str, session_id: Option<u32>) -> Result<bool> {
    for process in ProcessEntry32Iterator::new()? {
        if let Some(session_id) = session_id {
            let actual_session = match process_id_to_session(process.process_id()) {
                Ok(session) => session,
                Err(_) => {
                    continue;
                }
            };

            if session_id != actual_session {
                continue;
            }
        }

        if str::eq_ignore_ascii_case(process.executable_name()?.as_str(), process_name) {
            // SAFETY: `OpenProcess` is always safe to call and returns a valid handle on success.
            let process = unsafe { OpenProcess(PROCESS_TERMINATE, false, process.process_id()) };

            match process {
                Ok(process) => {
                    // SAFETY: `OpenProcess` ensures that the handle is valid.
                    unsafe {
                        if let Err(error) = TerminateProcess(process, 1) {
                            warn!(process_name, session_id, %error, "TerminateProcess failed");
                            return Ok(false);
                        }
                    }

                    return Ok(true);
                }
                Err(error) => {
                    warn!(process_name, session_id, %error, "OpenProcess failed");
                    continue;
                }
            }
        }
    }

    Ok(false)
}

/// Get the Windows session ID for a given process ID.
pub fn process_id_to_session(pid: u32) -> Result<u32> {
    let mut session_id = 0;
    // SAFETY: `session_id` is always pointing to a valid memory location.
    unsafe { ProcessIdToSessionId(pid, &mut session_id as *mut _) }?;
    Ok(session_id)
}

/// Get the current Windows session ID.
pub fn get_current_session_id() -> Result<u32> {
    // SAFETY: FFI call with no outstanding preconditions.
    let process_id = unsafe { GetCurrentProcessId() };
    process_id_to_session(process_id)
}

struct EnumWindowsContext {
    expected_pid: u32,
    threads: Vec<u32>,
}

extern "system" fn windows_enum_func(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: lparam.0 set to valid EnumWindowsContext memory by caller (Windows itself).
    let enum_ctx = unsafe { &mut *(lparam.0 as *mut EnumWindowsContext) };

    let mut pid: u32 = 0;
    // SAFETY: pid points to valid memory.
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid as *mut _));
    }
    if pid == 0 || pid != enum_ctx.expected_pid {
        // Continue enumeration.
        return true.into();
    }

    // SAFETY: FFI call with no outstanding preconditions.
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, None) };
    if thread_id == 0 {
        // Continue enumeration.
        return true.into();
    }

    enum_ctx.threads.push(thread_id);

    true.into()
}

/// Posts message with given WPARAM and LPARAM values to the specific
/// appication with provided `pid`.
pub fn post_message_for_pid(pid: u32, msg: u32, wparam: WPARAM, lparam: LPARAM) -> Result<()> {
    let mut windows_enum_ctx = EnumWindowsContext {
        expected_pid: pid,
        threads: Default::default(),
    };

    // SAFETY: EnumWindows is safe to call with valid callback function
    // and context. Lifetime of windows_enum_ctx is guaranteed to be valid
    // until EnumWindows returns.
    unsafe {
        // Enumerate all windows associated with the process.
        EnumWindows(
            Some(windows_enum_func),
            LPARAM(&mut windows_enum_ctx as *mut EnumWindowsContext as isize),
        )
    }?;

    // Send message to all threads.
    if !windows_enum_ctx.threads.is_empty() {
        for thread in windows_enum_ctx.threads {
            // SAFETY: No outstanding preconditions.
            let _ = unsafe { PostThreadMessageW(thread, msg, wparam, lparam) };
        }
    }

    Ok(())
}
