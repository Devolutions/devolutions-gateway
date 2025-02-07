use tokio::sync::mpsc::Sender;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, HANDLE, HWND, LPARAM, WAIT_EVENT,
    WAIT_OBJECT_0, WPARAM,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Console::{AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_C_EVENT};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, GetProcessHandleFromHwnd, TerminateProcess, WaitForMultipleObjects, CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, INFINITE, NORMAL_PRIORITY_CLASS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW
};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, PostMessageW, PostThreadMessageW, WM_CLOSE, WM_QUIT};

use now_proto_pdu::{
    NowExecDataStreamKind, NowProtoError, NowStatusError,
};
use win_api_wrappers::event::Event;
use win_api_wrappers::handle::Handle;
use win_api_wrappers::process::Process;
use win_api_wrappers::security::acl::{RawSecurityAttributes, SecurityAttributes};
use win_api_wrappers::utils::{Pipe, WideString};

use crate::dvc::channel::{winapi_signaled_mpsc_channel, WinapiSignaledReceiver, WinapiSignaledSender};
use crate::dvc::fs::TmpFileGuard;
use crate::dvc::io::{ensure_overlapped_io_result, IoRedirectionPipes};


#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error(transparent)]
    NowStatus(NowStatusError),
    #[error("Execution was aborted by user")]
    Aborted,
    #[error("Failed to encode now-proto message")]
    Encode(#[from] now_proto_pdu::ironrdp_core::EncodeError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<windows::core::Error> for ExecError {
    fn from(error: windows::core::Error) -> Self {
        ExecError::NowStatus(NowStatusError::new_winapi(error.code().0 as u32))
    }
}

impl<T: Send + Sync + 'static> From<tokio::sync::mpsc::error::SendError<T>> for ExecError {
    fn from(error: tokio::sync::mpsc::error::SendError<T>) -> Self {
        ExecError::Other(error.into())
    }
}

#[derive(Debug)]
pub enum ProcessIoInputEvent {
    AbortExecution(u32),
    CancelExecution,
    DataIn {
        data: Vec<u8>,
        /// If last is set, then stdin pipe should be closed. Any consecutive DataIn messages
        /// will be ignored.
        last: bool,
    },
    TerminateIo,
}

/// Message, sent from Process IO thread to task to finalize process execution.
#[derive(Debug)]
pub enum ServerChannelEvent {
    CloseChannel,
    SessionStarted { session_id: u32 },
    SessionDataOut { session_id: u32, stream: NowExecDataStreamKind, last: bool, data: Vec<u8> },
    SessionCancelSuccess { session_id: u32 },
    SessionCancelFailed { session_id: u32, error: NowStatusError },
    SessionExited { session_id: u32, exit_code: u32 },
    SessionFailed { session_id: u32, error: ExecError },
}

pub struct WinApiProcessCtx {
    session_id: u32,

    input_event_rx: WinapiSignaledReceiver<ProcessIoInputEvent>,
    io_notification_tx: Sender<ServerChannelEvent>,

    stdout_read_pipe: Option<Pipe>,
    stderr_read_pipe: Option<Pipe>,
    stdin_write_pipe: Option<Pipe>,

    pid: u32,

    // NOTE: Order of fields is important, as process_handle must be dropped last in automatically
    // generated destructor, after all pipes were closed.
    process: Process,
}

impl WinApiProcessCtx {
    // Returns process exit code.
    pub fn start_io_loop(&mut self) -> Result<u32, ExecError> {
        let session_id = self.session_id;

        info!(session_id, "Process IO loop has started");

        // Events for overlapped IO
        let stdout_read_event = Event::new_unnamed()?;
        let stderr_read_event = Event::new_unnamed()?;

        let wait_events = vec![
            stdout_read_event.raw(),
            stderr_read_event.raw(),
            self.input_event_rx.raw_wait_handle(),
            self.process.handle.raw(),
        ];

        const WAIT_OBJECT_STDOUT_READ: WAIT_EVENT = WAIT_OBJECT_0;
        const WAIT_OBJECT_STDERR_READ: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 1);
        const WAIT_OBJECT_INPUT_MESSAGE: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 2);
        const WAIT_OBJECT_PROCESS_EXIT: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 3);

        // Initiate first overlapped read round

        let mut stdout_buffer = vec![0u8; 4 * 1024];
        let mut stderr_buffer = vec![0u8; 4 * 1024];

        let mut overlapped_stdout = OVERLAPPED {
            hEvent: stdout_read_event.raw(),
            ..Default::default()
        };

        let mut overlapped_stderr = OVERLAPPED {
            hEvent: stderr_read_event.raw(),
            ..Default::default()
        };

        // SAFETY: pipe is valid to read from, as long as it is not closed.
        let stdout_read_result = unsafe {
            ReadFile(
                self.stdout_read_pipe
                    .as_ref()
                    .map(|pipe| pipe.handle.raw())
                    .expect("BUG: stdout pipe is not initialized"),
                Some(&mut stdout_buffer[..]),
                None,
                Some(&mut overlapped_stdout as *mut _),
            )
        };

        ensure_overlapped_io_result(stdout_read_result)?;

        // SAFETY: pipe is valid to read from, as long as it is not closed.
        let stderr_read_result = unsafe {
            ReadFile(
                self.stderr_read_pipe
                    .as_ref()
                    .map(|pipe| pipe.handle.raw())
                    .expect("BUG: stderr pipe is not initialized"),
                Some(&mut stderr_buffer[..]),
                None,
                Some(&mut overlapped_stderr as *mut _),
            )
        };

        ensure_overlapped_io_result(stderr_read_result)?;

        // Signal client side about started execution

        self.io_notification_tx.blocking_send(ServerChannelEvent::SessionStarted { session_id })?;

        info!(session_id, "Process IO is ready for async loop execution");
        loop {
            // SAFETY: No preconditions.
            let signaled_event = unsafe { WaitForMultipleObjects(&wait_events, false, INFINITE) };

            match signaled_event {
                WAIT_OBJECT_PROCESS_EXIT => {
                    info!(session_id, "Process has signaled exit");

                    let mut code: u32 = 0;
                    // SAFETY: process_handle is valid and `code` is a valid stack memory, therefore
                    // it is safe to call GetExitCodeProcess.
                    unsafe {
                        GetExitCodeProcess(self.process.handle.raw(), &mut code as *mut _)?;
                    }

                    // Return standard Windows exit code.
                    return Ok(code);
                }
                WAIT_OBJECT_INPUT_MESSAGE => {
                    let process_io_message = self.input_event_rx.try_recv()?;

                    trace!(session_id, ?process_io_message, "Received process IO message");

                    match process_io_message {
                        ProcessIoInputEvent::AbortExecution(exit_code) => {
                            info!(session_id, "Aborting process execution by user request");

                            // Terminate process with requested status.
                            // SAFETY: No preconditions.
                            unsafe { TerminateProcess(self.process.handle.raw(), exit_code)? };

                            return Err(ExecError::Aborted);
                        }
                        ProcessIoInputEvent::CancelExecution => {
                            info!(session_id, "Cancelling process execution by user request");

                            let mut windows_enum_ctx = EnumWindowsContext {
                                expected_pid: self.pid,
                                threads: Default::default(),
                            };

                            // SAFETY: EnumWindows is safe to call with valid callback function
                            // and context. Lifetime of windows_enum_ctx is guaranteed to be valid
                            // until EnumWindows returns.
                            unsafe {
                                // Enumerate all windows associated with the process
                                EnumWindows(
                                    Some(windows_enum_func),
                                    LPARAM(&mut windows_enum_ctx as *mut EnumWindowsContext as isize),
                                )
                            }?;

                            // For GUI windows - send WM_CLOSE message
                            if !windows_enum_ctx.threads.is_empty() {
                                // Send cancel message to all windows
                                for thread in windows_enum_ctx.threads {
                                    // SAFETY: No outstanding preconditions.
                                    let _ = unsafe { PostThreadMessageW(thread, WM_QUIT, WPARAM(0), LPARAM(0)) };
                                }
                            }

                            // TODO: Figure out how to send CTRL+C to console applications.

                            // Acknowledge client that cancel request has been processed
                            // successfully.
                            self.io_notification_tx.blocking_send(
                                ServerChannelEvent::SessionCancelSuccess { session_id },
                            )?;

                            // wait for process to exit
                            continue;
                        }
                        ProcessIoInputEvent::DataIn { data, last } => {
                            trace!(session_id, "Received data to write to stdin pipe");

                            let pipe_handle = match self.stdin_write_pipe.as_ref() {
                                Some(pipe) => pipe.handle.raw(),
                                None => {
                                    // Ignore data, as stdin pipe was already closed.
                                    continue;
                                }
                            };

                            let mut bytes_written: u32 = 0;

                            // Send data to stdin pipe in a blocking maner.
                            // SAFETY: pipe is valid to write to, as long as it is not closed.
                            unsafe { WriteFile(pipe_handle, Some(&data), Some(&mut bytes_written as *mut _), None) }?;

                            if last {
                                // Close stdin pipe
                                self.stdin_write_pipe = None;
                            }
                        }
                        ProcessIoInputEvent::TerminateIo => {
                            info!(session_id, "Terminating IO loop");

                            // Terminate IO loop
                            return Err(ExecError::Aborted);
                        }
                    }
                }
                WAIT_OBJECT_STDOUT_READ => {
                    trace!(session_id, "Received data from stdout pipe");

                    let pipe_handle = if let Some(pipe) = self.stdout_read_pipe.as_ref() {
                        pipe.handle.raw()
                    } else {
                        // Ignore data, as stdout pipe was already closed.
                        continue;
                    };

                    let mut bytes_read: u32 = 0;

                    // SAFETY: Destination buffer is valid during the lifetime of this function,
                    // thus it is safe to read into it. (buffer was implicitly borrowed by ReadFile)
                    let overlapped_result = unsafe {
                        GetOverlappedResult(
                            pipe_handle,
                            &overlapped_stdout as *const _,
                            &mut bytes_read as *mut _,
                            false,
                        )
                    };

                    if let Err(err) = overlapped_result {
                        // SAFETY: No preconditions.
                        match unsafe { GetLastError() } {
                            ERROR_HANDLE_EOF | ERROR_BROKEN_PIPE => {
                                // EOF on stdout pipe, close it and send EOF message to message_tx
                                self.stdout_read_pipe = None;

                                self.io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                                    session_id,
                                    stream: NowExecDataStreamKind::Stdout,
                                    last: true,
                                    data: Vec::new()
                                })?;
                            }
                            _code => return Err(err.into()),
                        }
                        continue;
                    }

                    self.io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                        session_id,
                        stream: NowExecDataStreamKind::Stdout,
                        last: false,
                        data: stdout_buffer[..bytes_read as usize].to_vec()
                    })?;

                    // Schedule next overlapped read
                    // SAFETY: pipe is valid to read from, as long as it is not closed.
                    let stdout_read_result = unsafe {
                        ReadFile(
                            pipe_handle,
                            Some(&mut stdout_buffer[..]),
                            None,
                            Some(&mut overlapped_stdout as *mut _),
                        )
                    };

                    ensure_overlapped_io_result(stdout_read_result)?;
                }
                WAIT_OBJECT_STDERR_READ => {
                    trace!(session_id, "Received data from stderr pipe");

                    let pipe_handle = if let Some(pipe) = self.stderr_read_pipe.as_ref() {
                        pipe.handle.raw()
                    } else {
                        // Ignore data, as stderr pipe was already closed.
                        continue;
                    };

                    let mut bytes_read: u32 = 0;

                    // SAFETY: Destination buffer is valid during the lifetime of this function,
                    // thus it is safe to read into it. (buffer was implicitly borrowed by ReadFile)
                    let overlapped_result = unsafe {
                        GetOverlappedResult(
                            pipe_handle,
                            &overlapped_stderr as *const _,
                            &mut bytes_read as *mut _,
                            false,
                        )
                    };

                    if let Err(err) = overlapped_result {
                        // SAFETY: No_preconditions.
                        match unsafe { GetLastError() } {
                            ERROR_HANDLE_EOF | ERROR_BROKEN_PIPE => {
                                // EOF on stderr pipe, close it and send EOF message to message_tx
                                self.stderr_read_pipe = None;
                                self.io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                                    session_id,
                                    stream: NowExecDataStreamKind::Stderr,
                                    last: true,
                                    data: Vec::new()
                                })?;

                            }
                            _code => return Err(err.into()),
                        }
                        continue;
                    }

                    self.io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                        session_id,
                        stream: NowExecDataStreamKind::Stderr,
                        last: false,
                        data: stderr_buffer[..bytes_read as usize].to_vec()
                    })?;

                    // Schedule next overlapped read
                    // SAFETY: pipe is valid to read from, as long as it is not closed.
                    let stderr_read_result = unsafe {
                        ReadFile(
                            pipe_handle,
                            Some(&mut stderr_buffer[..]),
                            None,
                            Some(&mut overlapped_stderr as *mut _),
                        )
                    };

                    ensure_overlapped_io_result(stderr_read_result)?;
                }
                _ => {
                    // Unexpected event, spurious wakeup?
                    continue;
                }
            }
        }
    }
}

/// Builder for process execution session.
pub struct WinApiProcessBuilder {
    executable: String,
    command_line: String,
    current_directory: String,
    temp_files: Vec<TmpFileGuard>,
}

impl WinApiProcessBuilder {
    pub fn new(executable: &str) -> Self {
        Self {
            executable: executable.to_string(),
            command_line: String::new(),
            current_directory: String::new(),
            temp_files: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_temp_file(mut self, temp_file: TmpFileGuard) -> Self {
        self.temp_files.push(temp_file);
        self
    }

    #[must_use]
    pub fn with_command_line(mut self, command_line: &str) -> Self {
        self.command_line = command_line.to_string();
        self
    }

    #[must_use]
    pub fn with_current_directory(mut self, current_directory: &str) -> Self {
        self.current_directory = current_directory.to_string();
        self
    }

    /// Starts process execution and spawns IO thread to redirect stdio to/from dvc.
    pub fn run(
        self,
        session_id: u32,
        io_notification_tx: Sender<ServerChannelEvent>,
    ) -> Result<WinApiProcess, ExecError> {
        let command_line = format!("\"{}\" {}", self.executable, self.command_line)
            .trim_end()
            .to_string();
        let current_directory = self.current_directory.clone();

        info!(
            session_id,
            "Starting process: `{command_line}`; cwd:`{current_directory}`"
        );

        let mut command_line_wide = WideString::from(command_line);
        let current_directory_wide = if current_directory.is_empty() {
            WideString::default()
        } else {
            WideString::from(current_directory)
        };

        let mut process_information = PROCESS_INFORMATION::default();

        let IoRedirectionPipes {
            stdout_read_pipe,
            stdout_write_pipe,
            stderr_read_pipe,
            stderr_write_pipe,
            stdin_read_pipe,
            stdin_write_pipe,
        } = IoRedirectionPipes::new()?;

        let startup_info = STARTUPINFOW {
            cb: u32::try_from(size_of::<STARTUPINFOW>()).expect("BUG: STARTUPINFOW should always fit into u32"),
            dwFlags: STARTF_USESTDHANDLES,
            hStdError: stderr_write_pipe.handle.raw(),
            hStdInput: stdin_read_pipe.handle.raw(),
            hStdOutput: stdout_write_pipe.handle.raw(),
            ..Default::default()
        };

        let security_attributes = RawSecurityAttributes::try_from(&SecurityAttributes {
            security_descriptor: None,
            inherit_handle: true,
        })?;

        // SAFETY: All parameters constructed above are valid and safe to use.
        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                command_line_wide.as_pwstr(),
                Some(security_attributes.as_raw() as *const _),
                None,
                true,
                NORMAL_PRIORITY_CLASS | CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE,
                None,
                current_directory_wide.as_pcwstr(),
                &startup_info as *const _,
                &mut process_information as *mut _,
            )?;
        }

        // SAFETY: No preconditions.
        unsafe {
            // We don't need the thread handle, so we close it
            CloseHandle(process_information.hThread)
        }?;

        // Handles were duplicated by CreateProcessW, so we can close them immediately.
        // Explicitly drop handles just for clarity.
        drop(stdout_write_pipe);
        drop(stderr_write_pipe);
        drop(stdin_read_pipe);

        let process_handle = Process::from(
            // SAFETY: process_information is valid and contains valid process handle.
            unsafe { Handle::new_owned(process_information.hProcess) }.map_err(anyhow::Error::from)?,
        );

        let pid = process_information.dwProcessId;

        // Create channel for `task` -> `Process IO thread` communication
        let (input_event_tx, input_event_rx) = winapi_signaled_mpsc_channel()?;

        let join_handle = std::thread::spawn(move || {
            let mut process_ctx = WinApiProcessCtx {
                session_id,
                input_event_rx,
                io_notification_tx: io_notification_tx.clone(),
                stdout_read_pipe: Some(stdout_read_pipe),
                stderr_read_pipe: Some(stderr_read_pipe),
                stdin_write_pipe: Some(stdin_write_pipe),
                pid,
                process: process_handle,
            };

            let notification = match process_ctx.start_io_loop() {
                Ok(exit_code) => {
                    ServerChannelEvent::SessionExited { session_id, exit_code }
                }
                Err(error) => {
                    ServerChannelEvent::SessionFailed { session_id, error }
                }
            };

            if let Err(error) = io_notification_tx.blocking_send(notification) {
                error!(%error, session_id, "Failed to send io notification to task; This may cause resource leak!");
            }
        });

        Ok(WinApiProcess {
            input_event_tx,
            join_handle,
            _temp_files: self.temp_files,
        })
    }
}

/// Represents spawned process with IO redirection.
pub struct WinApiProcess {
    input_event_tx: WinapiSignaledSender<ProcessIoInputEvent>,
    join_handle: std::thread::JoinHandle<()>,
    _temp_files: Vec<TmpFileGuard>,
}

impl WinApiProcess {
    pub async fn abort_execution(&self, exit_code: u32) -> anyhow::Result<()> {
        self.input_event_tx
            .send(ProcessIoInputEvent::AbortExecution(exit_code))
            .await
    }

    pub async fn cancel_execution(&self) -> anyhow::Result<()> {
        self.input_event_tx.send(ProcessIoInputEvent::CancelExecution).await
    }

    pub async fn send_stdin(&self, data: Vec<u8>, last: bool) -> anyhow::Result<()> {
        self.input_event_tx
            .send(ProcessIoInputEvent::DataIn { data, last })
            .await
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.input_event_tx.send(ProcessIoInputEvent::TerminateIo).await?;
        Ok(())
    }

    pub fn is_session_terminated(&self) -> bool {
        self.join_handle.is_finished()
    }
}

struct EnumWindowsContext {
    expected_pid: u32,
    threads: Vec<u32>,
}

unsafe extern "system" fn windows_enum_func(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: lparam.0 should be set to valid EnumWindowsContext memory by caller.
    let enum_ctx = unsafe { &mut *(lparam.0 as *mut EnumWindowsContext) };

    // SAFETY: No preconditions.

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid as *mut _));

    if pid == 0 || pid != enum_ctx.expected_pid {
        // Continue enumeration.
        return true.into();
    }


    // Get thread id
    let thread_id = GetWindowThreadProcessId(hwnd, None);

    if thread_id == 0 {
        // Continue enumeration.
        return true.into();
    }

    enum_ctx.threads.push(thread_id);

    true.into()
}
