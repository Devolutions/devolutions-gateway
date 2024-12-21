use tokio::sync::mpsc::Sender;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, HANDLE, HWND, LPARAM, WAIT_EVENT,
    WAIT_OBJECT_0, WPARAM,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Console::{
    AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_C_EVENT,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, GetProcessHandleFromHwnd, TerminateProcess, WaitForMultipleObjects, INFINITE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, PostMessageW, WM_CLOSE};

use now_proto_pdu::{
    NowExecCancelRspMsg, NowExecDataFlags, NowExecDataMsg, NowExecResultMsg, NowMessage, NowSeverity, NowStatus,
    NowStatusCode, NowVarBuf,
};
use win_api_wrappers::event::Event;
use win_api_wrappers::handle::Handle;
use win_api_wrappers::process::Process;
use win_api_wrappers::security::acl::SecurityAttributesInit;
use win_api_wrappers::utils::{Pipe, WideString};

use crate::dvc::channel::{winapi_signaled_mpsc_channel, WinapiSignaledReceiver, WinapiSignaledSender};
use crate::dvc::fs::TmpFileGuard;
use crate::dvc::io::{ensure_overlapped_io_result, IoRedirectionPipes};
use crate::dvc::status::{ExecAgentError, ExecResultKind};

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("Execution was aborted by user")]
    Aborted,
    #[error(transparent)]
    Windows(#[from] windows::core::Error),
    #[error("Execution failed with agent error: {}", .0.0)]
    Agent(ExecAgentError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<ExecAgentError> for ExecError {
    fn from(error: ExecAgentError) -> Self {
        ExecError::Agent(error)
    }
}

#[derive(Debug)]
pub enum ProcessIoInputEvent {
    AbortExecution(NowStatus),
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
pub enum ProcessIoNotification {
    Terminated { session_id: u32 },
}

pub struct WinApiProcessCtx {
    session_id: u32,

    dvc_tx: WinapiSignaledSender<NowMessage>,
    input_event_rx: WinapiSignaledReceiver<ProcessIoInputEvent>,

    stdout_read_pipe: Option<Pipe>,
    stderr_read_pipe: Option<Pipe>,
    stdin_write_pipe: Option<Pipe>,

    // NOTE: Order of fields is important, as process_handle must be dropped last in automatically
    // generated destructor, after all pipes were closed.
    process: Process,
}

impl WinApiProcessCtx {
    // Returns process exit code.
    pub fn start_io_loop(&mut self) -> Result<u16, ExecError> {
        let session_id = self.session_id;

        info!(session_id, "Process IO loop has started");

        // Events for overlapped IO
        let stdout_read_event = Event::new_unnamed()?;
        let stderr_read_event = Event::new_unnamed()?;

        let wait_events = vec![
            stdout_read_event.raw(),
            stderr_read_event.raw(),
            self.input_event_rx.raw_event(),
            self.process.handle.raw(),
        ];

        const WAIT_OBJECT_STDOUT_READ: WAIT_EVENT = WAIT_OBJECT_0;
        const WAIT_OBJECT_STDERR_READ: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 1);
        const WAIT_OBJECT_INPUT_MESSAGE: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 2);
        const WAIT_OBJECT_PROCESS_EXIT: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 3);

        // Initiate first overlapped read round

        let mut stdout_buffer = vec![0u8; 4 * 1024];
        let mut stderr_buffer = vec![0u8; 4 * 1024];

        let mut stdout_first_chunk = true;
        let mut stderr_first_chunk = true;

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

        info!(session_id, "Process IO is ready for async loop execution");
        loop {
            // SAFETY: No preconditions.
            let signaled_event = unsafe { WaitForMultipleObjects(&wait_events, false, INFINITE) };

            match signaled_event {
                WAIT_OBJECT_PROCESS_EXIT => {
                    info!(session_id, "Process has signaled exit");

                    // Restore Ctrl+C handler for current process, in case it was disabled by
                    // CancelExecution event.

                    // SAFETY: No preconditions.
                    unsafe { SetConsoleCtrlHandler(None, false)? };

                    let mut code: u32 = 0;
                    // SAFETY: process_handle is valid and `code` is a valid stack memory, therefore
                    // it is safe to call GetExitCodeProcess.
                    unsafe {
                        GetExitCodeProcess(self.process.handle.raw(), &mut code as *mut _)?;
                    }

                    return Ok(u16::try_from(code).unwrap_or(0xFFFF));
                }
                WAIT_OBJECT_INPUT_MESSAGE => {
                    let process_io_message = self.input_event_rx.try_recv()?;

                    trace!(session_id, ?process_io_message, "Received process IO message");

                    match process_io_message {
                        ProcessIoInputEvent::AbortExecution(status) => {
                            info!(session_id, "Aborting process execution by user request");

                            // Terminate process with requested status.
                            // SAFETY: No preconditions.
                            unsafe { TerminateProcess(self.process.handle.raw(), status.code().0.into())? };

                            return Err(ExecError::Aborted);
                        }
                        ProcessIoInputEvent::CancelExecution => {
                            info!(session_id, "Cancelling process execution by user request");

                            let mut windows_enum_ctx = EnumWindowsContext {
                                expected_process: self.process.handle.raw(),
                                windows: Vec::new(),
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
                            if !windows_enum_ctx.windows.is_empty() {
                                // Send cancel message to all windows
                                for hwnd in windows_enum_ctx.windows {
                                    // SAFETY: No preconditions.
                                    let _ = unsafe { PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)) };
                                }

                                // Acknowledge client that cancel request was sent.
                                self.dvc_tx.blocking_send(
                                    NowExecCancelRspMsg::new(
                                        session_id,
                                        NowStatus::new(NowSeverity::Info, NowStatusCode::SUCCESS),
                                    )
                                    .into(),
                                )?;

                                // Wait for process to exit
                                continue;
                            }

                            // For console applications - send CTRL+C
                            // SAFETY: No preconditions.

                            let pid = self.process.pid();

                            // SAFETY: No preconditions.
                            if pid != 0 && unsafe { AttachConsole(pid) }.is_ok() {
                                // Disable Ctrl+C handler for current process. Will be re-enabled,
                                // when process exits (see WAIT_OBJECT_PROCESS_EXIT above).
                                // SAFETY: No preconditions.
                                unsafe { SetConsoleCtrlHandler(None, true)? };

                                // Send Ctrl+C to console application
                                // SAFETY: No preconditions.
                                unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)? };

                                // Detach from console
                                // SAFETY: No preconditions.
                                unsafe { FreeConsole()? };

                                // Acknowledge client that cancel request was sent successfully.
                                self.dvc_tx.blocking_send(
                                    NowExecCancelRspMsg::new(
                                        session_id,
                                        NowStatus::new(NowSeverity::Info, NowStatusCode::SUCCESS)
                                            .with_kind(ExecResultKind::SESSION_ERROR_AGENT.0)
                                            .expect("BUG: Status kind is out of range"),
                                    )
                                    .into(),
                                )?;

                                // wait for process to exit
                                continue;
                            }

                            // Neither GUI nor console application, send cancel response with error
                            self.dvc_tx.blocking_send(
                                NowExecCancelRspMsg::new(
                                    session_id,
                                    NowStatus::new(NowSeverity::Error, NowStatusCode::FAILURE)
                                        .with_kind(ExecResultKind::SESSION_ERROR_AGENT.0)
                                        .expect("BUG: Status kind is out of range"),
                                )
                                .into(),
                            )?;
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

                    let flags = if stdout_first_chunk {
                        stdout_first_chunk = false;
                        NowExecDataFlags::FIRST | NowExecDataFlags::STDOUT
                    } else {
                        NowExecDataFlags::STDOUT
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
                                let exec_message = NowExecDataMsg::new(
                                    flags | NowExecDataFlags::LAST,
                                    session_id,
                                    NowVarBuf::new(Vec::new())
                                        .expect("BUG: empty buffer should always fit into NowVarBuf"),
                                );

                                self.dvc_tx.blocking_send(exec_message.into())?;
                            }
                            _code => return Err(err.into()),
                        }
                        continue;
                    }

                    let data_message = NowExecDataMsg::new(
                        flags,
                        session_id,
                        NowVarBuf::new(stdout_buffer[..bytes_read as usize].to_vec())
                            .expect("BUG: read buffer should always fit into NowVarBuf"),
                    );

                    self.dvc_tx.blocking_send(data_message.into())?;

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

                    let flags = if stderr_first_chunk {
                        stderr_first_chunk = false;
                        NowExecDataFlags::FIRST | NowExecDataFlags::STDERR
                    } else {
                        NowExecDataFlags::STDERR
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
                                let exec_message = NowExecDataMsg::new(
                                    flags | NowExecDataFlags::LAST,
                                    session_id,
                                    NowVarBuf::new(Vec::new())
                                        .expect("BUG: empty buffer should always fit into NowVarBuf"),
                                );

                                self.dvc_tx.blocking_send(exec_message.into())?;
                            }
                            _code => return Err(err.into()),
                        }
                        continue;
                    }

                    let data_message = NowExecDataMsg::new(
                        flags,
                        session_id,
                        NowVarBuf::new(stderr_buffer.as_slice())
                            .expect("BUG: read buffer should always fit into NowVarBuf"),
                    );

                    self.dvc_tx.blocking_send(data_message.into())?;

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
    pub fn with_command_line(mut self, command_line: String) -> Self {
        self.command_line = command_line;
        self
    }

    #[must_use]
    pub fn with_current_directory(mut self, current_directory: String) -> Self {
        self.current_directory = current_directory;
        self
    }

    /// Starts process execution and spawns IO thread to redirect stdio to/from dvc.
    pub fn run(
        self,
        session_id: u32,
        dvc_tx: WinapiSignaledSender<NowMessage>,
        io_notification_tx: Sender<ProcessIoNotification>,
    ) -> anyhow::Result<WinApiProcess> {
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

        let security_attributes = SecurityAttributesInit { inherit_handle: true }.init();

        // SAFETY: All parameters constructed above are valid and safe to use.
        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                command_line_wide.as_pwstr(),
                Some(security_attributes.as_ptr()),
                None,
                true,
                Default::default(),
                None,
                current_directory_wide.as_pcwstr(),
                &startup_info as *const _,
                &mut process_information as *mut _,
            )?;
        }

        // We don't need the thread handle, so we close it

        // SAFETY: FFI call with no outstanding precondition.
        unsafe { CloseHandle(process_information.hThread) }?;

        // Handles were duplicated by CreateProcessW, so we can close them immediately.
        // Explicitly drop handles just for clarity.
        drop(stdout_write_pipe);
        drop(stderr_write_pipe);
        drop(stdin_read_pipe);

        let process_handle = Process::from(
            // SAFETY: process_information is valid and contains valid process handle.
            unsafe { Handle::new_owned(process_information.hProcess)? },
        );

        // Create channel for `task` -> `Process IO thread` communication
        let (input_event_tx, input_event_rx) = winapi_signaled_mpsc_channel()?;

        let join_handle = std::thread::spawn(move || {
            let mut process_ctx = WinApiProcessCtx {
                session_id,
                dvc_tx: dvc_tx.clone(),
                input_event_rx,
                stdout_read_pipe: Some(stdout_read_pipe),
                stderr_read_pipe: Some(stderr_read_pipe),
                stdin_write_pipe: Some(stdin_write_pipe),
                process: process_handle,
            };

            let status = match process_ctx.start_io_loop() {
                Ok(status) => {
                    info!(session_id, "Process execution completed with exit code {}", status);
                    NowStatus::new(NowSeverity::Info, NowStatusCode(status))
                        .with_kind(ExecResultKind::EXITED.0)
                        .expect("BUG: Status kind is out of range")
                }
                Err(ExecError::Aborted) => {
                    info!(session_id, "Process execution aborted by user");

                    NowStatus::new(NowSeverity::Info, NowStatusCode::SUCCESS)
                        .with_kind(ExecResultKind::ABORTED.0)
                        .expect("BUG: Status kind is out of range")
                }
                Err(ExecError::Windows(error)) => {
                    error!(%error, session_id, "Process execution thread failed with WinAPI error");

                    let code = match u16::try_from(error.code().0) {
                        Ok(code) => NowStatusCode(code),
                        Err(_) => NowStatusCode::FAILURE,
                    };

                    NowStatus::new(NowSeverity::Error, code)
                        .with_kind(ExecResultKind::SESSION_ERROR_SYSETM.0)
                        .expect("BUG: Status kind is out of range")
                }
                Err(ExecError::Agent(error)) => {
                    error!(?error, session_id, "Process execution thread failed with agent error");

                    NowStatus::new(NowSeverity::Error, NowStatusCode(error.0))
                        .with_kind(ExecResultKind::SESSION_ERROR_AGENT.0)
                        .expect("BUG: Status kind is out of range")
                }
                Err(ExecError::Other(error)) => {
                    error!(%error, session_id, "Process execution thread failed with unknown error");

                    NowStatus::new(NowSeverity::Error, NowStatusCode(ExecAgentError::OTHER.0))
                        .with_kind(ExecResultKind::SESSION_ERROR_AGENT.0)
                        .expect("BUG: Status kind is out of range")
                }
            };

            let message = NowExecResultMsg::new(session_id, status);

            if let Err(error) = dvc_tx.blocking_send(message.into()) {
                error!(%error, session_id, "Failed to send process result message over channel");
            }

            if let Err(error) = io_notification_tx.blocking_send(ProcessIoNotification::Terminated { session_id }) {
                error!(%error, session_id, "Failed to send termination message to task; This may cause resource leak!");
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
    pub async fn abort_execution(&self, status: NowStatus) -> anyhow::Result<()> {
        self.input_event_tx
            .send(ProcessIoInputEvent::AbortExecution(status))
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
    expected_process: HANDLE,
    windows: Vec<HWND>,
}

unsafe extern "system" fn windows_enum_func(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: lparam.0 should be set to valid EnumWindowsContext memory by caller.
    let enum_ctx = unsafe { &mut *(lparam.0 as *mut EnumWindowsContext) };

    // SAFETY: No preconditions.
    let process = unsafe { GetProcessHandleFromHwnd(hwnd) };

    if process.is_invalid() {
        // Continue enumeration.
        return true.into();
    }

    if process == enum_ctx.expected_process {
        enum_ctx.windows.push(hwnd);
    }

    true.into()
}
