use std::collections::HashMap;

use now_proto_pdu::{NowExecDataStreamKind, NowStatusError};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info, trace, warn};
use win_api_wrappers::event::Event;
use win_api_wrappers::handle::Handle;
use win_api_wrappers::process::{Process, post_message_for_pid};
use win_api_wrappers::security::attributes::SecurityAttributesInit;
use win_api_wrappers::utils::{Pipe, WideString};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, GetLastError, LPARAM, WAIT_EVENT, WAIT_OBJECT_0, WPARAM,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, INFINITE,
    NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOW,
    WaitForMultipleObjects,
};
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, WM_QUIT};
use windows::core::PCWSTR;

use crate::dvc::channel::{
    WinapiSignaledReceiver, WinapiSignaledSender, bounded_mpsc_channel, winapi_signaled_mpsc_channel,
};
use crate::dvc::encoding::{DataEncoding, InputEncoder, OutputDecoder};
use crate::dvc::env::make_environment_block;
use crate::dvc::fs::TmpFileGuard;
use crate::dvc::io::{IoRedirectionPipes, ensure_overlapped_io_result};

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
        #[allow(clippy::cast_sign_loss)] // Not relevant for Windows error codes.
        ExecError::NowStatus(NowStatusError::new_winapi(error.code().0 as u32))
    }
}

impl From<std::io::Error> for ExecError {
    fn from(error: std::io::Error) -> Self {
        ExecError::Other(error.into())
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
    TerminateIo,
}

/// Input for the process stdin.
#[derive(Debug)]
pub struct StdinChunk {
    data: Vec<u8>,
    /// Closes stdin after this chunk; later chunks are ignored.
    last: bool,
}

/// Message, sent from Process IO thread to task to finalize process execution.
#[derive(Debug)]
pub enum ServerChannelEvent {
    CloseChannel,
    SessionStarted {
        session_id: u32,
    },
    SessionDataOut {
        session_id: u32,
        stream: NowExecDataStreamKind,
        last: bool,
        data: Vec<u8>,
    },
    SessionCancelSuccess {
        session_id: u32,
    },
    SessionCancelFailed {
        session_id: u32,
        error: NowStatusError,
    },
    SessionExited {
        session_id: u32,
        exit_code: u32,
    },
    SessionFailed {
        session_id: u32,
        error: ExecError,
    },
    WindowRecordingEvent {
        message: now_proto_pdu::OwnedNowSessionWindowRecEventMsg,
    },
}

pub struct WinApiProcessCtx {
    session_id: u32,

    stdout_read_pipe: Option<Pipe>,
    stderr_read_pipe: Option<Pipe>,
    stdin_write_pipe: Option<Pipe>,

    encoding: DataEncoding,

    pid: u32,

    // NOTE: Order of fields is important, as process_handle must be dropped last in automatically
    // generated destructor, after all pipes were closed.
    process: Process,
}

impl WinApiProcessCtx {
    pub fn process_abort(&mut self, exit_code: u32) -> Result<(), ExecError> {
        info!(
            session_id = self.session_id,
            "Aborting process execution by user request"
        );

        self.process.terminate(exit_code)?;

        Ok(())
    }

    pub fn process_cancel(&mut self, io_notification_tx: Sender<ServerChannelEvent>) -> Result<(), ExecError> {
        info!(
            session_id = self.session_id,
            "Cancelling process execution by user request"
        );

        post_message_for_pid(self.pid, WM_QUIT, WPARAM(0), LPARAM(0))?;

        // TODO(DGW-301): Figure out how to correctly send CTRL+C to console applications.

        // Acknowledge client that cancel request has been processed
        // successfully.
        io_notification_tx.blocking_send(ServerChannelEvent::SessionCancelSuccess {
            session_id: self.session_id,
        })?;

        Ok(())
    }

    pub fn wait(
        mut self,
        mut input_event_rx: WinapiSignaledReceiver<ProcessIoInputEvent>,
        io_notification_tx: Sender<ServerChannelEvent>,
    ) -> Result<u32, ExecError> {
        let session_id = self.session_id;

        info!(session_id, "Waiting for process to exit");

        let wait_events = vec![input_event_rx.raw_wait_handle(), self.process.handle.raw()];

        const WAIT_OBJECT_INPUT_MESSAGE: WAIT_EVENT = WAIT_OBJECT_0;
        const WAIT_OBJECT_PROCESS_EXIT: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 1);

        io_notification_tx.blocking_send(ServerChannelEvent::SessionStarted { session_id })?;

        loop {
            // SAFETY: No preconditions.
            let signaled_event = unsafe { WaitForMultipleObjects(&wait_events, false, INFINITE) };

            match signaled_event {
                WAIT_OBJECT_PROCESS_EXIT => {
                    info!(session_id, "Process has signaled exit");

                    return Ok(self.process.exit_code()?);
                }
                WAIT_OBJECT_INPUT_MESSAGE => {
                    let process_io_message = input_event_rx.try_recv()?;

                    trace!(session_id, ?process_io_message, "Received process IO message");

                    match process_io_message {
                        ProcessIoInputEvent::AbortExecution(exit_code) => {
                            info!(session_id, "Aborting process execution by user request");

                            self.process_abort(exit_code)?;
                            return Err(ExecError::Aborted);
                        }
                        ProcessIoInputEvent::CancelExecution => {
                            self.process_cancel(io_notification_tx.clone())?;

                            // wait for process to exit
                            continue;
                        }
                        ProcessIoInputEvent::TerminateIo => {
                            info!(session_id, "Terminating IO loop");

                            // Terminate IO loop
                            return Err(ExecError::Aborted);
                        }
                    }
                }
                _ => {
                    // Unexpected event, spurious wakeup?
                    continue;
                }
            }
        }
    }

    /// Starts IO redirection loop for a launched process.
    ///
    /// Returns process exit code.
    pub fn wait_with_io_redirection(
        mut self,
        mut input_event_rx: WinapiSignaledReceiver<ProcessIoInputEvent>,
        io_notification_tx: Sender<ServerChannelEvent>,
    ) -> Result<u32, ExecError> {
        let session_id = self.session_id;

        info!(session_id, ?self.encoding, "Process IO redirection loop has started");

        // Encoding transcoders for stdout/stderr.
        let mut stdout_decoder = OutputDecoder::new(self.encoding);
        let mut stderr_decoder = OutputDecoder::new(self.encoding);

        // Events for overlapped IO
        let stdout_read_event = Event::new_unnamed()?;
        let stderr_read_event = Event::new_unnamed()?;

        let wait_events = vec![
            stdout_read_event.raw(),
            stderr_read_event.raw(),
            input_event_rx.raw_wait_handle(),
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

        io_notification_tx.blocking_send(ServerChannelEvent::SessionStarted { session_id })?;

        info!(session_id, "Process IO is ready for async loop execution");
        loop {
            // SAFETY: No preconditions.
            let signaled_event = unsafe { WaitForMultipleObjects(&wait_events, false, INFINITE) };

            match signaled_event {
                WAIT_OBJECT_PROCESS_EXIT => {
                    info!(session_id, "Process has signaled exit");

                    return Ok(self.process.exit_code()?);
                }
                WAIT_OBJECT_INPUT_MESSAGE => {
                    let process_io_message = input_event_rx.try_recv()?;

                    trace!(session_id, ?process_io_message, "Received process IO message");

                    match process_io_message {
                        ProcessIoInputEvent::AbortExecution(exit_code) => {
                            info!(session_id, "Aborting process execution by user request");

                            self.process_abort(exit_code)?;
                            return Err(ExecError::Aborted);
                        }
                        ProcessIoInputEvent::CancelExecution => {
                            self.process_cancel(io_notification_tx.clone())?;

                            // wait for process to exit
                            continue;
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

                                // Flush any remaining decoder state at EOF.
                                let flushed = stdout_decoder.flush();
                                if !flushed.is_empty() {
                                    io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                                        session_id,
                                        stream: NowExecDataStreamKind::Stdout,
                                        last: false,
                                        data: flushed,
                                    })?;
                                }

                                io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                                    session_id,
                                    stream: NowExecDataStreamKind::Stdout,
                                    last: true,
                                    data: Vec::new(),
                                })?;
                            }
                            _code => return Err(err.into()),
                        }
                        continue;
                    }

                    // Transcode stdout from process encoding to UTF-8.
                    let raw_len = bytes_read as usize;
                    let decoded_data = stdout_decoder.decode(&stdout_buffer[..raw_len]);

                    if !decoded_data.is_empty() {
                        io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                            session_id,
                            stream: NowExecDataStreamKind::Stdout,
                            last: false,
                            data: decoded_data.into_owned(),
                        })?;
                    }

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

                                // Flush any remaining decoder state at EOF.
                                let flushed = stderr_decoder.flush();
                                if !flushed.is_empty() {
                                    io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                                        session_id,
                                        stream: NowExecDataStreamKind::Stderr,
                                        last: false,
                                        data: flushed,
                                    })?;
                                }

                                io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                                    session_id,
                                    stream: NowExecDataStreamKind::Stderr,
                                    last: true,
                                    data: Vec::new(),
                                })?;
                            }
                            _code => return Err(err.into()),
                        }
                        continue;
                    }

                    // Transcode stderr from process encoding to UTF-8.
                    let decoded_data = stderr_decoder.decode(&stderr_buffer[..bytes_read as usize]);

                    if !decoded_data.is_empty() {
                        io_notification_tx.blocking_send(ServerChannelEvent::SessionDataOut {
                            session_id,
                            stream: NowExecDataStreamKind::Stderr,
                            last: false,
                            data: decoded_data.into_owned(),
                        })?;
                    }

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

/// Writes stdin chunks to the process until the last one, then closes its stdin.
///
/// Runs on a thread of its own because the write blocks until the process reads: in the IO loop, it would stop
/// stdout and stderr from being drained, and a process blocked on full output pipes never reads its input.
/// After a failed write, later input is discarded: the process no longer reads stdin, and its exit is reported by the
/// IO loop.
fn write_stdin(session_id: u32, pipe: Pipe, mut encoder: InputEncoder, mut stdin_rx: Receiver<StdinChunk>) {
    while let Some(StdinChunk { data, last }) = stdin_rx.blocking_recv() {
        let mut bytes = encoder.encode(&data).into_owned();

        if last {
            bytes.extend(encoder.flush());
        }

        if let Err(error) = write_all(&pipe, &bytes) {
            warn!(session_id, %error, "Failed to write to the process stdin; discarding further input");
            return;
        }

        if last {
            break;
        }
    }

    trace!(session_id, "Closing the process stdin");
}

fn write_all(pipe: &Pipe, mut bytes: &[u8]) -> anyhow::Result<()> {
    while !bytes.is_empty() {
        let mut bytes_written: u32 = 0;

        // SAFETY: The pipe is a synchronous handle, and the buffer outlives the call.
        unsafe { WriteFile(pipe.handle.raw(), Some(bytes), Some(&mut bytes_written), None) }?;

        let bytes_written = usize::try_from(bytes_written).expect("u32 fits into usize on Windows");

        if bytes_written == 0 {
            anyhow::bail!("stdin write made no progress");
        }

        bytes = bytes.get(bytes_written..).unwrap_or_default();
    }

    Ok(())
}

/// Builder for process execution session.
pub struct WinApiProcessBuilder {
    executable: String,
    command_line: String,
    current_directory: String,
    enable_io_redirection: bool,
    encoding: DataEncoding,
    env: HashMap<String, String>,
    temp_files: Vec<TmpFileGuard>,
}

impl WinApiProcessBuilder {
    pub fn new(executable: &str) -> Self {
        Self {
            executable: executable.to_owned(),
            command_line: String::new(),
            current_directory: String::new(),
            enable_io_redirection: false,
            encoding: DataEncoding::from_oem_codepage(),
            env: HashMap::new(),
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
        self.command_line = command_line.to_owned();
        self
    }

    #[must_use]
    pub fn with_current_directory(mut self, current_directory: &str) -> Self {
        self.current_directory = current_directory.to_owned();
        self
    }

    #[must_use]
    pub fn with_io_redirection(mut self, enable: bool) -> Self {
        self.enable_io_redirection = enable;
        self
    }

    #[must_use]
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_owned(), value.to_owned());
        self
    }

    #[must_use]
    pub fn with_encoding(mut self, encoding: DataEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    fn run_impl(
        mut self,
        session_id: u32,
        io_notification_tx: Option<Sender<ServerChannelEvent>>,
        detached: bool,
    ) -> Result<Option<WinApiProcess>, ExecError> {
        let command_line = format!("\"{}\" {}", self.executable, self.command_line)
            .trim_end()
            .to_owned();
        let current_directory = self.current_directory.clone();

        info!(
            session_id,
            "Starting process: `{command_line}`; cwd:`{current_directory}`"
        );

        let command_line = WideString::from(command_line);
        let current_directory = if current_directory.is_empty() {
            WideString::default()
        } else {
            WideString::from(current_directory)
        };

        // Move out temp files guard from builder to transfer over `WinApiProcess` instance
        // later.
        let temp_files = std::mem::take(&mut self.temp_files);

        let io_redirection = self.enable_io_redirection;
        let encoding = self.encoding;

        let process_ctx = if io_redirection {
            prepare_process_with_io_redirection(session_id, command_line, current_directory, self.env, encoding)?
        } else {
            prepare_process(session_id, command_line, current_directory, self.env, encoding)?
        };

        // For detached mode, spawn a thread that waits for process exit and keeps temp files alive
        if detached && !temp_files.is_empty() {
            std::thread::spawn(move || {
                let _temp_files = temp_files;

                // Wait for process to exit (indefinitely)
                if let Err(error) = process_ctx.process.wait(None) {
                    error!(%error, session_id, "Failed to wait for detached process");
                    return;
                }

                info!(session_id, "Detached process exited");

                // Temp files will be cleaned up when this thread exits
            });

            info!(session_id, "Detached process started successfully");
            return Ok(None);
        }

        // Create channel for `task` -> `Process IO thread` communication
        let (input_event_tx, input_event_rx) = winapi_signaled_mpsc_channel()?;

        let mut process_ctx = process_ctx;
        let stdin_tx = match process_ctx.stdin_write_pipe.take() {
            Some(pipe) => {
                let (stdin_tx, stdin_rx) = bounded_mpsc_channel()?;
                let encoder = InputEncoder::new(encoding);

                std::thread::Builder::new()
                    .name(format!("process-{session_id}-stdin"))
                    .spawn(move || write_stdin(session_id, pipe, encoder, stdin_rx))?;

                Some(stdin_tx)
            }
            None => None,
        };

        let io_notification_tx =
            io_notification_tx.expect("BUG: io_notification_tx must be Some for non-detached mode");

        let join_handle = std::thread::spawn(move || {
            let run_result = if io_redirection {
                process_ctx.wait_with_io_redirection(input_event_rx, io_notification_tx.clone())
            } else {
                process_ctx.wait(input_event_rx, io_notification_tx.clone())
            };

            let notification = match run_result {
                Ok(exit_code) => ServerChannelEvent::SessionExited { session_id, exit_code },
                Err(error) => ServerChannelEvent::SessionFailed { session_id, error },
            };

            if let Err(error) = io_notification_tx.blocking_send(notification) {
                error!(%error, session_id, "Failed to send io notification to task; This may cause resource leak!");
            }
        });

        Ok(Some(WinApiProcess {
            input_event_tx,
            stdin_tx,
            join_handle,
            _temp_files: temp_files,
        }))
    }

    /// Starts process execution and spawns IO thread to redirect stdio to/from dvc.
    pub fn run(
        self,
        session_id: u32,
        io_notification_tx: Sender<ServerChannelEvent>,
    ) -> Result<WinApiProcess, ExecError> {
        Ok(self
            .run_impl(session_id, Some(io_notification_tx), false)?
            .expect("result should be non-optional when running in non-detached mode"))
    }

    /// Starts process in detached mode (fire-and-forget).
    /// No IO redirection. Process exit is monitored in a background thread to manage temp file cleanup.
    /// Returns immediately after spawning.
    pub fn run_detached(self, session_id: u32) -> Result<(), ExecError> {
        // Result always empty and therefore ignored in detached mode.
        self.run_impl(session_id, None, true)?;
        Ok(())
    }
}

fn prepare_process(
    session_id: u32,
    mut command_line: WideString,
    current_directory: WideString,
    env: HashMap<String, String>,
    encoding: DataEncoding,
) -> Result<WinApiProcessCtx, ExecError> {
    let mut process_information = PROCESS_INFORMATION::default();

    let startup_info = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).expect("BUG: STARTUPINFOW should always fit into u32"),
        dwFlags: Default::default(),
        ..Default::default()
    };

    let environment_block = (!env.is_empty()).then(|| make_environment_block(env)).transpose()?;

    let mut creation_flags = NORMAL_PRIORITY_CLASS | CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE;

    if environment_block.is_some() {
        creation_flags |= CREATE_UNICODE_ENVIRONMENT;
    }

    // SAFETY: All parameters constructed above are valid and safe to use.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(command_line.as_pwstr()),
            None,
            None,
            true,
            creation_flags,
            environment_block.as_ref().map(|block| block.as_ptr() as *const _),
            current_directory.as_pcwstr(),
            &startup_info as *const _,
            &mut process_information as *mut _,
        )?;
    }

    // The thread handle returned by CreateProcessW is only needed if you want to manage or
    // wait on the primary thread of the new process. Since we only need to manage the process
    // itself and not its main thread, we close the thread handle immediately to avoid
    // resource leaks.

    // SAFETY: FFI call with no outstanding precondition.
    unsafe { CloseHandle(process_information.hThread) }?;

    let process_handle = Process::from(
        // SAFETY: process_information is valid and contains valid process handle.
        unsafe { Handle::new_owned(process_information.hProcess) }.map_err(anyhow::Error::from)?,
    );

    let pid = process_information.dwProcessId;

    Ok(WinApiProcessCtx {
        session_id,
        stdout_read_pipe: None,
        stderr_read_pipe: None,
        stdin_write_pipe: None,
        encoding,
        pid,
        process: process_handle,
    })
}

fn prepare_process_with_io_redirection(
    session_id: u32,
    mut command_line: WideString,
    current_directory: WideString,
    env: HashMap<String, String>,
    encoding: DataEncoding,
) -> Result<WinApiProcessCtx, ExecError> {
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
        dwFlags: STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW,
        wShowWindow: u16::try_from(SW_HIDE.0).expect("SW_HIDE fits into u16"),
        hStdError: stderr_write_pipe.handle.raw(),
        hStdInput: stdin_read_pipe.handle.raw(),
        hStdOutput: stdout_write_pipe.handle.raw(),
        ..Default::default()
    };

    let security_attributes = SecurityAttributesInit {
        inherit_handle: true,
        ..Default::default()
    }
    .init();

    let environment_block = (!env.is_empty()).then(|| make_environment_block(env)).transpose()?;

    let mut creation_flags = NORMAL_PRIORITY_CLASS | CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE;
    if environment_block.is_some() {
        creation_flags |= CREATE_UNICODE_ENVIRONMENT;
    }

    // SAFETY: All parameters constructed above are valid and safe to use.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(command_line.as_pwstr()),
            Some(security_attributes.as_ptr()),
            None,
            true,
            creation_flags,
            environment_block.as_ref().map(|block| block.as_ptr() as *const _),
            current_directory.as_pcwstr(),
            &startup_info as *const _,
            &mut process_information as *mut _,
        )?;
    }

    // SAFETY: FFI call with no outstanding precondition.
    unsafe { CloseHandle(process_information.hThread) }?;

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

    let process_ctx = WinApiProcessCtx {
        session_id,
        stdout_read_pipe: Some(stdout_read_pipe),
        stderr_read_pipe: Some(stderr_read_pipe),
        stdin_write_pipe: Some(stdin_write_pipe),
        encoding,
        pid,
        process: process_handle,
    };

    Ok(process_ctx)
}

/// Represents spawned process with IO redirection.
pub struct WinApiProcess {
    input_event_tx: WinapiSignaledSender<ProcessIoInputEvent>,
    /// `None` without IO redirection.
    stdin_tx: Option<Sender<StdinChunk>>,
    join_handle: std::thread::JoinHandle<()>,
    _temp_files: Vec<TmpFileGuard>,
}

impl Drop for WinApiProcess {
    fn drop(&mut self) {
        // Ensure that the input event channel is closed when the process is dropped.
        // This will signal the IO thread to terminate if it is still running.
        let _ = self.input_event_tx.try_send(ProcessIoInputEvent::TerminateIo);
    }
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

    /// Returns a send of `data` to the process stdin that waits while the stdin queue is full.
    ///
    /// The send owns what it needs, so the caller can keep serving process output while it waits: the process may not
    /// read its stdin until its output is drained.
    /// Input for a process that no longer reads stdin is discarded.
    pub fn send_stdin(&self, data: Vec<u8>, last: bool) -> impl Future<Output = ()> + Send + 'static {
        let stdin_tx = self.stdin_tx.clone();

        async move {
            let Some(stdin_tx) = stdin_tx else {
                return;
            };

            if stdin_tx.send(StdinChunk { data, last }).await.is_err() {
                debug!("Discarding input for a closed process stdin");
            }
        }
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.input_event_tx.send(ProcessIoInputEvent::TerminateIo).await?;
        Ok(())
    }

    pub fn is_session_terminated(&self) -> bool {
        self.join_handle.is_finished()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A process that fills its output before reading stdin must still get all of a large input.
    ///
    /// The input exceeds the stdin pipe buffer, so a stdin write that blocks the output drain deadlocks.
    // oracle: spec Windows anonymous pipes block a writer until the reader frees buffer space
    #[tokio::test(flavor = "multi_thread")]
    async fn large_stdin_after_output_completes() {
        const SESSION_ID: u32 = 1;
        const OUTPUT_LINES: u32 = 3000;
        const INPUT_LINES: u32 = 5000;

        let (io_notification_tx, mut io_notification_rx) = tokio::sync::mpsc::channel(100);
        let process = WinApiProcessBuilder::new("cmd.exe")
            .with_command_line(&format!(
                "/d /c (for /L %i in (1,1,{OUTPUT_LINES}) do @echo output-line-%i) & sort"
            ))
            .with_io_redirection(true)
            .with_encoding(DataEncoding::Raw)
            .run(SESSION_ID, io_notification_tx)
            .expect("start cmd.exe");

        let input: String = (0..INPUT_LINES).map(|i| format!("input-line-{i:05}\r\n")).collect();
        let feed = tokio::spawn(process.send_stdin(input.into_bytes(), true));

        let mut stdout = Vec::new();
        let exit_code = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                match io_notification_rx.recv().await.expect("notification channel open") {
                    ServerChannelEvent::SessionDataOut {
                        stream: NowExecDataStreamKind::Stdout,
                        data,
                        ..
                    } => stdout.extend(data),
                    ServerChannelEvent::SessionExited { exit_code, .. } => break exit_code,
                    ServerChannelEvent::SessionFailed { error, .. } => panic!("process failed: {error}"),
                    _ => {}
                }
            }
        })
        .await
        .expect("process exits instead of deadlocking on stdin");

        feed.await.expect("stdin feed completes");

        let stdout = String::from_utf8(stdout).expect("ASCII output");
        assert_eq!(exit_code, 0);
        assert!(stdout.contains(&format!("output-line-{OUTPUT_LINES}")));
        assert!(stdout.contains(&format!("input-line-{:05}", INPUT_LINES - 1)));
        assert_eq!(
            stdout.matches("input-line-").count(),
            usize::try_from(INPUT_LINES).expect("u32 fits into usize")
        );
    }
}
