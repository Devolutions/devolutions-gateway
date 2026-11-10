use std::collections::HashMap;
use std::os::windows::io::AsRawHandle as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use now_proto_pdu::{NowExecDataStreamKind, NowProtoError, NowStatusError};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info, trace, warn};
use win_api_wrappers::event::Event;
use win_api_wrappers::handle::Handle;
use win_api_wrappers::process::{Process, post_message_for_pid};
use win_api_wrappers::security::attributes::SecurityAttributesInit;
use win_api_wrappers::thread::Thread;
use win_api_wrappers::utils::{Pipe, WideString};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DISABLED_BY_POLICY, ERROR_BROKEN_PIPE, ERROR_CANCELLED, ERROR_ELEVATION_REQUIRED, ERROR_HANDLE_EOF,
    ERROR_NOT_FOUND, ERROR_PRIVILEGE_NOT_HELD, GetLastError, HANDLE, LPARAM, WAIT_EVENT, WAIT_OBJECT_0, WPARAM,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{CancelSynchronousIo, GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    INFINITE, NORMAL_PRIORITY_CLASS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESHOWWINDOW,
    STARTF_USESTDHANDLES, STARTUPINFOW, WaitForMultipleObjects,
};
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_RESTORE, WM_QUIT};
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
    ProcessNotification {
        active: Arc<AtomicBool>,
        event: Box<ServerChannelEvent>,
    },
    CloseChannel,
    SessionStarted {
        session_id: u32,
        no_io_redirection: bool,
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

#[derive(Clone)]
struct ProcessNotifications {
    sender: Sender<ServerChannelEvent>,
    active: Arc<AtomicBool>,
}

impl ProcessNotifications {
    fn new(sender: Sender<ServerChannelEvent>) -> Self {
        Self {
            sender,
            active: Arc::new(AtomicBool::new(true)),
        }
    }

    fn blocking_send(
        &self,
        event: ServerChannelEvent,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ServerChannelEvent>> {
        self.sender.blocking_send(ServerChannelEvent::ProcessNotification {
            active: Arc::clone(&self.active),
            event: Box::new(event),
        })
    }
}

impl ServerChannelEvent {
    pub fn into_active_event(self) -> Option<Self> {
        match self {
            Self::ProcessNotification { active, event } => active.load(Ordering::Acquire).then_some(*event),
            event => Some(event),
        }
    }
}

pub struct WinApiProcessCtx {
    session_id: u32,

    stdout_read_pipe: Option<Pipe>,
    stderr_read_pipe: Option<Pipe>,
    stdin_write_pipe: Option<Pipe>,

    encoding: DataEncoding,

    pid: u32,
    started_no_io_redirection: bool,
    elevated: bool,
    _temp_files: Vec<TmpFileGuard>,

    // NOTE: Order of fields is important, as process_handle must be dropped last in automatically
    // generated destructor, after all pipes were closed.
    process: Process,
}

impl Drop for WinApiProcessCtx {
    fn drop(&mut self) {
        // Elevated processes can outlive their channel; keep scripts until the interpreter exits, even after errors.
        if self.elevated
            && !self._temp_files.is_empty()
            && let Err(error) = self.process.wait(None)
        {
            error!(%error, session_id = self.session_id, "Failed to wait for elevated process cleanup");
        }
    }
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

    fn process_cancel(&mut self, io_notification_tx: ProcessNotifications) -> Result<(), ExecError> {
        info!(
            session_id = self.session_id,
            "Cancelling process execution by user request"
        );

        // TODO(DGW-301): Figure out how to correctly send CTRL+C to console applications.

        let notification = match post_message_for_pid(self.pid, WM_QUIT, WPARAM(0), LPARAM(0)) {
            Ok(()) => ServerChannelEvent::SessionCancelSuccess {
                session_id: self.session_id,
            },
            Err(error) => {
                let error = match error.downcast::<windows::core::Error>() {
                    Ok(error) => NowStatusError::new_winapi(error.code().0.cast_unsigned()),
                    Err(error) => return Err(error.into()),
                };
                ServerChannelEvent::SessionCancelFailed {
                    session_id: self.session_id,
                    error,
                }
            }
        };
        io_notification_tx.blocking_send(notification)?;

        Ok(())
    }

    fn wait(
        mut self,
        mut input_event_rx: WinapiSignaledReceiver<ProcessIoInputEvent>,
        io_notification_tx: ProcessNotifications,
    ) -> Result<u32, ExecError> {
        let session_id = self.session_id;

        info!(session_id, "Waiting for process to exit");

        let wait_events = vec![input_event_rx.raw_wait_handle(), self.process.handle.raw()];

        const WAIT_OBJECT_INPUT_MESSAGE: WAIT_EVENT = WAIT_OBJECT_0;
        const WAIT_OBJECT_PROCESS_EXIT: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 1);

        io_notification_tx.blocking_send(ServerChannelEvent::SessionStarted {
            session_id,
            no_io_redirection: self.started_no_io_redirection,
        })?;

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
    fn wait_with_io_redirection(
        mut self,
        mut input_event_rx: WinapiSignaledReceiver<ProcessIoInputEvent>,
        io_notification_tx: ProcessNotifications,
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

        io_notification_tx.blocking_send(ServerChannelEvent::SessionStarted {
            session_id,
            no_io_redirection: false,
        })?;

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

const STDIN_WRITER_STOP_TIMEOUT: Duration = Duration::from_secs(2);

struct StdinWriter {
    sender: Option<Sender<StdinChunk>>,
    thread: Option<JoinHandle<()>>,
}

impl StdinWriter {
    fn stop(&mut self) -> anyhow::Result<()> {
        drop(self.sender.take());

        let Some(thread) = self.thread.take() else {
            return Ok(());
        };

        let deadline = Instant::now() + STDIN_WRITER_STOP_TIMEOUT;
        while !thread.is_finished() && Instant::now() < deadline {
            // SAFETY: The join handle owns this valid thread handle until it is dropped.
            if let Err(error) = unsafe { CancelSynchronousIo(HANDLE(thread.as_raw_handle() as *mut _)) }
                && error.code() != ERROR_NOT_FOUND.to_hresult()
            {
                warn!(%error, "Failed to cancel synchronous process stdin write");
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        if thread.is_finished() {
            if thread.join().is_err() {
                anyhow::bail!("process stdin writer thread panicked");
            }
            return Ok(());
        }

        // UNTESTED: A writer that does not stop remains detached with its pipe and write buffer alive, because
        // freeing either while WriteFile is pending would be unsafe. When changing this timeout, check that cleanup
        // remains bounded and the pending write's memory stays owned.
        error!(
            timeout = ?STDIN_WRITER_STOP_TIMEOUT,
            "Process stdin writer did not stop after cancellation"
        );
        drop(thread);
        anyhow::bail!("process stdin writer did not stop within {STDIN_WRITER_STOP_TIMEOUT:?}")
    }
}

impl Drop for StdinWriter {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            error!(%error, "Failed to stop process stdin writer");
        }
    }
}

/// Builder for process execution session.
pub struct WinApiProcessBuilder {
    executable: String,
    command_line: String,
    current_directory: String,
    enable_io_redirection: bool,
    elevated: bool,
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
            elevated: false,
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
    pub fn with_elevated_execution(mut self) -> Self {
        self.elevated = true;
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
        io_notification_tx: Option<ProcessNotifications>,
        job: Option<&ProcessJob>,
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

        if self.elevated {
            let io_notification_tx = io_notification_tx.ok_or_else(|| {
                ExecError::Other(anyhow::anyhow!("elevated execution requires a notification sender"))
            })?;

            return self.run_elevated_impl(session_id, io_notification_tx, detached);
        }

        let temp_files = std::mem::take(&mut self.temp_files);
        let io_redirection = self.enable_io_redirection;
        let encoding = self.encoding;
        let process_ctx = if io_redirection {
            prepare_process_with_io_redirection(session_id, command_line, current_directory, self.env, encoding, job)?
        } else {
            prepare_process(session_id, command_line, current_directory, self.env, encoding, job)?
        };

        if detached {
            if !temp_files.is_empty() {
                std::thread::spawn(move || {
                    let _temp_files = temp_files;

                    // Wait for process exit to keep its temporary files alive.
                    if let Err(error) = process_ctx.process.wait(None) {
                        error!(%error, session_id, "Failed to wait for detached process");
                        return;
                    }

                    info!(session_id, "Detached process exited");

                    // Temporary files are cleaned up when this thread exits.
                });
            }

            info!(session_id, "Detached process started successfully");
            return Ok(None);
        }

        // Create channel for `task` -> `Process IO thread` communication
        let (input_event_tx, input_event_rx) = winapi_signaled_mpsc_channel()?;

        let mut process_ctx = process_ctx;
        let stdin_writer = match process_ctx.stdin_write_pipe.take() {
            Some(pipe) => {
                let (stdin_tx, stdin_rx) = bounded_mpsc_channel()?;
                let encoder = InputEncoder::new(encoding);

                let thread = std::thread::Builder::new()
                    .name(format!("process-{session_id}-stdin"))
                    .spawn(move || write_stdin(session_id, pipe, encoder, stdin_rx))?;

                Some(StdinWriter {
                    sender: Some(stdin_tx),
                    thread: Some(thread),
                })
            }
            None => None,
        };

        let io_notification_tx =
            io_notification_tx.expect("BUG: io_notification_tx must be Some for non-detached mode");
        let notifications_active = Arc::clone(&io_notification_tx.active);

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
            notifications_active,
            input_event_tx,
            stdin_writer,
            join_handle,
            _temp_files: temp_files,
        }))
    }

    fn run_elevated_impl(
        self,
        session_id: u32,
        io_notification_tx: ProcessNotifications,
        detached: bool,
    ) -> Result<Option<WinApiProcess>, ExecError> {
        let Self {
            executable,
            command_line,
            current_directory,
            enable_io_redirection: requested_io_redirection,
            temp_files,
            ..
        } = self;

        if detached {
            std::thread::Builder::new()
                .name(format!("process-{session_id}-elevation"))
                .spawn(move || {
                    let process_ctx = match prepare_elevated_process(
                        session_id,
                        &executable,
                        &command_line,
                        &current_directory,
                        requested_io_redirection,
                        temp_files,
                    ) {
                        Ok(process_ctx) => process_ctx,
                        Err(error) => {
                            let notification = ServerChannelEvent::SessionFailed { session_id, error };
                            if let Err(error) = io_notification_tx.blocking_send(notification) {
                                error!(%error, session_id, "Failed to send elevated launch error");
                            }
                            return;
                        }
                    };

                    if let Err(error) = io_notification_tx.blocking_send(ServerChannelEvent::SessionExited {
                        session_id,
                        exit_code: 0,
                    }) {
                        error!(%error, session_id, "Failed to send elevated launch result");
                    }

                    // Dropping the context waits for exit before releasing temporary scripts.
                    drop(process_ctx);
                })
                .map_err(anyhow::Error::from)?;

            return Ok(None);
        }

        let (input_event_tx, input_event_rx) = winapi_signaled_mpsc_channel()?;
        let notifications_active = Arc::clone(&io_notification_tx.active);
        let join_handle = std::thread::Builder::new()
            .name(format!("process-{session_id}-elevation"))
            .spawn(move || {
                let run_result = prepare_elevated_process(
                    session_id,
                    &executable,
                    &command_line,
                    &current_directory,
                    requested_io_redirection,
                    temp_files,
                )
                .and_then(|process_ctx| process_ctx.wait(input_event_rx, io_notification_tx.clone()));

                let notification = match run_result {
                    Ok(exit_code) => ServerChannelEvent::SessionExited { session_id, exit_code },
                    Err(error) => ServerChannelEvent::SessionFailed { session_id, error },
                };

                if let Err(error) = io_notification_tx.blocking_send(notification) {
                    error!(%error, session_id, "Failed to send elevated process result");
                }
            })?;

        Ok(Some(WinApiProcess {
            notifications_active,
            input_event_tx,
            stdin_writer: None,
            join_handle,
            _temp_files: Vec::new(),
        }))
    }

    /// Starts process execution and spawns IO thread to redirect stdio to/from dvc.
    ///
    /// Standard launches join `job` when provided, so their process trees are killed when the job is dropped.
    pub fn run(
        self,
        session_id: u32,
        io_notification_tx: Sender<ServerChannelEvent>,
        job: Option<&ProcessJob>,
    ) -> Result<WinApiProcess, ExecError> {
        Ok(self
            .run_impl(
                session_id,
                Some(ProcessNotifications::new(io_notification_tx)),
                job,
                false,
            )?
            .expect("result should be non-optional when running in non-detached mode"))
    }

    /// Starts process in detached mode (fire-and-forget).
    /// No IO redirection. Process exit is monitored in a background thread to manage temp file cleanup.
    /// Returns immediately after spawning.
    pub fn run_detached(self, session_id: u32) -> Result<(), ExecError> {
        self.run_impl(session_id, None, None, true)?;
        Ok(())
    }

    pub fn run_detached_with_notifications(
        self,
        session_id: u32,
        io_notification_tx: Sender<ServerChannelEvent>,
    ) -> Result<Arc<AtomicBool>, ExecError> {
        // Result always empty and therefore ignored in detached mode.
        let notifications = ProcessNotifications::new(io_notification_tx);
        let active = Arc::clone(&notifications.active);
        let sender = self.elevated.then_some(notifications);
        self.run_impl(session_id, sender, None, true)?;
        Ok(active)
    }
}

/// Job object whose processes are killed when it is dropped, or when the host exits or crashes.
pub struct ProcessJob(Handle);

impl ProcessJob {
    pub fn new() -> anyhow::Result<Self> {
        // SAFETY: Creating an unnamed job object with default security attributes has no preconditions.
        // The handle is not inheritable, so no child process can keep the job open.
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }?;
        // SAFETY: `job` was just created and nothing else owns it.
        let job = unsafe { Handle::new_owned(job) }?;

        let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                ..Default::default()
            },
            ..Default::default()
        };

        // SAFETY: `limits` is a JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the size passed, and outlives the call.
        unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                u32::try_from(size_of_val(&limits)).expect("JOBOBJECT_EXTENDED_LIMIT_INFORMATION size fits into u32"),
            )
        }?;

        Ok(Self(job))
    }
}

fn creation_flags(job: Option<&ProcessJob>, has_environment_block: bool) -> PROCESS_CREATION_FLAGS {
    let mut flags = NORMAL_PRIORITY_CLASS | CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE;

    if has_environment_block {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    }

    // A process that ran before joining its job could start processes outside it.
    if job.is_some() {
        flags |= CREATE_SUSPENDED;
    }

    flags
}

/// Takes ownership of the handles returned by `CreateProcessW` for a process created with [`creation_flags`], and
/// lets the process run.
///
/// With a job, the process joins it first, and is killed if it cannot.
fn start_created_process(
    process_information: &PROCESS_INFORMATION,
    job: Option<&ProcessJob>,
) -> Result<Process, ExecError> {
    // SAFETY: `CreateProcessW` returned these handles, and nothing else owns them.
    let thread = Thread::from(unsafe { Handle::new_owned(process_information.hThread) }.map_err(anyhow::Error::from)?);
    // SAFETY: Same as above.
    let process =
        Process::from(unsafe { Handle::new_owned(process_information.hProcess) }.map_err(anyhow::Error::from)?);

    if let Some(job) = job {
        // SAFETY: Both handles are valid for the duration of the call.
        let started = unsafe { AssignProcessToJobObject(job.0.raw(), process.handle.raw()) }
            .map_err(anyhow::Error::from)
            .and_then(|()| thread.resume());

        if let Err(error) = started {
            // UNTESTED: a process that cannot join its job must be killed, not left running where no channel can
            // end it. No test makes AssignProcessToJobObject or ResumeThread fail; when changing this path, check
            // that every failure after CreateProcessW still terminates the suspended process.
            if let Err(error) = process.terminate(1) {
                error!(%error, "Failed to kill a process that could not join its job");
            }

            return Err(error.context("failed to start the process in its job").into());
        }
    }

    Ok(process)
}

fn prepare_process(
    session_id: u32,
    mut command_line: WideString,
    current_directory: WideString,
    env: HashMap<String, String>,
    encoding: DataEncoding,
    job: Option<&ProcessJob>,
) -> Result<WinApiProcessCtx, ExecError> {
    let mut process_information = PROCESS_INFORMATION::default();

    let startup_info = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).expect("BUG: STARTUPINFOW should always fit into u32"),
        dwFlags: Default::default(),
        ..Default::default()
    };

    let environment_block = (!env.is_empty()).then(|| make_environment_block(env)).transpose()?;

    // SAFETY: All parameters constructed above are valid and safe to use.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(command_line.as_pwstr()),
            None,
            None,
            true,
            creation_flags(job, environment_block.is_some()),
            environment_block.as_ref().map(|block| block.as_ptr() as *const _),
            current_directory.as_pcwstr(),
            &startup_info as *const _,
            &mut process_information as *mut _,
        )?;
    }

    let process_handle = start_created_process(&process_information, job)?;

    let pid = process_information.dwProcessId;

    Ok(WinApiProcessCtx {
        session_id,
        stdout_read_pipe: None,
        stderr_read_pipe: None,
        stdin_write_pipe: None,
        encoding,
        pid,
        started_no_io_redirection: false,
        elevated: false,
        _temp_files: Vec::new(),
        process: process_handle,
    })
}

fn prepare_process_with_io_redirection(
    session_id: u32,
    mut command_line: WideString,
    current_directory: WideString,
    env: HashMap<String, String>,
    encoding: DataEncoding,
    job: Option<&ProcessJob>,
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

    // SAFETY: All parameters constructed above are valid and safe to use.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(command_line.as_pwstr()),
            Some(security_attributes.as_ptr()),
            None,
            true,
            creation_flags(job, environment_block.is_some()),
            environment_block.as_ref().map(|block| block.as_ptr() as *const _),
            current_directory.as_pcwstr(),
            &startup_info as *const _,
            &mut process_information as *mut _,
        )?;
    }

    // Handles were duplicated by CreateProcessW, so we can close them immediately.
    // Explicitly drop handles just for clarity.
    drop(stdout_write_pipe);
    drop(stderr_write_pipe);
    drop(stdin_read_pipe);

    let process_handle = start_created_process(&process_information, job)?;

    let pid = process_information.dwProcessId;

    let process_ctx = WinApiProcessCtx {
        session_id,
        stdout_read_pipe: Some(stdout_read_pipe),
        stderr_read_pipe: Some(stderr_read_pipe),
        stdin_write_pipe: Some(stdin_write_pipe),
        encoding,
        pid,
        started_no_io_redirection: false,
        elevated: false,
        _temp_files: Vec::new(),
        process: process_handle,
    };

    Ok(process_ctx)
}

fn prepare_elevated_process(
    session_id: u32,
    executable: &str,
    command_line: &str,
    current_directory: &str,
    requested_io_redirection: bool,
    temp_files: Vec<TmpFileGuard>,
) -> Result<WinApiProcessCtx, ExecError> {
    let process = win_api_wrappers::process::shell_execute(
        std::path::Path::new(executable),
        command_line,
        std::path::Path::new(current_directory),
        "runas",
        SW_RESTORE,
    )
    .map_err(map_elevated_launch_error)?;
    let mut process_ctx = WinApiProcessCtx {
        session_id,
        stdout_read_pipe: None,
        stderr_read_pipe: None,
        stdin_write_pipe: None,
        encoding: DataEncoding::Raw,
        pid: 0,
        started_no_io_redirection: requested_io_redirection,
        elevated: true,
        _temp_files: temp_files,
        process,
    };
    process_ctx.pid = process_ctx.process.process_id()?;
    Ok(process_ctx)
}

fn map_elevated_launch_error(error: anyhow::Error) -> ExecError {
    match error.downcast::<windows::core::Error>() {
        Ok(error)
            if [ERROR_CANCELLED, ERROR_ACCESS_DISABLED_BY_POLICY]
                .iter()
                .any(|code| error.code() == code.to_hresult()) =>
        {
            ExecError::NowStatus(NowStatusError::new_proto(NowProtoError::ElevationDenied))
        }
        Ok(error)
            if [ERROR_ELEVATION_REQUIRED, ERROR_PRIVILEGE_NOT_HELD]
                .iter()
                .any(|code| error.code() == code.to_hresult()) =>
        {
            ExecError::NowStatus(NowStatusError::new_proto(NowProtoError::ElevationUnavailable))
        }
        Ok(error) => ExecError::from(error),
        Err(error) => ExecError::Other(error),
    }
}

/// Represents spawned process with IO redirection.
pub struct WinApiProcess {
    notifications_active: Arc<AtomicBool>,
    input_event_tx: WinapiSignaledSender<ProcessIoInputEvent>,
    /// `None` without IO redirection.
    stdin_writer: Option<StdinWriter>,
    join_handle: JoinHandle<()>,
    _temp_files: Vec<TmpFileGuard>,
}

impl Drop for WinApiProcess {
    fn drop(&mut self) {
        // Invalidate queued events too, because an aborted session ID can be reused before consent completes.
        self.notifications_active.store(false, Ordering::Release);
        // Ensure that the input event channel is closed when the process is dropped.
        // This will signal the IO thread to terminate if it is still running.
        let _ = self.input_event_tx.try_send(ProcessIoInputEvent::TerminateIo);
    }
}

impl WinApiProcess {
    pub async fn abort_execution(&self, exit_code: u32) -> anyhow::Result<()> {
        self.input_event_tx
            .try_send(ProcessIoInputEvent::AbortExecution(exit_code))
    }

    pub async fn cancel_execution(&self) -> anyhow::Result<()> {
        self.input_event_tx.try_send(ProcessIoInputEvent::CancelExecution)
    }

    /// Returns a send of `data` to the process stdin that waits while the stdin queue is full.
    ///
    /// The send owns what it needs, so the caller can keep serving process output while it waits: the process may not
    /// read its stdin until its output is drained.
    /// Input for a process that no longer reads stdin is discarded.
    pub fn send_stdin(&self, data: Vec<u8>, last: bool) -> impl Future<Output = ()> + Send + 'static {
        let stdin_tx = self
            .stdin_writer
            .as_ref()
            .and_then(|writer| writer.sender.as_ref())
            .cloned();

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
        self.input_event_tx.try_send(ProcessIoInputEvent::TerminateIo)?;
        Ok(())
    }

    pub fn is_session_terminated(&self) -> bool {
        self.join_handle.is_finished()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use now_proto_pdu::NowExecResultMsg;

    use super::*;

    // oracle: regression #2191 pending consent must not let a full control queue block cancellation or shutdown.
    #[tokio::test]
    async fn full_control_queue_does_not_block_dispatcher() {
        let (input_event_tx, _input_event_rx) = winapi_signaled_mpsc_channel().expect("create input channel");
        while input_event_tx.try_send(ProcessIoInputEvent::CancelExecution).is_ok() {}
        let process = WinApiProcess {
            notifications_active: Arc::new(AtomicBool::new(true)),
            input_event_tx,
            stdin_writer: None,
            join_handle: std::thread::spawn(|| {}),
            _temp_files: Vec::new(),
        };

        tokio::time::timeout(Duration::from_secs(1), process.cancel_execution())
            .await
            .expect("cancel must not wait for consent")
            .expect_err("full queue cannot accept cancel");
        tokio::time::timeout(Duration::from_secs(1), process.abort_execution(7))
            .await
            .expect("abort must not wait for consent")
            .expect_err("full queue cannot accept abort");
        tokio::time::timeout(Duration::from_secs(1), process.shutdown())
            .await
            .expect("shutdown must not wait for consent")
            .expect_err("full queue cannot accept shutdown");
    }

    // oracle: regression #2191 elevated fire-and-forget launches without scripts must release their worker on launch.
    #[test]
    fn elevated_cleanup_without_scripts_does_not_wait_for_exit() {
        let job = ProcessJob::new().expect("create job");
        let mut context = running_process(&job);
        context.elevated = true;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            drop(context);
            done_tx.send(()).expect("report cleanup");
        });

        let completed = done_rx.recv_timeout(Duration::from_secs(2));
        drop(job);
        worker.join().expect("cleanup worker completes");
        completed.expect("cleanup must finish while the child is still running");
    }

    // oracle: regression #2191 aborting an execution must invalidate queued and future events before its ID is reused.
    #[test]
    fn dropped_execution_discards_queued_and_late_worker_failures() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(10);
        let notifications = ProcessNotifications::new(sender.clone());
        let (input_event_tx, _input_event_rx) = winapi_signaled_mpsc_channel().expect("create input channel");
        let process = WinApiProcess {
            notifications_active: Arc::clone(&notifications.active),
            input_event_tx,
            stdin_writer: None,
            join_handle: std::thread::spawn(|| {}),
            _temp_files: Vec::new(),
        };
        notifications
            .blocking_send(ServerChannelEvent::SessionFailed {
                session_id: 1,
                error: ExecError::NowStatus(NowStatusError::new_proto(NowProtoError::ElevationDenied)),
            })
            .expect("queue old failure");
        drop(process);
        notifications
            .blocking_send(ServerChannelEvent::SessionFailed {
                session_id: 1,
                error: ExecError::NowStatus(NowStatusError::new_proto(NowProtoError::ElevationDenied)),
            })
            .expect("queue late old failure");
        let replacement = ProcessNotifications::new(sender);
        replacement
            .blocking_send(ServerChannelEvent::SessionStarted {
                session_id: 1,
                no_io_redirection: true,
            })
            .expect("queue replacement event");

        assert!(receiver.try_recv().expect("old failure").into_active_event().is_none());
        assert!(receiver.try_recv().expect("late failure").into_active_event().is_none());
        assert!(matches!(
            receiver.try_recv().expect("replacement event").into_active_event(),
            Some(ServerChannelEvent::SessionStarted { session_id: 1, .. })
        ));
    }

    // oracle: regression #2191 channel loss during consent must not delete an elevated process's script before exit.
    #[test]
    fn closed_notification_channel_retains_elevated_script_until_exit() {
        let job = ProcessJob::new().expect("create job");
        let mut context = running_process(&job);
        let process = Process::from(context.process.handle.try_clone().expect("duplicate process handle"));
        let script = TmpFileGuard::new("cmd").expect("create script");
        let script_path = script.path().to_owned();
        context.elevated = true;
        context._temp_files.push(script);

        let (_input_tx, input_rx) = winapi_signaled_mpsc_channel().expect("create input channel");
        let (notification_tx, notification_rx) = tokio::sync::mpsc::channel(10);
        drop(notification_rx);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = context.wait(input_rx, ProcessNotifications::new(notification_tx));
            done_tx.send(result).expect("report worker result");
        });

        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(script_path.exists(), "script must survive notification failure");

        process.terminate(7).expect("stop child");
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("worker finishes after exit")
            .expect_err("the notification receiver was closed");
        worker.join().expect("worker completes");
        assert!(!script_path.exists(), "script is removed after process exit");
    }

    // oracle: spec Devolutions/now-libraries@4a24d1e50d1b952ff42525c9f34478abbc82746:protocols/docs/NOW-spec.md §Elevated Execution
    #[tokio::test(flavor = "multi_thread")]
    async fn cancellation_failure_keeps_process_tracked_until_exit() {
        let job = ProcessJob::new().expect("create job");
        let mut context = running_process(&job);
        let process = Process::from(context.process.handle.try_clone().expect("duplicate process handle"));
        // An absent window target deterministically exercises the same failure path as UIPI denial.
        context.pid = u32::MAX;
        context.elevated = true;

        let (input_tx, input_rx) = winapi_signaled_mpsc_channel().expect("create input channel");
        let (notification_tx, mut notification_rx) = tokio::sync::mpsc::channel(10);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let worker = std::thread::spawn(move || {
            let result = context.wait(input_rx, ProcessNotifications::new(notification_tx));
            done_tx.send(result).expect("report exit");
        });
        assert!(matches!(
            next_process_event(&mut notification_rx).await,
            ServerChannelEvent::SessionStarted { session_id: 1, .. }
        ));
        input_tx
            .send(ProcessIoInputEvent::CancelExecution)
            .await
            .expect("request cancel");
        assert!(matches!(
            next_process_event(&mut notification_rx).await,
            ServerChannelEvent::SessionCancelFailed { session_id: 1, .. }
        ));

        process.terminate(7).expect("stop child");
        let exit_code = tokio::time::timeout(Duration::from_secs(10), done_rx)
            .await
            .expect("worker completes")
            .expect("worker reports result")
            .expect("cancel failure does not end monitoring");
        assert_eq!(exit_code, 7);
        worker.join().expect("worker completes");
    }

    fn running_process(job: &ProcessJob) -> WinApiProcessCtx {
        prepare_process(
            1,
            WideString::from("cmd.exe /d /c ping -n 600 127.0.0.1 >nul"),
            WideString::default(),
            HashMap::new(),
            DataEncoding::Raw,
            Some(job),
        )
        .expect("start child")
    }

    async fn next_process_event(receiver: &mut Receiver<ServerChannelEvent>) -> ServerChannelEvent {
        tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .expect("event arrives")
            .expect("notification channel is open")
            .into_active_event()
            .expect("process is still active")
    }

    // oracle: spec Devolutions/now-libraries@4a24d1e50d1b952ff42525c9f34478abbc82746:protocols/docs/NOW-spec.md §Elevated Execution
    #[test]
    fn elevation_policy_failure_reports_denied() {
        assert_elevation_status(ERROR_ACCESS_DISABLED_BY_POLICY, NowProtoError::ElevationDenied);
    }

    // oracle: spec Devolutions/now-libraries@4a24d1e50d1b952ff42525c9f34478abbc82746:protocols/docs/NOW-spec.md §Elevated Execution
    #[test]
    fn missing_elevated_token_reports_unavailable() {
        assert_elevation_status(ERROR_ELEVATION_REQUIRED, NowProtoError::ElevationUnavailable);
    }

    // oracle: spec Devolutions/now-libraries@4a24d1e50d1b952ff42525c9f34478abbc82746:protocols/docs/NOW-spec.md §Elevated Execution
    #[test]
    fn missing_elevation_privilege_reports_unavailable() {
        assert_elevation_status(ERROR_PRIVILEGE_NOT_HELD, NowProtoError::ElevationUnavailable);
    }

    fn assert_elevation_status(code: windows::Win32::Foundation::WIN32_ERROR, expected: NowProtoError) {
        let ExecError::NowStatus(actual) = map_elevated_launch_error(windows::core::Error::from(code).into()) else {
            panic!("elevation failure must use a NOW status error");
        };
        assert_eq!(
            NowExecResultMsg::new_error(1, actual).expect("valid status"),
            NowExecResultMsg::new_error(1, NowStatusError::new_proto(expected)).expect("valid expected status")
        );
    }

    // oracle: spec ShellExecuteExW §Remarks
    #[test]
    fn missing_elevated_executable_preserves_platform_error() {
        let error = windows::core::Error::from(windows::Win32::Foundation::ERROR_FILE_NOT_FOUND);
        let expected = NowStatusError::new_winapi(error.code().0.cast_unsigned());
        let ExecError::NowStatus(actual) = map_elevated_launch_error(error.into()) else {
            panic!("missing executable must use a platform status");
        };
        assert_eq!(
            NowExecResultMsg::new_error(1, actual).expect("valid status"),
            NowExecResultMsg::new_error(1, expected).expect("valid expected status")
        );
    }

    // oracle: spec Devolutions/now-libraries@4a24d1e50d1b952ff42525c9f34478abbc82746:protocols/docs/NOW-spec.md §Elevated Execution
    #[test]
    fn elevation_consent_cancellation_reports_elevation_denied() {
        let error = windows::core::Error::from(ERROR_CANCELLED);

        let ExecError::NowStatus(actual) = map_elevated_launch_error(error.into()) else {
            panic!("elevation cancellation must use a NOW status error");
        };
        let expected = NowStatusError::new_proto(NowProtoError::ElevationDenied);

        assert_eq!(
            NowExecResultMsg::new_error(1, actual).expect("valid status error"),
            NowExecResultMsg::new_error(1, expected).expect("valid expected status error")
        );
    }

    // oracle: regression #2156 detached Process without temporary files must not panic after launch.
    #[test]
    fn detached_process_without_temp_files_returns_success() {
        WinApiProcessBuilder::new("cmd.exe")
            .with_command_line("/d /c exit 0")
            .run_detached(1)
            .expect("detached launch returns successfully without an IO notification channel");
    }

    /// A process that fills its output before reading stdin must still get all of a large input.
    ///
    /// The input exceeds the stdin pipe buffer, so a stdin write that blocks the output drain deadlocks.
    // oracle: spec CreatePipe §Remarks
    #[tokio::test(flavor = "multi_thread")]
    async fn large_stdin_after_output_completes() {
        const SESSION_ID: u32 = 1;
        const OUTPUT_LINES: u32 = 3000;
        const INPUT_LINES: u32 = 5000;

        let (io_notification_tx, mut io_notification_rx) = tokio::sync::mpsc::channel(100);
        let job = ProcessJob::new().expect("create job");
        let process = WinApiProcessBuilder::new("cmd.exe")
            .with_command_line(&format!(
                "/d /c (for /L %i in (1,1,{OUTPUT_LINES}) do @echo output-line-%i) & sort"
            ))
            .with_io_redirection(true)
            .with_encoding(DataEncoding::Raw)
            .run(SESSION_ID, io_notification_tx, Some(&job))
            .expect("start cmd.exe");

        let input: String = (0..INPUT_LINES).map(|i| format!("input-line-{i:05}\r\n")).collect();
        let feed = tokio::spawn(process.send_stdin(input.into_bytes(), true));

        let mut stdout = Vec::new();
        let exit_code = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                match io_notification_rx
                    .recv()
                    .await
                    .expect("notification channel open")
                    .into_active_event()
                    .expect("process is still active")
                {
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

    /// Dropping an attached execution must cancel a synchronous stdin write blocked by a child that does not read.
    // oracle: mutant dropping an execution leaves its synchronous stdin writer blocked.
    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_process_stops_a_blocked_stdin_writer() {
        const SESSION_ID: u32 = 1;

        let (io_notification_tx, _io_notification_rx) = tokio::sync::mpsc::channel(100);
        let job = ProcessJob::new().expect("create job");
        let process = WinApiProcessBuilder::new("cmd.exe")
            .with_command_line("/d /c ping -n 600 127.0.0.1 > nul")
            .with_io_redirection(true)
            .run(SESSION_ID, io_notification_tx, Some(&job))
            .expect("start cmd.exe");

        process.send_stdin(vec![b'x'; 1024 * 1024], false).await;
        std::thread::sleep(Duration::from_millis(100));

        let started_at = Instant::now();
        drop(process);
        assert!(
            started_at.elapsed() < STDIN_WRITER_STOP_TIMEOUT / 2,
            "dropping the process did not stop the blocked stdin writer promptly"
        );

        drop(job);
    }
}
