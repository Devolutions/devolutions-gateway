use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use now_proto_pdu::{NowChannelHeartbeatMsg, NowMessage};
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, error, info, trace, warn};
use win_api_wrappers::event::Event;
use win_api_wrappers::utils::Pipe;
use win_api_wrappers::wts::WtsVirtualChannel;
use windows::Win32::Foundation::{
    ERROR_GEN_FAILURE, ERROR_IO_PENDING, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::RemoteDesktop::CHANNEL_PDU_HEADER;
use windows::Win32::System::Threading::{INFINITE, WaitForMultipleObjects, WaitForSingleObject};
use windows::core::Owned;

use crate::dvc::channel::WinapiSignaledReceiver;
use crate::dvc::now_message_dissector::NowMessageDissector;

const DVC_CHANNEL_NAME: &str = "Devolutions::Now::Agent";
const DVC_RETRY_DELAYS: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

#[derive(Debug, Clone, Copy)]
enum DvcInitializationStage {
    Open,
    QueryFileHandle,
    StartRead,
}

impl std::fmt::Display for DvcInitializationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => f.write_str("opening the DVC channel"),
            Self::QueryFileHandle => f.write_str("querying the DVC file handle"),
            Self::StartRead => f.write_str("starting the initial DVC read"),
        }
    }
}

#[derive(Debug)]
struct DvcInitializationError {
    stage: DvcInitializationStage,
    error: anyhow::Error,
}

impl DvcInitializationError {
    fn is_retryable(&self) -> bool {
        self.error.chain().any(|source| {
            source
                .downcast_ref::<windows::core::Error>()
                .is_some_and(|error| error.code() == ERROR_GEN_FAILURE.to_hresult())
        })
    }

    /// Formats the underlying HRESULT for logs.
    ///
    /// The OS-provided error message is localized, unlike the numeric code.
    fn code_for_logs(&self) -> String {
        self.error
            .chain()
            .find_map(|source| source.downcast_ref::<windows::core::Error>())
            .map_or_else(|| "n/a".to_owned(), |error| format!("{:#010X}", error.code().0))
    }

    fn into_anyhow(self) -> anyhow::Error {
        self.error.context(self.stage.to_string())
    }
}

/// Counters and signalling shared between the DVC IO thread and the DVC task for one channel.
///
/// Beyond diagnostics, this gates the negotiation deadline, which must not start before the
/// channel is open, and records whether negotiation completed, which decides whether a failed
/// channel is reopened.
#[derive(Debug, Default)]
pub struct DvcInitializationProgress {
    open_attempts: AtomicU32,
    channel_opened: AtomicBool,
    channel_opened_notify: Notify,
    negotiated: AtomicBool,
}

impl DvcInitializationProgress {
    fn record_open_attempt(&self) {
        self.open_attempts.fetch_add(1, Ordering::Relaxed);
    }

    fn mark_channel_opened(&self) {
        self.channel_opened.store(true, Ordering::Relaxed);
        // `notify_one` stores a permit when no waiter is registered yet, so a waiter arriving
        // after this call still completes immediately.
        self.channel_opened_notify.notify_one();
    }

    /// Resolves once the DVC channel has been opened.
    ///
    /// Never resolves if the IO thread gives up on opening it; callers are expected to also
    /// observe the read channel closing, which is how that case terminates.
    pub async fn wait_for_channel_open(&self) {
        if self.channel_opened() {
            return;
        }

        self.channel_opened_notify.notified().await;
    }

    /// Resolves once the DVC channel has been open for `timeout`.
    ///
    /// The delay deliberately does not start until the channel is open; starting it earlier
    /// races the open retries and can expire before the client can negotiate. Like
    /// [`Self::wait_for_channel_open`], this never resolves if the channel is never opened.
    pub async fn negotiation_deadline(&self, timeout: Duration) {
        self.wait_for_channel_open().await;
        tokio::time::sleep(timeout).await;
    }

    /// Number of `WTSVirtualChannelOpenEx` attempts made so far.
    pub fn open_attempts(&self) -> u32 {
        self.open_attempts.load(Ordering::Relaxed)
    }

    /// Whether the DVC channel was successfully opened at any point.
    pub fn channel_opened(&self) -> bool {
        self.channel_opened.load(Ordering::Relaxed)
    }

    pub fn mark_negotiated(&self) {
        self.negotiated.store(true, Ordering::Relaxed);
    }

    /// Whether the client completed capability negotiation on this channel.
    pub fn negotiated(&self) -> bool {
        self.negotiated.load(Ordering::Relaxed)
    }
}

struct DvcIoContext {
    // Declared first so that its pending IO is cancelled before the WTS channel closes.
    io: Box<DvcIo>,
    _wts: WtsVirtualChannel,
}

/// Run main DVC IO loop for `Devolutions::Now::Agent` channel.
pub fn run_dvc_io(
    write_rx: WinapiSignaledReceiver<NowMessage<'static>>,
    read_tx: Sender<NowMessage<'static>>,
    stop_event: Event,
    progress: &DvcInitializationProgress,
    io_loop_ended_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<(), anyhow::Error> {
    let Some(mut context) = initialize_dvc_with_retry(&stop_event, progress)? else {
        info!("DVC IO thread stopped during initialization");
        return Ok(());
    };

    let result = context.io.serve(write_rx, &read_tx, &stop_event);

    // Notify processing before cancellation cleanup, which can block until pending IO completes.
    let _ = io_loop_ended_tx.send(());
    result
}

/// Interval at which decoded messages are offered again to a full processing queue.
const INBOUND_RETRY_INTERVAL_MS: u32 = 10;

/// Longest time without a write while decoded messages are held back.
///
/// No read is pending while messages are held back, so only a write can observe a closed channel.
/// Without this probe, a client lost during stdin backpressure goes unnoticed until the next heartbeat, or forever
/// when heartbeats are disabled, and the channel is never reopened.
const BACKLOG_PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// Overlapped IO state of one open DVC channel.
///
/// Reads and writes are both overlapped, so that a client slow to read never stops the loop from reading, and the
/// loop never blocks on the processing task.
/// Must stay boxed while IO is pending, because the OS writes to the `OVERLAPPED` structures and buffers.
struct DvcIo {
    file: Owned<HANDLE>,

    read_buffer: Box<[u8]>,
    read_overlapped: OVERLAPPED,
    read_event: Event,
    read_pending: bool,
    message_dissector: NowMessageDissector,
    /// Decoded messages the processing task has no room for yet.
    ///
    /// No read is issued while this is not empty, which bounds it to the messages of one read.
    inbound: VecDeque<NowMessage<'static>>,

    write_buffer: Vec<u8>,
    write_overlapped: OVERLAPPED,
    write_event: Event,
    write_pending: bool,
    last_write_started: Instant,
}

#[derive(Clone, Copy)]
enum DvcIoWake {
    Stop,
    ReadCompleted,
    WriteCompleted,
    Outbound,
}

impl DvcIo {
    fn new(file: Owned<HANDLE>) -> anyhow::Result<Box<Self>> {
        let read_event = Event::new_unnamed()?;
        let write_event = Event::new_unnamed()?;

        // All DVC messages should be under CHANNEL_CHUNK_LENGTH size, but sometimes RDP stack
        // sends a few messages together; 128Kb buffer should be enough to hold a few dozen messages.
        Ok(Box::new(Self {
            file,
            read_buffer: vec![0u8; 128 * 1024].into_boxed_slice(),
            read_overlapped: OVERLAPPED {
                hEvent: read_event.raw(),
                ..Default::default()
            },
            read_event,
            read_pending: false,
            message_dissector: NowMessageDissector::default(),
            inbound: VecDeque::new(),
            write_buffer: Vec::new(),
            write_overlapped: OVERLAPPED {
                hEvent: write_event.raw(),
                ..Default::default()
            },
            write_event,
            write_pending: false,
            last_write_started: Instant::now(),
        }))
    }

    fn serve(
        &mut self,
        mut write_rx: WinapiSignaledReceiver<NowMessage<'static>>,
        read_tx: &Sender<NowMessage<'static>>,
        stop_event: &Event,
    ) -> anyhow::Result<()> {
        loop {
            self.forward_inbound(read_tx)?;

            if self.inbound.is_empty() {
                if !self.read_pending {
                    self.start_read()?;
                }
            } else if !self.write_pending && self.last_write_started.elapsed() >= BACKLOG_PROBE_INTERVAL {
                // NOW clients already accept unsolicited heartbeats, which are sent even when none was negotiated.
                // Messages are only held back after negotiation, once stdin backpressure stops the processing task.
                trace!("Probing the DVC channel while inbound messages are held back");
                self.start_write(&NowChannelHeartbeatMsg::default().into())
                    .context("probing the DVC channel while inbound messages are held back")?;
            }

            // The stop event comes first so that it wins over a busy channel.
            let mut wakes = vec![(stop_event.raw(), DvcIoWake::Stop)];

            if self.read_pending {
                wakes.push((self.read_event.raw(), DvcIoWake::ReadCompleted));
            }

            // One write at a time: further messages wait in `write_rx`, which holds back the processing task.
            if self.write_pending {
                wakes.push((self.write_event.raw(), DvcIoWake::WriteCompleted));
            } else {
                wakes.push((write_rx.raw_wait_handle(), DvcIoWake::Outbound));
            }

            let handles: Vec<HANDLE> = wakes.iter().map(|(handle, _)| *handle).collect();
            let timeout = if self.inbound.is_empty() {
                INFINITE
            } else {
                INBOUND_RETRY_INTERVAL_MS
            };

            // SAFETY: All handles are valid for the duration of the call.
            let wait_status = unsafe { WaitForMultipleObjects(&handles, false, timeout) };

            if wait_status == WAIT_TIMEOUT {
                continue;
            }

            let wake = usize::try_from(wait_status.0.wrapping_sub(WAIT_OBJECT_0.0))
                .ok()
                .and_then(|index| wakes.get(index))
                .map(|(_, wake)| *wake);

            match wake {
                Some(DvcIoWake::Stop) => {
                    info!("DVC IO thread is stopped");
                    return Ok(());
                }
                Some(DvcIoWake::ReadCompleted) => self.complete_read()?,
                Some(DvcIoWake::WriteCompleted) => self.complete_write()?,
                Some(DvcIoWake::Outbound) => {
                    trace!("DVC channel write event is signaled");

                    let message = write_rx.try_recv()?;
                    self.start_write(&message)?;
                }
                None => {
                    return Err(windows::core::Error::from_win32())
                        .with_context(|| format!("waiting for DVC IO failed with status {:#X}", wait_status.0));
                }
            }
        }
    }

    fn start_read(&mut self) -> windows::core::Result<()> {
        // SAFETY: The buffer and `OVERLAPPED` live in this boxed struct, whose `Drop` waits for the read to finish.
        let result = unsafe {
            ReadFile(
                *self.file,
                Some(&mut self.read_buffer),
                None,
                Some(&mut self.read_overlapped),
            )
        };
        ensure_overlapped_io_result(result)?;
        self.read_pending = true;

        Ok(())
    }

    fn complete_read(&mut self) -> anyhow::Result<()> {
        trace!("DVC channel read event is signaled");

        self.read_pending = false;
        let mut bytes_read: u32 = 0;

        // SAFETY: The read was issued on this handle with this `OVERLAPPED`, and has completed.
        unsafe { GetOverlappedResult(*self.file, &self.read_overlapped, &mut bytes_read, false) }?;

        const HEADER_SIZE: usize = size_of::<CHANNEL_PDU_HEADER>();

        let bytes_read = usize::try_from(bytes_read).expect("u32 fits into usize on Windows");
        let payload = self.read_buffer.get(HEADER_SIZE..bytes_read).with_context(|| {
            format!("DVC read returned {bytes_read} bytes, fewer than the {HEADER_SIZE}-byte channel PDU header")
        })?;

        let messages = match self.message_dissector.dissect(payload) {
            Ok(messages) => messages,
            Err(error) => {
                error!(?error, "Failed to dissect DVC messages");
                return Err(error.context("failed to dissect DVC messages"));
            }
        };

        for message in messages {
            debug!(?message, "DVC message received");
            self.inbound.push_back(message);
        }

        Ok(())
    }

    /// Hands decoded messages to the processing task, keeping those it has no room for.
    ///
    /// The send never blocks, because the loop also services outbound writes: blocking here while the processing task
    /// awaits an outbound send would deadlock both sides.
    /// Kept messages stop further reads until the queue has room, so a slow processing task holds back the client
    /// rather than losing a message.
    /// NOW capability responses carry no request id, so a lost request would silently shift every later response the
    /// client matches by send order.
    fn forward_inbound(&mut self, read_tx: &Sender<NowMessage<'static>>) -> anyhow::Result<()> {
        while let Some(message) = self.inbound.pop_front() {
            match read_tx.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(message)) => {
                    trace!(pending = self.inbound.len() + 1, "DVC processing queue is full");
                    self.inbound.push_front(message);
                    break;
                }
                Err(TrySendError::Closed(_)) => {
                    anyhow::bail!("the DVC message processing task has stopped");
                }
            }
        }

        Ok(())
    }

    fn start_write(&mut self, message: &NowMessage<'static>) -> anyhow::Result<()> {
        self.write_buffer = now_proto_pdu::ironrdp_core::encode_vec(message)?;

        // SAFETY: The buffer and `OVERLAPPED` live in this boxed struct, whose `Drop` waits for the write to finish.
        let result = unsafe {
            WriteFile(
                *self.file,
                Some(&self.write_buffer),
                None,
                Some(&mut self.write_overlapped),
            )
        };
        self.last_write_started = Instant::now();
        ensure_overlapped_io_result(result)?;
        self.write_pending = true;

        Ok(())
    }

    fn complete_write(&mut self) -> anyhow::Result<()> {
        self.write_pending = false;
        let mut bytes_written: u32 = 0;

        // SAFETY: The write was issued on this handle with this `OVERLAPPED`, and has completed.
        unsafe { GetOverlappedResult(*self.file, &self.write_overlapped, &mut bytes_written, false) }?;

        let bytes_written = usize::try_from(bytes_written).expect("u32 fits into usize on Windows");

        // The rest of a short write cannot be sent in a second write: the client decodes each DVC message on its own.
        if bytes_written != self.write_buffer.len() {
            anyhow::bail!("DVC write sent {bytes_written} of {} bytes", self.write_buffer.len());
        }

        Ok(())
    }
}

impl Drop for DvcIo {
    fn drop(&mut self) {
        let pending = [
            (self.read_pending, &self.read_overlapped),
            (self.write_pending, &self.write_overlapped),
        ];

        for (_, overlapped) in pending.into_iter().filter(|(pending, _)| *pending) {
            let mut bytes_transferred: u32 = 0;

            // The OS writes to the buffer and `OVERLAPPED` until the operation finishes, so it must finish before
            // they are freed. Errors are ignored: the operation may complete before it is cancelled, and a failed
            // operation is finished all the same.
            // SAFETY: The handle and `OVERLAPPED` are those of an issued operation, and are still alive.
            let _ = unsafe { CancelIoEx(*self.file, Some(overlapped)) };
            // SAFETY: Same as above.
            let _ = unsafe { GetOverlappedResult(*self.file, overlapped, &mut bytes_transferred, true) };
        }
    }
}

fn initialize_dvc_with_retry(
    stop_event: &Event,
    progress: &DvcInitializationProgress,
) -> anyhow::Result<Option<Box<DvcIoContext>>> {
    let mut attempt = 1usize;

    loop {
        let started_at = Instant::now();
        progress.record_open_attempt();

        let error = match initialize_dvc() {
            Ok(mut context) => match start_initial_read(&mut context) {
                Ok(()) => {
                    progress.mark_channel_opened();
                    info!(
                        attempt,
                        elapsed_ms = started_at.elapsed().as_millis(),
                        "DVC IO thread is running"
                    );
                    return Ok(Some(context));
                }
                Err(error) => DvcInitializationError {
                    stage: DvcInitializationStage::StartRead,
                    error: error.into(),
                },
            },
            Err(error) => error,
        };

        // A failure returning in a couple of milliseconds was rejected locally by the RDP stack;
        // one taking a round trip was rejected by the client.
        let elapsed_ms = started_at.elapsed().as_millis();

        match error {
            error if error.is_retryable() => {
                let Some(delay) = dvc_retry_delay(attempt - 1) else {
                    error!(
                        attempts = attempt,
                        stage = %error.stage,
                        error_code = %error.code_for_logs(),
                        elapsed_ms,
                        "Giving up on DVC initialization; retries exhausted"
                    );

                    return Err(error.into_anyhow());
                };

                warn!(
                    attempt,
                    stage = %error.stage,
                    error = %error.error,
                    error_code = %error.code_for_logs(),
                    elapsed_ms,
                    retry_delay_ms = delay.as_millis(),
                    "Transient DVC initialization failure; retrying"
                );

                if !wait_for_retry_delay(stop_event, delay)? {
                    return Ok(None);
                }

                attempt += 1;
            }
            error => {
                error!(
                    attempts = attempt,
                    stage = %error.stage,
                    error_code = %error.code_for_logs(),
                    elapsed_ms,
                    "DVC initialization failed with a non-retryable error"
                );

                return Err(error.into_anyhow());
            }
        }
    }
}

fn initialize_dvc() -> Result<Box<DvcIoContext>, DvcInitializationError> {
    trace!("Opening DVC channel");
    let wts = WtsVirtualChannel::open_dvc(DVC_CHANNEL_NAME).map_err(|error| DvcInitializationError {
        stage: DvcInitializationStage::Open,
        error,
    })?;

    trace!("Querying DVC channel");
    let channel_file = wts.query_file_handle().map_err(|error| DvcInitializationError {
        stage: DvcInitializationStage::QueryFileHandle,
        error,
    })?;

    let io = DvcIo::new(channel_file).map_err(|error| DvcInitializationError {
        stage: DvcInitializationStage::StartRead,
        error,
    })?;

    Ok(Box::new(DvcIoContext { io, _wts: wts }))
}

fn start_initial_read(context: &mut DvcIoContext) -> Result<(), windows::core::Error> {
    context.io.start_read()?;

    trace!("DVC channel opened");

    Ok(())
}

fn dvc_retry_delay(retry: usize) -> Option<Duration> {
    DVC_RETRY_DELAYS.get(retry).copied()
}

fn wait_for_retry_delay(stop_event: &Event, delay: Duration) -> anyhow::Result<bool> {
    let timeout = u32::try_from(delay.as_millis()).unwrap_or(u32::MAX);

    // SAFETY: stop_event is a valid event handle for the lifetime of this call.
    let status = unsafe { WaitForSingleObject(stop_event.raw(), timeout) };

    match status {
        WAIT_OBJECT_0 => Ok(false),
        WAIT_TIMEOUT => Ok(true),
        _ => anyhow::bail!("waiting for DVC retry delay failed with status {}", status.0),
    }
}

pub fn ensure_overlapped_io_result(result: windows::core::Result<()>) -> Result<(), windows::core::Error> {
    if let Err(error) = result {
        // SAFETY: GetLastError is alwayі safe to call
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(error);
        }
    }

    Ok(())
}

pub struct IoRedirectionPipes {
    pub stdout_read_pipe: Pipe,
    pub stdout_write_pipe: Pipe,

    pub stderr_read_pipe: Pipe,
    pub stderr_write_pipe: Pipe,

    pub stdin_read_pipe: Pipe,
    pub stdin_write_pipe: Pipe,
}

impl IoRedirectionPipes {
    pub fn new() -> anyhow::Result<Self> {
        let (stdout_read_pipe, stdout_write_pipe) = Pipe::new_async_stdout_redirection_pipe()?;
        let (stderr_read_pipe, stderr_write_pipe) = Pipe::new_async_stdout_redirection_pipe()?;
        let (stdin_read_pipe, stdin_write_pipe) = Pipe::new_sync_stdin_redirection_pipe()?;

        Ok(IoRedirectionPipes {
            stdout_read_pipe,
            stdout_write_pipe,
            stderr_read_pipe,
            stderr_write_pipe,
            stdin_read_pipe,
            stdin_write_pipe,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::poll;
    use now_proto_pdu::NowMessage;
    use tokio::sync::mpsc;

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Instant;

    use now_proto_pdu::ironrdp_core::encode_vec;
    use now_proto_pdu::{NowChannelHeartbeatMsg, NowExecDataMsg, NowExecDataStreamKind};
    use win_api_wrappers::event::Event;
    use windows::Win32::Foundation::{ERROR_MORE_DATA, GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    };
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        PeekNamedPipe,
    };
    use windows::core::{Owned, PCWSTR};

    use super::{DVC_RETRY_DELAYS, DvcInitializationProgress, DvcIo, dvc_retry_delay};
    use crate::dvc::channel::{WinapiSignaledSender, winapi_signaled_mpsc_channel};

    /// A connected message-mode pipe standing in for the DVC: the loop serves the overlapped server end, and the test
    /// plays the client on the synchronous end.
    fn dvc_pipe() -> (usize, Owned<HANDLE>) {
        static NEXT_PIPE: AtomicU32 = AtomicU32::new(0);

        let name = format!(
            r"\\.\pipe\devolutions-session-dvc-io-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        );
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();

        // SAFETY: The name is a valid null-terminated string.
        let server = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                None,
            )
        };
        assert!(!server.is_invalid(), "{}", windows::core::Error::from_win32());

        // SAFETY: The name is a valid null-terminated string.
        let client = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .expect("connect to the test pipe");

        // The raw value crosses to the IO thread, which takes ownership of it.
        // SAFETY: Both handles were just opened and are owned by nothing else.
        (server.0 as usize, unsafe { Owned::new(client) })
    }

    const PIPE_BUFFER_SIZE: u32 = 4 * 1024;

    struct RunningDvcIo {
        write_tx: WinapiSignaledSender<NowMessage<'static>>,
        read_rx: mpsc::Receiver<NowMessage<'static>>,
        stop_event: Event,
        thread: std::thread::JoinHandle<anyhow::Result<()>>,
    }

    fn run_dvc_io_on(server: usize, read_queue_capacity: usize) -> RunningDvcIo {
        let (write_tx, write_rx) = winapi_signaled_mpsc_channel().expect("create the write queue");
        let (read_tx, read_rx) = mpsc::channel(read_queue_capacity);
        let stop_event = Event::new_unnamed().expect("create the stop event");
        let thread_stop_event = stop_event.clone();

        let thread = std::thread::spawn(move || {
            // SAFETY: The handle was opened by `dvc_pipe`, which gave up ownership of it.
            let file = unsafe { Owned::new(HANDLE(server as *mut _)) };
            let mut io = DvcIo::new(file)?;
            io.serve(write_rx, &read_tx, &thread_stop_event)
        });

        RunningDvcIo {
            write_tx,
            read_rx,
            stop_event,
            thread,
        }
    }

    impl RunningDvcIo {
        fn recv(&mut self) -> NowMessage<'static> {
            let deadline = Instant::now() + TEST_TIMEOUT;

            loop {
                if let Ok(message) = self.read_rx.try_recv() {
                    return message;
                }

                assert!(Instant::now() < deadline, "no message reached the processing queue");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn join(self) -> anyhow::Result<()> {
            let deadline = Instant::now() + TEST_TIMEOUT;

            while !self.thread.is_finished() {
                assert!(Instant::now() < deadline, "the DVC IO loop did not stop");
                std::thread::sleep(Duration::from_millis(5));
            }

            self.thread.join().expect("the DVC IO loop panicked")
        }

        fn stop(self) -> anyhow::Result<()> {
            self.stop_event.set().expect("set the stop event");
            self.join()
        }
    }

    /// Writes one channel read as the RDP stack delivers it: an 8-byte `CHANNEL_PDU_HEADER`, then the data.
    fn write_pdu(client: &Owned<HANDLE>, data: &[u8]) {
        const CHANNEL_FLAG_FIRST_AND_LAST: u32 = 0x3;

        let mut pdu = u32::try_from(data.len())
            .expect("test data fits")
            .to_le_bytes()
            .to_vec();
        pdu.extend_from_slice(&CHANNEL_FLAG_FIRST_AND_LAST.to_le_bytes());
        pdu.extend_from_slice(data);

        write_raw(client, &pdu);
    }

    fn write_raw(client: &Owned<HANDLE>, bytes: &[u8]) {
        let mut written = 0;
        // SAFETY: The handle and buffer are valid for the duration of the synchronous call.
        unsafe { WriteFile(**client, Some(bytes), Some(&mut written), None) }.expect("write to the test pipe");
        assert_eq!(written as usize, bytes.len());
    }

    fn read_exact(client: &Owned<HANDLE>, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        let mut filled = 0;

        while filled < len {
            let mut read = 0;
            // SAFETY: The handle and buffer are valid for the duration of the synchronous call.
            let result = unsafe { ReadFile(**client, Some(&mut bytes[filled..]), Some(&mut read), None) };

            // A message larger than the buffer is read in parts, each reported as `ERROR_MORE_DATA`.
            if let Err(error) = result {
                assert_eq!(error.code(), ERROR_MORE_DATA.to_hresult(), "read from the test pipe");
            }

            filled += read as usize;
        }

        bytes
    }

    /// Waits until the client has bytes to read, so that a following [`read_exact`] cannot block forever.
    fn wait_for_outbound(client: &Owned<HANDLE>, failure: &str) {
        let deadline = Instant::now() + TEST_TIMEOUT;

        loop {
            let mut available = 0;
            // SAFETY: The handle is valid, and only the byte count is requested.
            unsafe { PeekNamedPipe(**client, None, 0, None, Some(&mut available), None) }.expect("peek the test pipe");

            if available > 0 {
                return;
            }

            assert!(Instant::now() < deadline, "{failure}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn encoded(message: &NowMessage<'_>) -> Vec<u8> {
        encode_vec(message).expect("encode a NOW message")
    }

    fn exec_data(session_id: u32, data: Vec<u8>) -> NowMessage<'static> {
        NowExecDataMsg::new(session_id, NowExecDataStreamKind::Stdin, false, data)
            .expect("build an exec data message")
            .into()
    }

    // oracle: scaffold
    #[test]
    fn read_shorter_than_the_channel_header_is_an_error_with_its_length() {
        let (server, client) = dvc_pipe();
        let running = run_dvc_io_on(server, 1);

        write_raw(&client, &[0; 4]);

        let error = running.join().expect_err("a 4-byte read cannot hold a channel header");
        let message = format!("{error:#}");
        assert!(message.contains("4 bytes"), "unexpected error: {message}");
    }

    /// An empty channel PDU carries no message and must not end the loop, so a later message still arrives.
    // oracle: scaffold
    #[test]
    fn empty_channel_pdu_is_skipped() {
        let (server, client) = dvc_pipe();
        let mut running = run_dvc_io_on(server, 1);
        let message = exec_data(1, b"after".to_vec());

        write_pdu(&client, &[]);
        write_pdu(&client, &encoded(&message));

        assert_eq!(encoded(&running.recv()), encoded(&message));
        running.stop().expect("the loop stops cleanly");
    }

    /// A client that does not read our output must not stop us from reading its input; with a synchronous write the
    /// loop would block until the client reads.
    // oracle: mutant
    #[test]
    fn reads_continue_while_a_large_write_is_pending() {
        let (server, client) = dvc_pipe();
        let mut running = run_dvc_io_on(server, 1);

        let outbound = exec_data(1, vec![0xA5; 1024 * 1024]);
        let outbound_bytes = encoded(&outbound);
        running.write_tx.try_send(outbound).expect("queue the outbound message");

        // The write is in flight once its first bytes are visible to the client.
        wait_for_outbound(&client, "the outbound write never started");

        let inbound = exec_data(2, b"stdin".to_vec());
        write_pdu(&client, &encoded(&inbound));
        assert_eq!(encoded(&running.recv()), encoded(&inbound));

        // The outbound message arrives whole, as a single pipe message.
        assert_eq!(read_exact(&client, outbound_bytes.len()), outbound_bytes);

        running.stop().expect("the loop stops cleanly");
    }

    /// A full processing queue must hold messages back rather than drop them or end the channel: the client matches
    /// responses by send order, so a gap would desynchronize it.
    // oracle: mutant
    #[test]
    fn full_processing_queue_holds_messages_back_in_order() {
        let (server, client) = dvc_pipe();
        let mut running = run_dvc_io_on(server, 1);
        let messages: Vec<_> = (1..=3).map(|session_id| exec_data(session_id, vec![0; 16])).collect();

        for message in &messages {
            write_pdu(&client, &encoded(message));
        }

        // Give the loop time to read past the queue's capacity before anything is received.
        std::thread::sleep(Duration::from_millis(200));
        assert!(!running.thread.is_finished(), "the loop ended on a full queue");

        for message in &messages {
            assert_eq!(encoded(&running.recv()), encoded(message));
        }

        running.stop().expect("the loop stops cleanly");
    }

    /// A client that goes away while the processing queue is full must still end the loop, so the channel is reopened.
    ///
    /// No read is pending while messages are held back, so only a write can observe the closed channel.
    // oracle: mutant
    #[test]
    fn closed_channel_ends_the_loop_while_messages_are_held_back() {
        let (server, client) = dvc_pipe();
        let running = run_dvc_io_on(server, 1);

        for session_id in 1..=3 {
            write_pdu(&client, &encoded(&exec_data(session_id, vec![0; 16])));
        }

        std::thread::sleep(Duration::from_millis(200));
        drop(client);

        running.join().expect_err("a closed channel ends the loop");
    }

    /// Probing a held-back channel must not disturb it: the client gets heartbeats, and every message still arrives.
    // oracle: mutant
    #[test]
    fn held_back_channel_is_probed_with_heartbeats() {
        let (server, client) = dvc_pipe();
        let mut running = run_dvc_io_on(server, 1);
        let messages: Vec<_> = (1..=3).map(|session_id| exec_data(session_id, vec![0; 16])).collect();

        for message in &messages {
            write_pdu(&client, &encoded(message));
        }

        let heartbeat = encoded(&NowChannelHeartbeatMsg::default().into());
        wait_for_outbound(&client, "the held-back channel was never probed");
        assert_eq!(read_exact(&client, heartbeat.len()), heartbeat);

        for message in &messages {
            assert_eq!(encoded(&running.recv()), encoded(message));
        }

        running.stop().expect("the loop stops cleanly");
    }

    /// Stopping with a read and a write in flight must cancel both and return.
    // oracle: scaffold
    #[test]
    fn stop_cancels_pending_io() {
        let (server, _client) = dvc_pipe();
        let running = run_dvc_io_on(server, 1);

        running
            .write_tx
            .try_send(exec_data(1, vec![0; 1024 * 1024]))
            .expect("queue the outbound message");
        std::thread::sleep(Duration::from_millis(100));

        running.stop().expect("the loop stops cleanly");
    }

    // oracle: scaffold
    #[test]
    fn closed_processing_queue_is_an_error() {
        let (server, client) = dvc_pipe();
        let running = run_dvc_io_on(server, 1);
        let RunningDvcIo {
            write_tx,
            read_rx,
            stop_event,
            thread,
        } = running;
        drop(read_rx);

        write_pdu(&client, &encoded(&exec_data(1, Vec::new())));

        let running = RunningDvcIo {
            write_tx,
            read_rx: mpsc::channel(1).1,
            stop_event,
            thread,
        };
        running.join().expect_err("a closed processing queue ends the loop");
    }

    #[test]
    fn dvc_retry_delays_are_bounded() {
        assert_eq!(dvc_retry_delay(0), Some(Duration::from_millis(250)));
        assert_eq!(dvc_retry_delay(4), Some(Duration::from_secs(4)));
        assert_eq!(dvc_retry_delay(5), None);
    }

    /// Pins the intended retry budget: six attempts across 7.75 seconds of backoff.
    #[test]
    fn dvc_retry_budget_is_expected() {
        let attempts = 1 + DVC_RETRY_DELAYS.len();
        let total: Duration = DVC_RETRY_DELAYS.iter().sum();

        assert_eq!(attempts, 6);
        assert_eq!(total, Duration::from_millis(7750));
    }

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// The deadline must not elapse while the channel is still unopened, however long the open
    /// takes. Moving the delay ahead of the channel-open wait reintroduces the race where the
    /// deadline expires before the client is able to negotiate.
    #[tokio::test(start_paused = true)]
    async fn negotiation_deadline_does_not_start_before_channel_open() {
        let progress = DvcInitializationProgress::default();
        let mut deadline = Box::pin(progress.negotiation_deadline(TEST_TIMEOUT));

        // Register the deadline's interest in the open signal before any time passes.
        assert!(poll!(deadline.as_mut()).is_pending());

        // Far beyond the timeout, but the channel was never opened.
        tokio::time::advance(TEST_TIMEOUT * 100).await;
        assert!(
            poll!(deadline.as_mut()).is_pending(),
            "deadline elapsed while the channel was still unopened"
        );

        // Opening the channel starts the delay; it must not already be over.
        progress.mark_channel_opened();
        assert!(
            poll!(deadline.as_mut()).is_pending(),
            "deadline elapsed immediately on channel open"
        );

        tokio::time::advance(TEST_TIMEOUT).await;
        assert!(poll!(deadline.as_mut()).is_ready());
    }

    /// A channel opened before the deadline is awaited must still be observed, otherwise the
    /// notification is lost and the deadline never elapses.
    #[tokio::test(start_paused = true)]
    async fn negotiation_deadline_starts_when_channel_is_already_open() {
        let progress = DvcInitializationProgress::default();
        progress.mark_channel_opened();

        let mut deadline = Box::pin(progress.negotiation_deadline(TEST_TIMEOUT));

        assert!(poll!(deadline.as_mut()).is_pending());

        tokio::time::advance(TEST_TIMEOUT).await;
        assert!(poll!(deadline.as_mut()).is_ready());
    }
}
