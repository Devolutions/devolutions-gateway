use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use now_proto_pdu::NowMessage;
use tokio::sync::Notify;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, error, info, trace, warn};
use win_api_wrappers::event::Event;
use win_api_wrappers::utils::Pipe;
use win_api_wrappers::wts::WtsVirtualChannel;
use windows::Win32::Foundation::{
    ERROR_GEN_FAILURE, ERROR_IO_PENDING, GetLastError, HANDLE, WAIT_EVENT, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
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

/// Counters and signalling shared between the DVC IO thread and the DVC task.
///
/// Beyond diagnostics, this gates the negotiation deadline, which must not start before the
/// channel is open.
#[derive(Debug, Default)]
pub struct DvcInitializationProgress {
    open_attempts: AtomicU32,
    channel_opened: AtomicBool,
    channel_opened_notify: Notify,
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
}

struct DvcIoContext {
    _wts: WtsVirtualChannel,
    channel_file: Owned<HANDLE>,
    pdu_chunk_buffer: Box<[u8]>,
    overlapped: OVERLAPPED,
    bytes_read: u32,
    message_dissector: NowMessageDissector,
    read_event: Event,
}

/// Run main DVC IO loop for `Devolutions::Now::Agent` channel.
pub fn run_dvc_io(
    mut write_rx: WinapiSignaledReceiver<NowMessage<'static>>,
    read_tx: Sender<NowMessage<'static>>,
    stop_event: Event,
    progress: &DvcInitializationProgress,
) -> Result<(), anyhow::Error> {
    let Some(mut context) = initialize_dvc_with_retry(&stop_event, progress)? else {
        info!("DVC IO thread stopped during initialization");
        return Ok(());
    };

    loop {
        let events = [context.read_event.raw(), write_rx.raw_wait_handle(), stop_event.raw()];

        const WAIT_OBJECT_READ_DVC: WAIT_EVENT = WAIT_OBJECT_0;
        const WAIT_OBJECT_WRITE_DVC: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 1);
        const WAIT_OBJECT_STOP: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 2);

        // SAFETY: No preconditions.
        let wait_status = unsafe { WaitForMultipleObjects(&events, false, INFINITE) };

        match wait_status {
            // Read event is signaled (incoming data from DVC channel).
            WAIT_OBJECT_READ_DVC => {
                trace!("DVC channel read event is signaled");

                // SAFETY: No preconditions.
                unsafe {
                    GetOverlappedResult(
                        *context.channel_file,
                        &context.overlapped,
                        &mut context.bytes_read,
                        false,
                    )
                }?;

                if context.bytes_read
                    < u32::try_from(size_of::<CHANNEL_PDU_HEADER>())
                        .expect("CHANNEL_PDU_HEADER size always fits into u32")
                {
                    // Channel is closed abruptly; abort loop.
                    return Ok(());
                }

                let chunk_data_size = usize::try_from(context.bytes_read)
                    .expect("read size can't be breater than CHANNEL_CHUNK_LENGTH, therefore it should fit into usize")
                    .checked_sub(size_of::<CHANNEL_PDU_HEADER>())
                    .expect("read size is less than header size; Correctness of this should be ensured by the OS");

                const HEADER_SIZE: usize = size_of::<CHANNEL_PDU_HEADER>();

                let messages = context
                    .message_dissector
                    .dissect(&context.pdu_chunk_buffer[HEADER_SIZE..HEADER_SIZE + chunk_data_size])
                    .context("failed to dissect DVC messages");

                let messages = match messages {
                    Ok(messages) => messages,
                    Err(err) => {
                        error!(?err, "Failed to dissect DVC messages");
                        return Err(err);
                    }
                };

                // Send all messages over the channel.
                for message in messages {
                    debug!(?message, "DVC message received");
                    // We do non-blocking send to avoid blocking the IO thread. Processing
                    // task is expected to be fast enough to keep up with the incoming messages.
                    match read_tx.try_send(message) {
                        Ok(_) => {}
                        Err(TrySendError::Full(_)) => {
                            error!("DVC message was dropped due to channel overflow");
                        }
                        Err(e) => {
                            error!("DVC message was dropped due to closed channel");
                            return Err(e.into());
                        }
                    }
                }
                // Prepare async read file operation one more time.
                // SAFETY: No preconditions.
                let result = unsafe {
                    ReadFile(
                        *context.channel_file,
                        Some(&mut context.pdu_chunk_buffer),
                        None,
                        Some(&mut context.overlapped),
                    )
                };

                ensure_overlapped_io_result(result)?;
            }
            // Write event is signaled (outgoing data to DVC channel).
            WAIT_OBJECT_WRITE_DVC => {
                trace!("DVC channel write event is signaled");

                let message_to_write = write_rx.try_recv()?;
                let message_bytes = now_proto_pdu::ironrdp_core::encode_vec(&message_to_write)?;

                let mut dw_written: u32 = 0;

                // SAFETY: No preconditions.
                unsafe { WriteFile(*context.channel_file, Some(&message_bytes), Some(&mut dw_written), None)? }
            }
            WAIT_OBJECT_STOP => {
                info!("DVC IO thread is stopped");
                // Stop event is signaled; abort loop.
                return Ok(());
            }
            _ => {
                // Spurious wakeup or wait failure
            }
        };
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

    // All DVC messages should be under CHANNEL_CHUNK_LENGTH size, but sometimes RDP stack
    // sends a few messages together; 128Kb buffer should be enough to hold a few dozen messages.
    let pdu_chunk_buffer = vec![0u8; 128 * 1024].into_boxed_slice();
    let read_event = Event::new_unnamed().map_err(|error| DvcInitializationError {
        stage: DvcInitializationStage::StartRead,
        error,
    })?;
    let overlapped = OVERLAPPED {
        hEvent: read_event.raw(),
        ..Default::default()
    };

    Ok(Box::new(DvcIoContext {
        _wts: wts,
        channel_file,
        pdu_chunk_buffer,
        overlapped,
        bytes_read: 0,
        message_dissector: NowMessageDissector::default(),
        read_event,
    }))
}

fn start_initial_read(context: &mut DvcIoContext) -> Result<(), windows::core::Error> {
    // Prepare async read operation.
    // SAFETY: Both `channel_file` and event passed to `overlapped` are valid during this call,
    // therefore it is safe to call.
    let read_result: Result<(), windows::core::Error> = unsafe {
        ReadFile(
            *context.channel_file,
            Some(&mut context.pdu_chunk_buffer),
            None,
            Some(&mut context.overlapped),
        )
    };
    ensure_overlapped_io_result(read_result)?;

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

    use super::{DVC_RETRY_DELAYS, DvcInitializationProgress, dvc_retry_delay};

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
