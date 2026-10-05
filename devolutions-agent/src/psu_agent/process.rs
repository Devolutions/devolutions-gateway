use std::collections::HashMap;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::{Instant, MissedTickBehavior};

use crate::psu_agent::process_tree::ProcessTree;
use crate::psu_agent::protocol::agent_message::Payload as AgentPayload;
use crate::psu_agent::protocol::{AgentMessage, ProcessCompleted, ProcessStarted, StartProcess, StreamData};
use crate::psu_agent::{agent_message, diagnostic, stream_closed, stream_data};

const PWSH_STDIN_CLOSED_EXIT_CODE: i32 = 160;
const GRACEFUL_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
// Matches the Windows pipe buffer, where a write completes only once the child process reads it.
const STDIN_WRITE_CHUNK_SIZE: usize = 4 * 1024;
const MIB: usize = 1024 * 1024;

/// Limits on stdin data buffered for a child process.
///
/// Stdin frames are queued without waiting because all streams share one server connection. The server is expected
/// to apply flow control to the input it sends, keeping backlogs well below `max_buffered_bytes` and
/// `max_total_buffered_bytes`.
///
/// Time during which the child process output is held back by the server connection does not count toward the stall
/// timeouts, because a child process blocked writing its output cannot read its input.
#[derive(Debug, Clone, Copy)]
pub(super) struct StdinLimits {
    /// A child process is considered stalled while at least this many bytes of its stdin are unread and none are
    /// consumed.
    pub(super) stall_threshold_bytes: usize,
    /// Upper bound assumed for stdin bytes written to the pipe but not read by the child process yet.
    ///
    /// Written bytes count as consumed, so they are not part of the pending backlog. Without this allowance, a
    /// backlog just above the threshold could fall below it once the pipe buffer fills, and never time out.
    pub(super) pipe_allowance_bytes: usize,
    /// How long a child process may stay stalled before it is stopped.
    ///
    /// Also how long a stream must have made no stdin progress before it can be stopped to make room in
    /// `max_total_buffered_bytes`.
    pub(super) stall_timeout: Duration,
    /// How long any unwritten stdin may make no progress before the child process is stopped.
    ///
    /// Bounds how long a backlog below `stall_threshold_bytes` stays charged against `max_total_buffered_bytes`.
    pub(super) pending_stall_timeout: Duration,
    /// Pending bytes beyond which the stream is failed immediately to bound memory usage.
    pub(super) max_buffered_bytes: usize,
    /// Pending bytes across all streams beyond which stalled streams are stopped to make room, or the stream
    /// receiving input is failed if no stalled stream frees enough.
    ///
    /// Each server connection has its own registry, so this budget is per connection rather than agent-wide. On
    /// reconnect, the processes of the previous connection may briefly hold their input while they are being stopped.
    pub(super) max_total_buffered_bytes: usize,
}

impl Default for StdinLimits {
    // Far above what a script normally receives on stdin, so only a child process that stopped reading is affected,
    // while a few stalled jobs cannot use more than a bounded amount of agent memory.
    fn default() -> Self {
        Self {
            stall_threshold_bytes: 16 * MIB,
            pipe_allowance_bytes: MIB,
            stall_timeout: Duration::from_secs(30),
            pending_stall_timeout: Duration::from_secs(5 * 60),
            max_buffered_bytes: 64 * MIB,
            max_total_buffered_bytes: 256 * MIB,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StopRequest {
    /// Close stdin and let the child process exit on its own.
    Graceful,
    Kill,
    /// The stdin backlog exceeded [`StdinLimits::max_buffered_bytes`] or [`StdinLimits::max_total_buffered_bytes`].
    StdinOverflow,
}

impl StopRequest {
    fn severity(self) -> u8 {
        match self {
            Self::Graceful => 1,
            Self::Kill | Self::StdinOverflow => 2,
        }
    }
}

/// The most severe stop requested for a process.
///
/// A watch channel only keeps the latest value, so stop requests can never fill it, and repeated requests that do
/// not escalate do not wake the process up again.
type StopSender = Arc<watch::Sender<Option<StopRequest>>>;

fn request_stop(stop: &watch::Sender<Option<StopRequest>>, request: StopRequest) {
    stop.send_if_modified(|current| {
        let escalates = current.is_none_or(|current| request.severity() > current.severity());
        if escalates {
            *current = Some(request);
        }
        escalates
    });
}

/// Why the agent killed a child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillReason {
    ServerRequest,
    ExitTimeout,
    StdinOverflow,
    StdinStalled(Stall),
}

/// Why the stall watchdog considers a child process stalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stall {
    /// At least [`StdinLimits::stall_threshold_bytes`] made no progress for [`StdinLimits::stall_timeout`].
    LargeBacklog,
    /// Some stdin made no progress for [`StdinLimits::pending_stall_timeout`].
    PendingInput,
}

const INPUT_ACCEPTED: u8 = 0;
const INPUT_OVERFLOWED: u8 = 1;
const CHILD_EXITED: u8 = 2;

/// Stdin backlog accounting shared by the registry, the stdin pump, and the stall watchdog.
#[derive(Debug)]
struct StdinBacklog {
    /// Memory charged for frames that are queued or being written, released once a frame is dropped.
    pending_bytes: AtomicUsize,
    /// Bytes of queued frames not written to the child process yet, for the stall watchdog.
    unwritten_bytes: AtomicUsize,
    /// Pending bytes across all streams of the registry.
    total_pending_bytes: Arc<AtomicUsize>,
    consumed_bytes: AtomicU64,
    /// Whether input was dropped before the child process exit was observed.
    ///
    /// Moves once from `INPUT_ACCEPTED` to either `INPUT_OVERFLOWED` or `CHILD_EXITED`, so input that arrives after
    /// the exit cannot change the reported outcome.
    input_state: AtomicU8,
    /// Set by the stdin pump before it closes stdin because the server ended the stream.
    end_of_stream: AtomicBool,
    /// How long unwritten stdin has made no progress, in milliseconds, as last measured by the stall watchdog.
    ///
    /// Zero while the stall watchdog does not supervise the stream.
    stalled_for_ms: AtomicU64,
    /// Value of `consumed_bytes` when `stalled_for_ms` was measured, so that progress made since then is noticed.
    stalled_at_consumed_bytes: AtomicU64,
}

/// Memory charged against the stdin backlog for a queued frame, so that empty frames are bounded too.
fn frame_charge(frame: &StreamData) -> usize {
    size_of::<StreamData>() + frame.stream_id.len() + frame.data.len()
}

impl StdinBacklog {
    fn new(total_pending_bytes: Arc<AtomicUsize>) -> Self {
        Self {
            pending_bytes: AtomicUsize::new(0),
            unwritten_bytes: AtomicUsize::new(0),
            total_pending_bytes,
            consumed_bytes: AtomicU64::new(0),
            input_state: AtomicU8::new(INPUT_ACCEPTED),
            end_of_stream: AtomicBool::new(false),
            stalled_for_ms: AtomicU64::new(0),
            stalled_at_consumed_bytes: AtomicU64::new(0),
        }
    }

    fn add_pending(&self, bytes: usize) {
        self.pending_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.unwritten_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.total_pending_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Reverts [`add_pending`](Self::add_pending) for a frame that could not be queued.
    fn cancel_pending(&self, bytes: usize) {
        self.unwritten_bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.release(bytes);
    }

    /// Records stdin bytes written to the child process, for the stall watchdog.
    fn record_progress(&self, bytes: usize) {
        self.unwritten_bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.consumed_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Releases the memory charged for a frame once it is dropped.
    fn release(&self, bytes: usize) {
        self.pending_bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.total_pending_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Releases the memory charged for frames dropped with the stdin queue.
    ///
    /// Must only be called once no frame can be queued or written anymore.
    fn release_remaining(&self) {
        let remaining = self.pending_bytes.swap(0, Ordering::Relaxed);
        self.total_pending_bytes.fetch_sub(remaining, Ordering::Relaxed);
    }

    /// Records dropped input, and returns whether it happened before the child process exit was observed.
    fn record_overflow(&self) -> bool {
        match self
            .input_state
            .compare_exchange(INPUT_ACCEPTED, INPUT_OVERFLOWED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(state) => state == INPUT_OVERFLOWED,
        }
    }

    /// Returns whether the stream can be stopped to make room in [`StdinLimits::max_total_buffered_bytes`].
    fn is_evictable(&self, limits: StdinLimits) -> bool {
        let stall_timeout_ms = u64::try_from(limits.stall_timeout.as_millis()).unwrap_or(u64::MAX);

        // Acquire pairs with the release store of the watchdog, so the consumed bytes it measured are visible.
        self.input_state.load(Ordering::Acquire) == INPUT_ACCEPTED
            && self.unwritten_bytes.load(Ordering::Relaxed) > 0
            && self.stalled_for_ms.load(Ordering::Acquire) >= stall_timeout_ms
            && self.stalled_at_consumed_bytes.load(Ordering::Relaxed) == self.consumed_bytes.load(Ordering::Relaxed)
    }

    /// Marks the child process exit as observed, and returns whether input was dropped before.
    fn record_child_exit(&self) -> bool {
        self.input_state
            .compare_exchange(INPUT_ACCEPTED, CHILD_EXITED, Ordering::AcqRel, Ordering::Acquire)
            .is_err_and(|state| state == INPUT_OVERFLOWED)
    }
}

impl Drop for StdinBacklog {
    fn drop(&mut self) {
        // Frames that were never written to the child process are released with the backlog.
        self.total_pending_bytes
            .fetch_sub(*self.pending_bytes.get_mut(), Ordering::Relaxed);
    }
}

/// Records when the server connection holds back a child process output.
#[derive(Debug, Default)]
struct OutputBackpressure {
    waiting_senders: AtomicUsize,
    observed: AtomicBool,
}

impl OutputBackpressure {
    async fn send(
        &self,
        outgoing_tx: &mpsc::Sender<AgentMessage>,
        message: AgentMessage,
    ) -> Result<(), SendError<AgentMessage>> {
        let message = match outgoing_tx.try_send(message) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Closed(message)) => return Err(SendError(message)),
            Err(TrySendError::Full(message)) => message,
        };

        self.observed.store(true, Ordering::Relaxed);
        self.waiting_senders.fetch_add(1, Ordering::Relaxed);
        let _waiting = DecrementOnDrop(&self.waiting_senders);

        outgoing_tx.send(message).await
    }

    /// Returns whether output was held back at any point since the previous call.
    fn take_observed(&self) -> bool {
        self.observed.swap(false, Ordering::Relaxed) || self.waiting_senders.load(Ordering::Relaxed) > 0
    }
}

struct DecrementOnDrop<'a>(&'a AtomicUsize);

impl Drop for DecrementOnDrop<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Aborts a task when dropped, so that pumps never outlive an aborted `run_process`.
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Detects a child process that stopped consuming its stdin.
struct StallWatchdog {
    limits: StdinLimits,
    backlog: Arc<StdinBacklog>,
    output: Arc<OutputBackpressure>,
    last_check: Instant,
    last_consumed_bytes: u64,
    /// How long at least the stall threshold made no progress.
    stalled_for: Duration,
    /// How long any unwritten input made no progress.
    pending_for: Duration,
}

impl StallWatchdog {
    fn new(limits: StdinLimits, backlog: Arc<StdinBacklog>, output: Arc<OutputBackpressure>) -> Self {
        Self {
            limits,
            backlog,
            output,
            last_check: Instant::now(),
            last_consumed_bytes: 0,
            stalled_for: Duration::ZERO,
            pending_for: Duration::ZERO,
        }
    }

    fn check_period(&self) -> Duration {
        (self.limits.stall_timeout / 4).clamp(Duration::from_millis(10), Duration::from_secs(1))
    }

    /// Returns why the child process is stalled, if it made no stdin progress for longer than a stall timeout.
    fn check(&mut self) -> Option<Stall> {
        let now = Instant::now();
        let elapsed = now - self.last_check;
        self.last_check = now;

        let consumed_bytes = self.backlog.consumed_bytes.load(Ordering::Relaxed);
        let progressed = consumed_bytes != self.last_consumed_bytes;
        self.last_consumed_bytes = consumed_bytes;

        let output_held_back = self.output.take_observed();

        let unwritten_bytes = self.backlog.unwritten_bytes.load(Ordering::Relaxed);
        let backlog_full = unwritten_bytes > 0
            && unwritten_bytes + self.limits.pipe_allowance_bytes >= self.limits.stall_threshold_bytes;

        if progressed || unwritten_bytes == 0 {
            self.stalled_for = Duration::ZERO;
            self.pending_for = Duration::ZERO;
        } else {
            if !backlog_full {
                self.stalled_for = Duration::ZERO;
            } else if !output_held_back {
                self.stalled_for += elapsed;
            }

            if !output_held_back {
                self.pending_for += elapsed;
            }
        }

        self.backlog
            .stalled_at_consumed_bytes
            .store(consumed_bytes, Ordering::Relaxed);
        self.backlog.stalled_for_ms.store(
            u64::try_from(self.pending_for.as_millis()).unwrap_or(u64::MAX),
            Ordering::Release,
        );

        if self.stalled_for >= self.limits.stall_timeout {
            Some(Stall::LargeBacklog)
        } else if self.pending_for >= self.limits.pending_stall_timeout {
            Some(Stall::PendingInput)
        } else {
            None
        }
    }

    /// Stops supervising the stream, which can then no longer be stopped to make room for other streams.
    fn stop(&self) {
        self.backlog.stalled_for_ms.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct ProcessRegistry {
    inner: Arc<Mutex<ProcessRegistryInner>>,
    limits: StdinLimits,
    total_pending_bytes: Arc<AtomicUsize>,
}

#[derive(Debug, Default)]
struct ProcessRegistryInner {
    streams: HashMap<String, StreamEntry>,
    processes: HashMap<String, ProcessEntry>,
    last_registration: u64,
}

/// Keeps the stream ID reserved until its process completes, so that its output cannot be mistaken for another
/// process output.
#[derive(Debug)]
struct StreamEntry {
    registration: u64,
    /// `None` once the input is closed.
    stdin: Option<mpsc::UnboundedSender<StreamData>>,
    backlog: Arc<StdinBacklog>,
    stop: StopSender,
}

#[derive(Debug)]
struct ProcessEntry {
    registration: u64,
    stop: StopSender,
}

/// Channels of a registered process, consumed by [`run_process`].
#[derive(Debug)]
pub(super) struct ProcessChannels {
    registration: u64,
    stdin: mpsc::UnboundedReceiver<StreamData>,
    backlog: Arc<StdinBacklog>,
    control: watch::Receiver<Option<StopRequest>>,
}

impl ProcessRegistry {
    #[cfg(test)]
    fn new(limits: StdinLimits) -> Self {
        Self {
            inner: Arc::default(),
            limits,
            total_pending_bytes: Arc::default(),
        }
    }

    /// Registers a process and its stdin stream.
    ///
    /// Identifiers already in use are rejected rather than replaced, so that a duplicate request cannot detach a
    /// running process from its stop requests and input.
    pub(super) async fn register(&self, correlation_id: &str, stream_id: &str) -> anyhow::Result<ProcessChannels> {
        let mut inner = self.inner.lock().await;
        anyhow::ensure!(
            !inner.processes.contains_key(correlation_id),
            "correlation ID {correlation_id} is already in use"
        );
        anyhow::ensure!(
            !inner.streams.contains_key(stream_id),
            "stream ID {stream_id} is already in use"
        );

        inner.last_registration += 1;
        let registration = inner.last_registration;
        let (stdin_tx, stdin_rx) = mpsc::unbounded_channel();
        let (control_tx, control_rx) = watch::channel(None);
        let control_tx = Arc::new(control_tx);
        let backlog = Arc::new(StdinBacklog::new(Arc::clone(&self.total_pending_bytes)));

        inner.streams.insert(
            stream_id.to_owned(),
            StreamEntry {
                registration,
                stdin: Some(stdin_tx),
                backlog: Arc::clone(&backlog),
                stop: Arc::clone(&control_tx),
            },
        );
        inner.processes.insert(
            correlation_id.to_owned(),
            ProcessEntry {
                registration,
                stop: control_tx,
            },
        );

        Ok(ProcessChannels {
            registration,
            stdin: stdin_rx,
            backlog,
            control: control_rx,
        })
    }

    /// Queues a frame for the child process stdin without waiting.
    ///
    /// All streams share the server connection, so waiting for one child process to drain its stdin would stall
    /// every other stream and control message. A stream whose backlog exceeds the limit is failed instead.
    pub(super) async fn dispatch_stream_data(&self, stream_data: StreamData) {
        let mut inner = self.inner.lock().await;
        dispatch_locked(&mut inner, self.limits, &self.total_pending_bytes, stream_data);
    }

    pub(super) async fn stop_process(&self, correlation_id: &str, kill_process: bool) {
        // The process stays registered until it completes, so its correlation ID cannot be reused before its
        // ProcessCompleted message is sent.
        let request = if kill_process {
            StopRequest::Kill
        } else {
            StopRequest::Graceful
        };

        // Recorded while holding the lock, so that a concurrent dispatch cannot stop the stream to make room in the
        // stdin budget after it was found without a stop request.
        if let Some(entry) = self.inner.lock().await.processes.get(correlation_id) {
            request_stop(&entry.stop, request);
        }
    }

    /// Closes the stream input on server request; the child process sees the end of its stdin.
    pub(super) async fn close_stream(&self, stream_id: &str) {
        if let Some(entry) = self.inner.lock().await.streams.get_mut(stream_id) {
            entry.stdin = None;
        }
    }

    async fn close_registered_input(&self, stream_id: &str, registration: u64) {
        if let Some(entry) = self
            .inner
            .lock()
            .await
            .streams
            .get_mut(stream_id)
            .filter(|entry| entry.registration == registration)
        {
            entry.stdin = None;
        }
    }

    async fn unregister(&self, correlation_id: &str, stream_id: &str, registration: u64) {
        let mut inner = self.inner.lock().await;
        if inner
            .streams
            .get(stream_id)
            .is_some_and(|entry| entry.registration == registration)
        {
            inner.streams.remove(stream_id);
        }
        if inner
            .processes
            .get(correlation_id)
            .is_some_and(|entry| entry.registration == registration)
        {
            inner.processes.remove(correlation_id);
        }
    }
}

fn dispatch_locked(
    inner: &mut ProcessRegistryInner,
    limits: StdinLimits,
    total_pending_bytes: &AtomicUsize,
    stream_data: StreamData,
) {
    let frame_bytes = frame_charge(&stream_data);

    let Some(entry) = inner.streams.get(&stream_data.stream_id) else {
        return;
    };
    // Input received after the stream input was closed, or once the stdin pump is gone, is dropped without making
    // room for it in the stdin budget.
    match &entry.stdin {
        None => return,
        Some(stdin) if stdin.is_closed() => {
            if let Some(entry) = inner.streams.get_mut(&stream_data.stream_id) {
                entry.stdin = None;
            }
            return;
        }
        Some(_) => {}
    }
    let within_limits = entry
        .backlog
        .pending_bytes
        .load(Ordering::Relaxed)
        .saturating_add(frame_bytes)
        <= limits.max_buffered_bytes
        && reserve_total_budget(inner, limits, total_pending_bytes, &stream_data.stream_id, frame_bytes);

    let Some(entry) = inner.streams.get_mut(&stream_data.stream_id) else {
        return;
    };
    let Some(stdin) = &entry.stdin else {
        return;
    };
    let end_of_stream = stream_data.end_of_stream;

    let keep_input = if within_limits {
        // Charged before sending, so the stdin pump never releases a frame that is not charged yet.
        entry.backlog.add_pending(frame_bytes);
        if stdin.send(stream_data).is_ok() {
            !end_of_stream
        } else {
            entry.backlog.cancel_pending(frame_bytes);
            false
        }
    } else {
        if entry.backlog.record_overflow() {
            request_stop(&entry.stop, StopRequest::StdinOverflow);
        }
        false
    };

    // Close the input after the last frame, when the stdin pump is gone, or when the backlog overflows.
    if !keep_input {
        entry.stdin = None;
    }
}

/// Returns whether a frame for `stream_id` fits in [`StdinLimits::max_total_buffered_bytes`].
///
/// When it does not, stalled streams are stopped, starting with the one charged the most stdin memory, until the
/// frame fits. A stalled stream is preferred over the stream receiving input, which may be healthy. The frame does not
/// fit if no other stalled stream is left.
///
/// Input held by streams already stopped for exceeding a limit is not counted, because it is released as soon as
/// their child process is killed. Usage can therefore exceed the budget briefly.
fn reserve_total_budget(
    inner: &mut ProcessRegistryInner,
    limits: StdinLimits,
    total_pending_bytes: &AtomicUsize,
    stream_id: &str,
    frame_bytes: usize,
) -> bool {
    loop {
        let total_pending_bytes = total_pending_bytes.load(Ordering::Relaxed);
        if total_pending_bytes.saturating_add(frame_bytes) <= limits.max_total_buffered_bytes {
            return true;
        }

        let releasing_bytes: usize = inner
            .streams
            .values()
            .filter(|entry| entry.backlog.input_state.load(Ordering::Acquire) == INPUT_OVERFLOWED)
            .map(|entry| entry.backlog.pending_bytes.load(Ordering::Relaxed))
            .sum();
        if total_pending_bytes
            .saturating_sub(releasing_bytes)
            .saturating_add(frame_bytes)
            <= limits.max_total_buffered_bytes
        {
            return true;
        }

        let Some((stalled_stream_id, stalled)) = inner
            .streams
            .iter_mut()
            // A stream already being stopped keeps its outcome.
            .filter(|(_, entry)| entry.stop.borrow().is_none() && entry.backlog.is_evictable(limits))
            // Partly written frames stay fully charged, so the charge rather than the unwritten bytes is what is freed.
            .max_by_key(|(_, entry)| entry.backlog.pending_bytes.load(Ordering::Relaxed))
        else {
            return false;
        };

        if stalled_stream_id == stream_id {
            return false;
        }

        if stalled.backlog.record_overflow() {
            warn!(
                stream_id = %stalled_stream_id,
                pending_bytes = stalled.backlog.pending_bytes.load(Ordering::Relaxed),
                max_total_buffered_bytes = limits.max_total_buffered_bytes,
                "Stopping stalled PSU gRPC stream to make room in the stdin budget"
            );
            request_stop(&stalled.stop, StopRequest::StdinOverflow);
        }
        stalled.stdin = None;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_process(
    request: StartProcess,
    channels: ProcessChannels,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    registry: ProcessRegistry,
    agent_id: String,
    connection_id: String,
    default_executable: String,
) -> anyhow::Result<()> {
    let correlation_id = request.correlation_id.clone();
    let stream_id = request.stream_id.clone();
    let registration = channels.registration;

    let result = run_process_inner(
        request,
        channels,
        outgoing_tx,
        &registry,
        agent_id,
        connection_id,
        default_executable,
    )
    .await;

    registry.unregister(&correlation_id, &stream_id, registration).await;

    result
}

#[allow(clippy::too_many_arguments)]
async fn run_process_inner(
    request: StartProcess,
    channels: ProcessChannels,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    registry: &ProcessRegistry,
    agent_id: String,
    connection_id: String,
    default_executable: String,
) -> anyhow::Result<()> {
    let ProcessChannels {
        registration,
        stdin: stdin_rx,
        backlog,
        control: mut control_rx,
    } = channels;
    let limits = registry.limits;

    let executable = if request.executable.trim().is_empty() {
        default_executable
    } else {
        request.executable.clone()
    };

    info!(correlation_id = %request.correlation_id, executable = %executable, arguments = ?request.arguments, "Starting PSU gRPC child process");

    let mut command = Command::new(&executable);
    command
        .args(&request.arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if !request.working_directory.trim().is_empty() && std::path::Path::new(&request.working_directory).is_dir() {
        command.current_dir(&request.working_directory);
    }

    for (key, value) in &request.environment {
        command.env(key, value);
    }

    ProcessTree::prepare(&mut command);

    let started = async {
        let mut child = command.spawn()?;
        let process_tree = ProcessTree::attach(&mut child).await?;
        anyhow::Ok((child, process_tree))
    }
    .await
    .with_context(|| format!("failed to start PSU gRPC child process using {executable}"));
    let (mut child, mut process_tree) = match started {
        Ok(started) => started,
        Err(error) => {
            report_start_failure(&outgoing_tx, &agent_id, &connection_id, &request, &error).await;
            return Err(error);
        }
    };
    let process_id_u32 = child.id().unwrap_or(0);
    let process_id = i32::try_from(process_id_u32).unwrap_or(i32::MAX);

    let stdin = child.stdin.take().context("child process stdin was not piped")?;
    let stdout = child.stdout.take().context("child process stdout was not piped")?;
    let stderr = child.stderr.take().context("child process stderr was not piped")?;

    // Output is held back until ProcessStarted is sent, so that the server sees it first.
    let (process_started_tx, process_started_rx) = watch::channel(false);
    let output_backpressure = Arc::new(OutputBackpressure::default());
    let stdout_task = tokio::spawn(after_process_started(
        process_started_rx.clone(),
        pump_stdout_to_server(
            stdout,
            request.stream_id.clone(),
            outgoing_tx.clone(),
            Arc::clone(&output_backpressure),
            agent_id.clone(),
            connection_id.clone(),
            process_id,
        ),
    ));
    let stderr_task = tokio::spawn(after_process_started(
        process_started_rx,
        pump_stderr_diagnostics(
            stderr,
            outgoing_tx.clone(),
            Arc::clone(&output_backpressure),
            agent_id.clone(),
            connection_id.clone(),
            process_id,
        ),
    ));
    let mut stdin_task = tokio::spawn(pump_server_to_stdin(stdin_rx, stdin, Arc::clone(&backlog), process_id));
    let _abort_pumps = [
        stdout_task.abort_handle(),
        stderr_task.abort_handle(),
        stdin_task.abort_handle(),
    ]
    .map(AbortOnDrop);

    let mut watchdog = StallWatchdog::new(limits, Arc::clone(&backlog), Arc::clone(&output_backpressure));
    let mut watchdog_interval = tokio::time::interval(watchdog.check_period());
    watchdog_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Sent while the child process is supervised, so that stop requests apply even if the server connection holds
    // the message back. Waiting for it counts as held back output, so it does not count toward a stall.
    let send_process_started = output_backpressure.send(
        &outgoing_tx,
        agent_message(
            &agent_id,
            &connection_id,
            AgentPayload::ProcessStarted(ProcessStarted {
                correlation_id: request.correlation_id.clone(),
                process_id,
            }),
        ),
    );
    tokio::pin!(send_process_started);
    let mut process_started_sent = false;

    let mut stdin_task_completed = false;
    let mut control_open = true;
    let mut graceful_stop_requested = false;
    let mut exit_deadline = None;
    let mut kill_reason = None;

    // Every branch returns promptly, so stop requests are handled while waiting for the child process to exit.
    let status = loop {
        tokio::select! {
            // Stop requests come first, so that a stop requested by the server is not reported as a stall.
            biased;

            stop_request = control_rx.changed(), if control_open => match stop_request.map(|()| *control_rx.borrow_and_update()) {
                Ok(Some(StopRequest::Kill)) => {
                    info!(process_id, correlation_id = %request.correlation_id, "Killing PSU gRPC child process on server request");
                    kill_reason = Some(KillReason::ServerRequest);
                    break kill_process_tree(&mut child, &mut process_tree).await?;
                }
                Ok(Some(StopRequest::StdinOverflow)) => {
                    warn!(
                        process_id,
                        correlation_id = %request.correlation_id,
                        max_buffered_bytes = limits.max_buffered_bytes,
                        max_total_buffered_bytes = limits.max_total_buffered_bytes,
                        "Killing PSU gRPC child process because its stdin backlog exceeded a limit"
                    );
                    kill_reason = Some(KillReason::StdinOverflow);
                    break kill_process_tree(&mut child, &mut process_tree).await?;
                }
                Ok(Some(StopRequest::Graceful)) => {
                    if !graceful_stop_requested {
                        info!(process_id, correlation_id = %request.correlation_id, "Gracefully stopping PSU gRPC child process by closing stdin");
                        graceful_stop_requested = true;
                        if !stdin_task_completed {
                            stdin_task.abort();
                            let _ = (&mut stdin_task).await;
                            stdin_task_completed = true;
                            // Input left unwritten by the aborted pump is not a stall.
                            watchdog.stop();
                        }
                        exit_deadline.get_or_insert_with(|| Instant::now() + GRACEFUL_EXIT_TIMEOUT);
                    }
                }
                Ok(None) => {}
                // All stop request senders are gone; stop polling the closed channel.
                Err(_) => control_open = false,
            },
            result = &mut send_process_started, if !process_started_sent => {
                result.context("failed to send PSU gRPC ProcessStarted message")?;
                process_started_sent = true;
                process_started_tx.send_replace(true);
            }
            status = child.wait() => break status.context("failed to wait for PSU gRPC child process")?,
            _ = &mut stdin_task, if !stdin_task_completed => {
                stdin_task_completed = true;
                watchdog.stop();
                info!(process_id, "Finished receiving PSU gRPC stdin data; waiting for graceful child process exit");
                exit_deadline.get_or_insert_with(|| Instant::now() + GRACEFUL_EXIT_TIMEOUT);
            }
            () = sleep_until(exit_deadline) => {
                warn!(process_id, "PSU gRPC child process did not exit after stdin closed; killing child process");
                kill_reason = Some(KillReason::ExitTimeout);
                break kill_process_tree(&mut child, &mut process_tree).await?;
            }
            // Only input that the stdin pump is still writing can stall.
            _ = watchdog_interval.tick(), if !stdin_task_completed => {
                // A stop request recorded since the control channel was polled is handled on the next iteration
                // instead, so that it is not reported as a stall.
                if let Some(stall) = watchdog.check()
                    && control_rx.borrow().is_none()
                {
                    warn!(
                        process_id,
                        correlation_id = %request.correlation_id,
                        ?stall,
                        "Killing PSU gRPC child process because its stdin backlog made no progress"
                    );
                    kill_reason = Some(KillReason::StdinStalled(stall));
                    break kill_process_tree(&mut child, &mut process_tree).await?;
                }
            }
        }
    };

    // A stop request can be recorded while the child process exit is being selected; it still applies.
    if kill_reason.is_none() {
        match *control_rx.borrow_and_update() {
            Some(StopRequest::Kill) => kill_reason = Some(KillReason::ServerRequest),
            Some(StopRequest::StdinOverflow) => kill_reason = Some(KillReason::StdinOverflow),
            Some(StopRequest::Graceful) => graceful_stop_requested = true,
            None => {}
        }
    }

    // Input that arrives once the child process has exited could not be delivered anyway, so only an overflow
    // recorded before this point counts. This is decided atomically, before anything is awaited.
    let stdin_overflowed = backlog.record_child_exit();
    registry.close_registered_input(&request.stream_id, registration).await;
    let stdin_closed_from_end_of_stream = backlog.end_of_stream.load(Ordering::Relaxed);

    // Only a child process that exited on its own, with all of its input delivered, leaves its background processes
    // running.
    if kill_reason.is_none() && !graceful_stop_requested && !stdin_overflowed {
        process_tree.release();
    } else {
        process_tree.terminate();
    }

    if !stdin_task_completed {
        stdin_task.abort();
        let _ = stdin_task.await;
    }

    // The input is closed and the stdin pump is gone, so frames still queued were dropped. Release their charge now
    // rather than after output delivery, which can be held back by the server connection.
    backlog.release_remaining();

    if !process_started_sent {
        send_process_started
            .await
            .context("failed to send PSU gRPC ProcessStarted message")?;
        process_started_tx.send_replace(true);
    }

    await_pump_task(stdout_task, process_id, "stdout").await;
    await_pump_task(stderr_task, process_id, "stderr").await;

    let exit_code = status.code().unwrap_or(-1);
    let expected_pwsh_exit = stdin_closed_from_end_of_stream && exit_code == PWSH_STDIN_CLOSED_EXIT_CODE;
    if expected_pwsh_exit {
        info!(
            process_id,
            exit_code, "PSU gRPC child process exited with expected code after stdin EOF for pwsh -s"
        );
    } else {
        info!(process_id, exit_code, "PSU gRPC child process exited");
    }

    // Reflect the actual outcome so the server can distinguish success from
    // cancellation or a non-zero exit based on the StreamClosed message.
    let canceled = kill_reason.is_some() || graceful_stop_requested || stdin_overflowed;
    let stream_error = canceled || (exit_code != 0 && !expected_pwsh_exit);
    let stream_reason = if kill_reason == Some(KillReason::StdinStalled(Stall::LargeBacklog)) {
        format!(
            "no stdin consumed for {:?} while at least {} was unread",
            limits.stall_timeout,
            format_bytes(limits.stall_threshold_bytes)
        )
    } else if kill_reason == Some(KillReason::StdinStalled(Stall::PendingInput)) {
        format!(
            "no stdin consumed for {:?} while input was unread",
            limits.pending_stall_timeout
        )
    } else if kill_reason == Some(KillReason::StdinOverflow) || stdin_overflowed {
        format!(
            "stdin backlog limit exceeded ({} per job, {} for all jobs)",
            format_bytes(limits.max_buffered_bytes),
            format_bytes(limits.max_total_buffered_bytes)
        )
    } else if canceled {
        "child process canceled".to_owned()
    } else if stream_error {
        format!("child process exited with code {exit_code}")
    } else {
        "child process completed".to_owned()
    };

    let _ = outgoing_tx
        .send(agent_message(
            &agent_id,
            &connection_id,
            AgentPayload::StreamClosed(stream_closed(request.stream_id.clone(), stream_reason, stream_error)),
        ))
        .await;

    send_process_completed(
        &outgoing_tx,
        &agent_id,
        &connection_id,
        &request.correlation_id,
        exit_code,
        canceled,
        String::new(),
    )
    .await
    .context("failed to send PSU gRPC ProcessCompleted message")?;

    Ok(())
}

/// Reports a child process that could not be started.
async fn report_start_failure(
    outgoing_tx: &mpsc::Sender<AgentMessage>,
    agent_id: &str,
    connection_id: &str,
    request: &StartProcess,
    error: &anyhow::Error,
) {
    let error_message = format!("{error:#}");
    let _ = outgoing_tx
        .send(agent_message(
            agent_id,
            connection_id,
            AgentPayload::StreamClosed(stream_closed(request.stream_id.clone(), error_message.clone(), true)),
        ))
        .await;
    let _ = send_process_completed(
        outgoing_tx,
        agent_id,
        connection_id,
        &request.correlation_id,
        -1,
        false,
        error_message,
    )
    .await;
}

/// Runs an output pump once ProcessStarted is sent.
async fn after_process_started(
    mut process_started: watch::Receiver<bool>,
    pump: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    process_started
        .wait_for(|sent| *sent)
        .await
        .context("ProcessStarted was not sent")?;
    pump.await
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

async fn kill_process_tree(child: &mut Child, process_tree: &mut ProcessTree) -> anyhow::Result<ExitStatus> {
    process_tree.terminate();

    // Covers the case where the process tree could not be tracked.
    if let Err(error) = child.start_kill() {
        debug!(%error, "Failed to kill PSU gRPC child process directly");
    }

    child
        .wait()
        .await
        .context("failed to wait for killed PSU gRPC child process")
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{bytes} bytes")
    }
}

async fn await_pump_task(mut task: JoinHandle<anyhow::Result<()>>, process_id: i32, stream_name: &'static str) {
    tokio::select! {
        result = &mut task => match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(process_id, stream_name, error = format!("{error:#}"), "PSU gRPC child stream pump failed"),
            Err(error) => warn!(process_id, stream_name, %error, "PSU gRPC child stream pump panicked"),
        },
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            warn!(process_id, stream_name, "Timed out draining PSU gRPC child stream pump");
            task.abort();
            let _ = task.await;
        }
    }
}

/// Reports a `StartProcess` request that was not started because its identifiers are already in use.
///
/// Only a diagnostic is sent: `StreamClosed` or `ProcessCompleted` would carry the same identifiers and could be
/// mistaken for the outcome of the process that is already running.
pub(super) async fn report_rejected_start(
    outgoing_tx: &mpsc::Sender<AgentMessage>,
    agent_id: &str,
    connection_id: &str,
    error: &anyhow::Error,
) {
    let _ = outgoing_tx
        .send(agent_message(
            agent_id,
            connection_id,
            AgentPayload::Diagnostic(diagnostic("error", format!("rejected StartProcess: {error:#}"))),
        ))
        .await;
}

async fn send_process_completed(
    outgoing_tx: &mpsc::Sender<AgentMessage>,
    agent_id: &str,
    connection_id: &str,
    correlation_id: &str,
    exit_code: i32,
    canceled: bool,
    error_message: String,
) -> anyhow::Result<()> {
    outgoing_tx
        .send(agent_message(
            agent_id,
            connection_id,
            AgentPayload::ProcessCompleted(ProcessCompleted {
                correlation_id: correlation_id.to_owned(),
                exit_code,
                canceled,
                error_message,
            }),
        ))
        .await
        .context("failed to send PSU gRPC ProcessCompleted message")
}

async fn pump_stdout_to_server<R>(
    mut stdout: R,
    stream_id: String,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    backpressure: Arc<OutputBackpressure>,
    agent_id: String,
    connection_id: String,
    process_id: i32,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0u8; 4096];
    let mut line = Vec::new();
    let mut sequence = 0;

    let send_frame = |sequence, data, end_of_stream| {
        let message = agent_message(
            &agent_id,
            &connection_id,
            AgentPayload::StreamData(stream_data(stream_id.clone(), sequence, data, end_of_stream)),
        );
        let outgoing_tx = &outgoing_tx;
        let backpressure = &backpressure;
        async move {
            backpressure
                .send(outgoing_tx, message)
                .await
                .context("failed to send PSU gRPC stdout frame")
        }
    };

    loop {
        let read = stdout.read(&mut buffer).await.context("failed to read child stdout")?;
        if read == 0 {
            break;
        }

        for byte in &buffer[..read] {
            match *byte {
                b'\r' => {}
                b'\n' => {
                    send_frame(sequence, std::mem::take(&mut line), false).await?;
                    sequence += 1;
                }
                byte => line.push(byte),
            }
        }
    }

    if !line.is_empty() {
        send_frame(sequence, line, false).await?;
        sequence += 1;
    }

    send_frame(sequence, Vec::new(), true).await?;
    info!(process_id, stream_id = %stream_id, sequence, "Finished sending PSU gRPC stdout frames");
    Ok(())
}

async fn pump_server_to_stdin(
    mut incoming_rx: mpsc::UnboundedReceiver<StreamData>,
    mut stdin: ChildStdin,
    backlog: Arc<StdinBacklog>,
    process_id: i32,
) {
    while let Some(frame) = incoming_rx.recv().await {
        if frame.end_of_stream {
            backlog.release(frame_charge(&frame));
            info!(process_id, "Received PSU gRPC stdin end-of-stream; closing child stdin");
            // Recorded before stdin is closed, so it is visible by the time the child process exits.
            backlog.end_of_stream.store(true, Ordering::Relaxed);
            break;
        }

        let result = write_stdin_frame(&mut stdin, &frame, &backlog).await;
        // The frame memory is retained until here, even when parts of it were already written.
        backlog.release(frame_charge(&frame));
        drop(frame);

        if let Err(error) = result {
            warn!(process_id, %error, "Failed to write PSU gRPC frame to child stdin");
            break;
        }
    }

    let _ = stdin.shutdown().await;
}

async fn write_stdin_frame(stdin: &mut ChildStdin, frame: &StreamData, backlog: &StdinBacklog) -> std::io::Result<()> {
    // Every partial write counts as progress, so a child process that reads slowly is not considered stalled.
    for chunk in frame.data.chunks(STDIN_WRITE_CHUNK_SIZE) {
        let mut chunk = chunk;
        while !chunk.is_empty() {
            let written = stdin.write(chunk).await?;
            if written == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            backlog.record_progress(written);
            chunk = &chunk[written..];
        }
    }

    if !ends_with_line_ending(&frame.data) {
        stdin.write_all(b"\n").await?;
    }
    stdin.flush().await?;

    // Writing an empty frame counts as progress too.
    backlog.record_progress(frame_charge(frame) - frame.data.len());

    Ok(())
}

async fn pump_stderr_diagnostics<R>(
    stderr: R,
    outgoing_tx: mpsc::Sender<AgentMessage>,
    backpressure: Arc<OutputBackpressure>,
    agent_id: String,
    connection_id: String,
    process_id: i32,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut lines = BufReader::new(stderr).lines();
    while let Some(line) = lines.next_line().await.context("failed to read child stderr")? {
        if line.trim().is_empty() {
            continue;
        }

        backpressure
            .send(
                &outgoing_tx,
                agent_message(
                    &agent_id,
                    &connection_id,
                    AgentPayload::Diagnostic(diagnostic("warning", format!("pwsh[{process_id}] {line}"))),
                ),
            )
            .await
            .context("failed to send PSU gRPC stderr diagnostic")?;
    }

    Ok(())
}

fn ends_with_line_ending(data: &[u8]) -> bool {
    data.ends_with(b"\n") || data.ends_with(b"\r")
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    const LIMITS_FOR_TESTS: StdinLimits = StdinLimits {
        stall_threshold_bytes: 64 * 1024,
        pipe_allowance_bytes: 0,
        stall_timeout: Duration::from_millis(300),
        pending_stall_timeout: Duration::from_secs(60),
        max_buffered_bytes: 64 * MIB,
        max_total_buffered_bytes: 256 * MIB,
    };

    /// Writes a script that runs `windows` with cmd.exe on Windows, or `unix` with sh elsewhere.
    ///
    /// On Unix, scripts are passed to sh instead of being executed: a script that was just written fails to execute
    /// with ETXTBSY while a process forked concurrently by another test still holds the write handle.
    fn write_script(dir: &Path, name: &str, windows: &str, unix: &str) -> PathBuf {
        if cfg!(windows) {
            let path = dir.join(format!("{name}.cmd"));
            std::fs::write(&path, windows.replace('\n', "\r\n")).expect("write script");
            path
        } else {
            let path = dir.join(format!("{name}.sh"));
            std::fs::write(&path, unix).expect("write script");
            path
        }
    }

    /// A child process that waits `seconds` without reading stdin or writing output.
    fn sleeping_script(dir: &Path, seconds: u32) -> PathBuf {
        write_script(
            dir,
            "sleep",
            &format!("@ping -n {} 127.0.0.1 >nul\n", seconds + 1),
            &format!("sleep {seconds}\n"),
        )
    }

    /// A child process that prints `started`, then copies stdin lines to stdout after an optional delay.
    fn echo_script(dir: &Path, delay_seconds: u32) -> PathBuf {
        let (windows_delay, unix_delay) = if delay_seconds == 0 {
            (String::new(), String::new())
        } else {
            (
                format!("@ping -n {} 127.0.0.1 >nul\n", delay_seconds + 1),
                format!("sleep {delay_seconds}\n"),
            )
        };

        write_script(
            dir,
            "echo",
            &format!("@echo started\n{windows_delay}@findstr \"^\"\n"),
            &format!("echo started\n{unix_delay}exec cat\n"),
        )
    }

    /// Lines of the size sent by the tests, excluding markers printed by the scripts.
    fn data_lines(outcome: &Outcome) -> usize {
        outcome.stdout_lines.iter().filter(|line| line.len() == 1023).count()
    }

    fn start_request(id: &str, script: &Path) -> StartProcess {
        let script = script.to_string_lossy().into_owned();
        let (executable, arguments) = if cfg!(windows) {
            (script, Vec::new())
        } else {
            ("/bin/sh".to_owned(), vec![script])
        };

        StartProcess {
            correlation_id: id.to_owned(),
            stream_id: id.to_owned(),
            executable,
            arguments,
            working_directory: String::new(),
            environment: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    async fn spawn_process(
        registry: &ProcessRegistry,
        request: StartProcess,
        outgoing_capacity: usize,
    ) -> (JoinHandle<anyhow::Result<()>>, mpsc::Receiver<AgentMessage>) {
        let channels = registry
            .register(&request.correlation_id, &request.stream_id)
            .await
            .expect("register process");
        spawn_with_channels(registry, request, channels, outgoing_capacity)
    }

    fn spawn_with_channels(
        registry: &ProcessRegistry,
        request: StartProcess,
        channels: ProcessChannels,
        outgoing_capacity: usize,
    ) -> (JoinHandle<anyhow::Result<()>>, mpsc::Receiver<AgentMessage>) {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(outgoing_capacity);
        let task = tokio::spawn(run_process(
            request,
            channels,
            outgoing_tx,
            registry.clone(),
            "agent-id".to_owned(),
            "connection-id".to_owned(),
            "pwsh".to_owned(),
        ));
        (task, outgoing_rx)
    }

    async fn wait_for_process_started(outgoing_rx: &mut mpsc::Receiver<AgentMessage>) {
        loop {
            let message = outgoing_rx.recv().await.expect("outgoing channel closed");
            if matches!(message.payload, Some(AgentPayload::ProcessStarted(_))) {
                return;
            }
        }
    }

    struct Outcome {
        stdout_lines: Vec<Vec<u8>>,
        stream_closed: crate::psu_agent::protocol::StreamClosed,
        completed: ProcessCompleted,
    }

    async fn collect_outcome(
        task: JoinHandle<anyhow::Result<()>>,
        mut outgoing_rx: mpsc::Receiver<AgentMessage>,
        timeout: Duration,
    ) -> Outcome {
        tokio::time::timeout(timeout, async move {
            let mut stdout_lines = Vec::new();
            let mut stream_closed = None;
            let mut completed = None;

            while let Some(message) = outgoing_rx.recv().await {
                match message.payload {
                    Some(AgentPayload::StreamData(data)) if !data.end_of_stream => stdout_lines.push(data.data),
                    Some(AgentPayload::StreamClosed(closed)) => stream_closed = Some(closed),
                    Some(AgentPayload::ProcessCompleted(process_completed)) => completed = Some(process_completed),
                    _ => {}
                }
            }

            task.await.expect("process task panicked").expect("run process");

            Outcome {
                stdout_lines,
                stream_closed: stream_closed.expect("stream closed message"),
                completed: completed.expect("process completed message"),
            }
        })
        .await
        .expect("process did not complete in time")
    }

    async fn dispatch(registry: &ProcessRegistry, stream_id: &str, sequence: u64, data: Vec<u8>, end_of_stream: bool) {
        registry
            .dispatch_stream_data(stream_data(stream_id.to_owned(), sequence, data, end_of_stream))
            .await;
    }

    #[tokio::test]
    async fn stop_requests_keep_identifiers_reserved_until_the_process_completes() {
        let registry = ProcessRegistry::default();
        let mut channels = registry
            .register("correlation-id", "stream-id")
            .await
            .expect("register");

        registry.stop_process("correlation-id", false).await;
        channels.control.changed().await.expect("stop request");
        assert_eq!(*channels.control.borrow_and_update(), Some(StopRequest::Graceful));
        assert!(registry.inner.lock().await.processes.contains_key("correlation-id"));

        registry.stop_process("correlation-id", true).await;
        channels.control.changed().await.expect("stop request");
        assert_eq!(*channels.control.borrow_and_update(), Some(StopRequest::Kill));
        registry
            .register("correlation-id", "other-stream-id")
            .await
            .expect_err("a killed process keeps its correlation ID until it completes");

        registry
            .unregister("correlation-id", "stream-id", channels.registration)
            .await;
        registry
            .register("correlation-id", "stream-id")
            .await
            .expect("identifiers are released once the process completes");
    }

    #[tokio::test]
    async fn duplicate_identifiers_are_rejected_without_detaching_the_running_process() {
        let registry = ProcessRegistry::default();
        let mut channels = registry.register("process", "stream").await.expect("register");

        registry
            .register("process", "other-stream")
            .await
            .expect_err("duplicate correlation ID should be rejected");
        registry
            .register("other-process", "stream")
            .await
            .expect_err("duplicate stream ID should be rejected");

        dispatch(&registry, "stream", 0, b"data".to_vec(), false).await;
        assert_eq!(channels.stdin.try_recv().expect("stdin frame").data, b"data");

        registry.stop_process("process", true).await;
        assert_eq!(*channels.control.borrow_and_update(), Some(StopRequest::Kill));
    }

    #[tokio::test]
    async fn stdin_backlog_overflow_fails_only_that_stream() {
        let registry = ProcessRegistry::new(StdinLimits {
            max_buffered_bytes: 4 * 1024,
            ..LIMITS_FOR_TESTS
        });
        let mut stalled = registry.register("stalled", "stalled").await.expect("register");
        let mut healthy = registry.register("healthy", "healthy").await.expect("register");

        for sequence in 0..5 {
            dispatch(&registry, "stalled", sequence, vec![b'x'; 1024], false).await;
        }
        dispatch(&registry, "healthy", 0, b"data".to_vec(), false).await;

        assert_eq!(*stalled.control.borrow_and_update(), Some(StopRequest::StdinOverflow));
        assert!(stalled.backlog.input_state.load(Ordering::Relaxed) == INPUT_OVERFLOWED);
        assert!(registry.inner.lock().await.streams["stalled"].stdin.is_none());

        assert_eq!(healthy.stdin.try_recv().expect("healthy frame").data, b"data");
        assert!(healthy.control.borrow().is_none());
        assert!(registry.inner.lock().await.streams["healthy"].stdin.is_some());
    }

    #[tokio::test]
    async fn stdin_overflow_before_exit_is_reported_when_the_child_exits_successfully_first() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let marker = temp_dir.path().join("background-survived");
        let background = write_script(
            temp_dir.path(),
            "background",
            &format!("@ping -n 4 127.0.0.1 >nul\n@echo done> \"{}\"\n", marker.display()),
            &format!("sleep 3\ntouch '{}'\n", marker.display()),
        );
        // Starts a background process, then exits successfully right away.
        let script = write_script(
            temp_dir.path(),
            "exit",
            &format!("@start \"\" /B \"{}\"\n@exit /b 0\n", background.display()),
            &format!("sh '{}' &\nexit 0\n", background.display()),
        );
        let registry = ProcessRegistry::new(StdinLimits {
            max_buffered_bytes: 1024,
            ..LIMITS_FOR_TESTS
        });
        let request = start_request("job", &script);
        let mut channels = registry.register("job", "job").await.expect("register");

        dispatch(&registry, "job", 0, vec![b'x'; 2048], false).await;

        // Consume the notification to model a child process that exits before the stop request is read.
        assert_eq!(*channels.control.borrow_and_update(), Some(StopRequest::StdinOverflow));

        let (task, outgoing_rx) = spawn_with_channels(&registry, request, channels, 64);
        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(20)).await;

        assert!(outcome.stream_closed.error);
        assert!(
            outcome.stream_closed.reason.contains("stdin backlog limit exceeded"),
            "unexpected reason: {}",
            outcome.stream_closed.reason
        );
        assert!(outcome.completed.canceled);

        // A job that lost input is reported as canceled, so the processes it started are stopped too.
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!marker.exists(), "a process started by a job that lost input survived");
    }

    #[tokio::test]
    async fn partially_written_frame_stays_charged_until_dropped() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 30);
        let registry = ProcessRegistry::default();

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;

        let frame = stream_data("job".to_owned(), 0, vec![b'x'; 4 * MIB], false);
        let charge = frame_charge(&frame);
        registry.dispatch_stream_data(frame).await;

        // The child process never reads stdin, so the frame is only partly written once the pipe is full.
        let backlog = Arc::clone(&registry.inner.lock().await.streams["job"].backlog);
        tokio::time::timeout(Duration::from_secs(10), async {
            while backlog.consumed_bytes.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("no part of the frame was written");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(registry.total_pending_bytes.load(Ordering::Relaxed), charge);

        registry.stop_process("job", true).await;
        collect_outcome(task, outgoing_rx, Duration::from_secs(10)).await;
        drop(backlog);
        assert_eq!(registry.total_pending_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn stdin_overflow_after_the_child_exits_is_ignored() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        // The background process keeps stdout open, so output pumps are still draining after the child exits.
        let script = write_script(
            temp_dir.path(),
            "exit",
            "@start \"\" /B ping -n 4 127.0.0.1\n@exit /b 0\n",
            "sleep 3 &\nexit 0\n",
        );
        let registry = ProcessRegistry::new(StdinLimits {
            max_buffered_bytes: 1024,
            ..LIMITS_FOR_TESTS
        });

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        dispatch(&registry, "job", 0, vec![b'x'; 2048], false).await;

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(20)).await;
        assert!(!outcome.stream_closed.error, "{}", outcome.stream_closed.reason);
        assert!(!outcome.completed.canceled);
        assert_eq!(outcome.completed.exit_code, 0);
    }

    #[tokio::test]
    async fn burst_of_input_to_a_briefly_busy_child_is_delivered() {
        const LINES: usize = 1000;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = echo_script(temp_dir.path(), 1);
        let registry = ProcessRegistry::default();

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 4096).await;
        wait_for_process_started(&mut outgoing_rx).await;

        // About 1 MiB arrives while the child process is not reading yet, far more than the OS pipe buffer holds.
        for sequence in 0..LINES {
            let line = format!("{sequence:0>1023}").into_bytes();
            dispatch(
                &registry,
                "job",
                u64::try_from(sequence).expect("sequence"),
                line,
                false,
            )
            .await;
        }
        dispatch(&registry, "job", u64::MAX, Vec::new(), true).await;

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(30)).await;
        assert!(!outcome.stream_closed.error, "{}", outcome.stream_closed.reason);
        assert!(!outcome.completed.canceled);
        assert_eq!(data_lines(&outcome), LINES);
    }

    #[tokio::test]
    async fn slow_server_does_not_get_a_healthy_child_killed() {
        const LINES: usize = 2048;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = echo_script(temp_dir.path(), 0);
        let limits = StdinLimits {
            stall_timeout: Duration::from_secs(2),
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);

        // A single-message outgoing queue that is not read for a while models a server that reads slowly.
        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 1).await;
        wait_for_process_started(&mut outgoing_rx).await;

        // Wait until the process copying stdin runs, so its startup time is not mistaken for a stall. cat echoes
        // the ready line right away, while findstr buffers its output, so on Windows the script marker is used.
        dispatch(&registry, "job", 0, b"ready".to_vec(), false).await;
        let marker: &[u8] = if cfg!(windows) { b"started" } else { b"ready" };
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let message = outgoing_rx.recv().await.expect("outgoing channel closed");
                if matches!(message.payload, Some(AgentPayload::StreamData(data)) if data.data == marker) {
                    break;
                }
            }
        })
        .await
        .expect("child process did not start");

        for sequence in 0..LINES {
            let line = format!("{sequence:0>1023}").into_bytes();
            dispatch(
                &registry,
                "job",
                u64::try_from(sequence).expect("sequence"),
                line,
                false,
            )
            .await;
        }
        dispatch(&registry, "job", u64::MAX, Vec::new(), true).await;

        // Several stall timeouts elapse while the child process is blocked writing output.
        tokio::time::sleep(limits.stall_timeout * 3).await;

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(60)).await;
        assert!(!outcome.stream_closed.error, "{}", outcome.stream_closed.reason);
        assert!(!outcome.completed.canceled);
        assert_eq!(data_lines(&outcome), LINES);
    }

    #[tokio::test]
    async fn child_that_stops_consuming_stdin_is_killed_after_the_stall_timeout() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 30);
        let registry = ProcessRegistry::new(LIMITS_FOR_TESTS);

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;

        for sequence in 0..1024 {
            dispatch(&registry, "job", sequence, vec![b'x'; 1024], false).await;
        }

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(10)).await;
        assert!(outcome.stream_closed.error);
        assert!(
            outcome.stream_closed.reason.contains("no stdin consumed"),
            "unexpected reason: {}",
            outcome.stream_closed.reason
        );
        assert!(outcome.completed.canceled);
    }

    #[tokio::test]
    async fn kill_is_not_delayed_by_a_pending_graceful_stop() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 30);
        let registry = ProcessRegistry::default();

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;

        registry.stop_process("job", false).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        registry.stop_process("job", true).await;

        // The graceful stop alone would wait for GRACEFUL_EXIT_TIMEOUT before killing the child process.
        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(3)).await;
        assert!(outcome.completed.canceled);
    }

    #[tokio::test]
    async fn closed_stop_request_channel_does_not_end_the_process() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 1);
        let registry = ProcessRegistry::default();
        let channels = registry.register("job", "job").await.expect("register");

        // Drop every stop request sender.
        registry.unregister("job", "job", channels.registration).await;

        let (task, outgoing_rx) = spawn_with_channels(&registry, start_request("job", &script), channels, 64);
        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(20)).await;

        assert!(!outcome.completed.canceled);
        assert_eq!(outcome.completed.exit_code, 0);
    }

    #[tokio::test]
    async fn kill_terminates_processes_started_by_the_child() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let marker = temp_dir.path().join("grandchild-survived");
        let grandchild = write_script(
            temp_dir.path(),
            "grandchild",
            &format!("@ping -n 4 127.0.0.1 >nul\n@echo done> \"{}\"\n", marker.display()),
            &format!("sleep 3\ntouch '{}'\n", marker.display()),
        );
        let script = write_script(
            temp_dir.path(),
            "parent",
            &format!(
                "@start \"\" /B \"{}\"\n@ping -n 31 127.0.0.1 >nul\n",
                grandchild.display()
            ),
            &format!("sh '{}' &\nsleep 30\n", grandchild.display()),
        );
        let registry = ProcessRegistry::default();

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        registry.stop_process("job", true).await;
        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(10)).await;
        assert!(outcome.completed.canceled);

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            !marker.exists(),
            "a process started by the killed child process survived"
        );
    }

    #[tokio::test]
    async fn graceful_stop_terminates_processes_started_by_the_child() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let marker = temp_dir.path().join("grandchild-survived");
        let grandchild = write_script(
            temp_dir.path(),
            "grandchild",
            &format!("@ping -n 4 127.0.0.1 >nul\n@echo done> \"{}\"\n", marker.display()),
            &format!("sleep 3\ntouch '{}'\n", marker.display()),
        );
        // The parent exits on its own as soon as its stdin is closed.
        let script = write_script(
            temp_dir.path(),
            "parent",
            &format!("@start \"\" /B \"{}\"\n@findstr \"^\" >nul\n", grandchild.display()),
            &format!("sh '{}' &\ncat >/dev/null\n", grandchild.display()),
        );
        let registry = ProcessRegistry::default();

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let stopped_at = Instant::now();
        registry.stop_process("job", false).await;
        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(10)).await;
        let elapsed = stopped_at.elapsed();
        assert!(outcome.completed.canceled);

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            !marker.exists(),
            "a process started by the gracefully stopped child process survived (exit code {}, {elapsed:?})",
            outcome.completed.exit_code
        );
    }

    #[tokio::test]
    async fn empty_frames_count_toward_the_stdin_backlog_limit() {
        let registry = ProcessRegistry::new(StdinLimits {
            max_buffered_bytes: 64 * 1024,
            ..LIMITS_FOR_TESTS
        });
        let mut channels = registry.register("job", "job").await.expect("register");

        for sequence in 0..10_000 {
            dispatch(&registry, "job", sequence, Vec::new(), false).await;
        }

        assert_eq!(*channels.control.borrow_and_update(), Some(StopRequest::StdinOverflow));
        assert!(channels.backlog.input_state.load(Ordering::Relaxed) == INPUT_OVERFLOWED);
    }

    #[tokio::test]
    async fn expected_pwsh_exit_after_stdin_end_of_stream_is_not_an_error() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        // Like `pwsh -s`, exits with code 160 once stdin is closed.
        let script = write_script(
            temp_dir.path(),
            "server-mode",
            "@findstr \"^\" >nul\n@exit /b 160\n",
            "cat >/dev/null\nexit 160\n",
        );
        let registry = ProcessRegistry::default();

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;
        dispatch(&registry, "job", 0, Vec::new(), true).await;

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(20)).await;
        assert_eq!(outcome.completed.exit_code, PWSH_STDIN_CLOSED_EXIT_CODE);
        assert!(!outcome.stream_closed.error, "{}", outcome.stream_closed.reason);
        assert!(!outcome.completed.canceled);
    }

    #[tokio::test]
    async fn slowly_reading_child_is_not_killed() {
        const FRAMES: usize = 2;
        const LINES_PER_FRAME: usize = 64;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        // Reads one 1 KiB line every 50 ms, so writing a 64 KiB frame into a full Unix pipe takes twice the stall
        // timeout. On Windows, the pipe absorbs both frames, so the test only checks that slow reading is not
        // mistaken for a stall. The
        // reader handles a first line before reporting that it started, so loading the cmdlets it uses is not
        // mistaken for a stall.
        let script = write_script(
            temp_dir.path(),
            "slow-reader",
            "@powershell -NoLogo -NoProfile -NonInteractive -Command \"$null = [Console]::In.ReadLine(); Start-Sleep -Milliseconds 1; [Console]::Out.WriteLine('started'); [Console]::Out.Flush(); while ($null -ne [Console]::In.ReadLine()) { Start-Sleep -Milliseconds 50 }\"\n",
            "read -r line\necho started\nwhile IFS= read -r line; do sleep 0.05; done\n",
        );
        let limits = StdinLimits {
            stall_timeout: Duration::from_millis(1500),
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        dispatch(&registry, "job", 0, b"warm-up".to_vec(), false).await;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let message = outgoing_rx.recv().await.expect("outgoing channel closed");
                if matches!(message.payload, Some(AgentPayload::StreamData(data)) if data.data == b"started") {
                    break;
                }
            }
        })
        .await
        .expect("child process did not start");

        for sequence in 1..=FRAMES {
            let frame = (0..LINES_PER_FRAME)
                .flat_map(|line| format!("{line:0>1023}\n").into_bytes())
                .collect();
            dispatch(
                &registry,
                "job",
                u64::try_from(sequence).expect("sequence"),
                frame,
                false,
            )
            .await;
        }
        dispatch(&registry, "job", u64::MAX, Vec::new(), true).await;

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(60)).await;
        assert!(!outcome.stream_closed.error, "{}", outcome.stream_closed.reason);
        assert!(!outcome.completed.canceled);
    }
    #[tokio::test]
    async fn connection_stdin_budget_fails_the_stream_that_exceeds_it() {
        let registry = ProcessRegistry::new(StdinLimits {
            max_total_buffered_bytes: 16 * 1024,
            ..LIMITS_FOR_TESTS
        });
        let mut first = registry.register("first", "first").await.expect("register");
        let second = registry.register("second", "second").await.expect("register");

        for sequence in 0..12 {
            dispatch(&registry, "first", sequence, vec![b'x'; 1024], false).await;
        }
        for sequence in 0..6 {
            dispatch(&registry, "second", sequence, vec![b'x'; 1024], false).await;
        }

        // Each stream stays far below its own limit, but together they exceed the connection budget.
        assert!(first.control.borrow().is_none());
        assert_eq!(*second.control.borrow(), Some(StopRequest::StdinOverflow));

        // Input that was never written to a child process is released with its backlog.
        let registration = second.registration;
        drop(second);
        registry.unregister("second", "second", registration).await;
        while first.stdin.try_recv().is_ok() {}
        let pending = first.backlog.pending_bytes.load(Ordering::Relaxed);
        first.backlog.release(pending);
        assert_eq!(registry.total_pending_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn connection_stdin_budget_stops_the_largest_stalled_stream() {
        let limits = StdinLimits {
            max_total_buffered_bytes: 16 * 1024,
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);
        let small = registry.register("small", "small").await.expect("register");
        let large = registry.register("large", "large").await.expect("register");
        let mut healthy = registry.register("healthy", "healthy").await.expect("register");

        for sequence in 0..2 {
            dispatch(&registry, "small", sequence, vec![b'x'; 1024], false).await;
        }
        for sequence in 0..10 {
            dispatch(&registry, "large", sequence, vec![b'x'; 1024], false).await;
        }

        // Model the stall watchdog reporting both streams as stalled.
        let stall_timeout_ms = u64::try_from(limits.stall_timeout.as_millis()).expect("stall timeout");
        for stalled in [&small, &large] {
            stalled
                .backlog
                .stalled_for_ms
                .store(stall_timeout_ms, Ordering::Relaxed);
        }

        for sequence in 0..6 {
            dispatch(&registry, "healthy", sequence, vec![b'x'; 1024], false).await;
        }

        assert_eq!(*large.control.borrow(), Some(StopRequest::StdinOverflow));
        assert!(registry.inner.lock().await.streams["large"].stdin.is_none());
        assert!(
            small.control.borrow().is_none(),
            "only the largest stalled stream is stopped"
        );
        assert!(healthy.control.borrow().is_none());
        let mut received = 0;
        while healthy.stdin.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, 6);
    }

    #[tokio::test]
    async fn stalled_stream_that_progressed_since_the_last_check_is_not_stopped() {
        let limits = StdinLimits {
            max_total_buffered_bytes: 16 * 1024,
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);
        let stalled = registry.register("stalled", "stalled").await.expect("register");
        let receiving = registry.register("receiving", "receiving").await.expect("register");

        for sequence in 0..12 {
            dispatch(&registry, "stalled", sequence, vec![b'x'; 1024], false).await;
        }

        // The stall watchdog reported a stall, then the child process read some input before the next check.
        let stall_timeout_ms = u64::try_from(limits.stall_timeout.as_millis()).expect("stall timeout");
        stalled
            .backlog
            .stalled_for_ms
            .store(stall_timeout_ms, Ordering::Relaxed);
        stalled.backlog.record_progress(1);

        for sequence in 0..6 {
            dispatch(&registry, "receiving", sequence, vec![b'x'; 1024], false).await;
        }

        assert!(stalled.control.borrow().is_none());
        assert_eq!(*receiving.control.borrow(), Some(StopRequest::StdinOverflow));
    }

    #[tokio::test]
    async fn stalled_stream_being_stopped_is_not_stopped_again_for_the_stdin_budget() {
        let limits = StdinLimits {
            max_total_buffered_bytes: 16 * 1024,
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);
        let stalled = registry.register("stalled", "stalled").await.expect("register");
        let receiving = registry.register("receiving", "receiving").await.expect("register");

        for sequence in 0..12 {
            dispatch(&registry, "stalled", sequence, vec![b'x'; 1024], false).await;
        }
        let stall_timeout_ms = u64::try_from(limits.stall_timeout.as_millis()).expect("stall timeout");
        stalled
            .backlog
            .stalled_for_ms
            .store(stall_timeout_ms, Ordering::Relaxed);
        registry.stop_process("stalled", false).await;

        for sequence in 0..6 {
            dispatch(&registry, "receiving", sequence, vec![b'x'; 1024], false).await;
        }

        assert_eq!(*stalled.control.borrow(), Some(StopRequest::Graceful));
        assert_eq!(*receiving.control.borrow(), Some(StopRequest::StdinOverflow));
    }

    #[tokio::test]
    async fn frame_for_a_closed_stdin_queue_does_not_stop_a_stalled_stream() {
        let limits = StdinLimits {
            max_total_buffered_bytes: 16 * 1024,
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);
        let stalled = registry.register("stalled", "stalled").await.expect("register");
        let closed = registry.register("closed", "closed").await.expect("register");

        for sequence in 0..12 {
            dispatch(&registry, "stalled", sequence, vec![b'x'; 1024], false).await;
        }
        let stall_timeout_ms = u64::try_from(limits.stall_timeout.as_millis()).expect("stall timeout");
        stalled
            .backlog
            .stalled_for_ms
            .store(stall_timeout_ms, Ordering::Relaxed);

        // The stdin pump of the other stream is gone.
        drop(closed);
        dispatch(&registry, "closed", 0, vec![b'x'; 8 * 1024], false).await;

        assert!(stalled.control.borrow().is_none());
        assert!(registry.inner.lock().await.streams["closed"].stdin.is_none());
    }

    #[tokio::test]
    async fn stdin_budget_stops_the_stalled_stream_charged_the_most() {
        let limits = StdinLimits {
            max_total_buffered_bytes: 16 * 1024,
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);
        let partly_written = registry
            .register("partly-written", "partly-written")
            .await
            .expect("register");
        let unwritten = registry.register("unwritten", "unwritten").await.expect("register");
        let mut receiving = registry.register("receiving", "receiving").await.expect("register");

        dispatch(&registry, "partly-written", 0, vec![b'x'; 10 * 1024], false).await;
        for sequence in 0..4 {
            dispatch(&registry, "unwritten", sequence, vec![b'x'; 1024], false).await;
        }

        // Most of the large frame was written, but it stays charged until it is released.
        partly_written.backlog.record_progress(9 * 1024);

        // Model the stall watchdog reporting both streams as stalled since their last progress.
        let stall_timeout_ms = u64::try_from(limits.stall_timeout.as_millis()).expect("stall timeout");
        for stalled in [&partly_written, &unwritten] {
            stalled.backlog.stalled_at_consumed_bytes.store(
                stalled.backlog.consumed_bytes.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            stalled
                .backlog
                .stalled_for_ms
                .store(stall_timeout_ms, Ordering::Relaxed);
        }

        for sequence in 0..4 {
            dispatch(&registry, "receiving", sequence, vec![b'x'; 1024], false).await;
        }

        assert_eq!(*partly_written.control.borrow(), Some(StopRequest::StdinOverflow));
        assert!(unwritten.control.borrow().is_none());
        assert!(receiving.control.borrow().is_none());
        let mut received = 0;
        while receiving.stdin.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, 4);
    }

    #[tokio::test]
    async fn small_backlog_that_makes_no_progress_is_stopped_eventually() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 30);
        let registry = ProcessRegistry::new(StdinLimits {
            stall_threshold_bytes: 64 * MIB,
            pending_stall_timeout: Duration::from_secs(1),
            ..LIMITS_FOR_TESTS
        });

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;

        // More than the stdin pipe holds, but far below the stall threshold.
        for sequence in 0..512 {
            dispatch(&registry, "job", sequence, vec![b'x'; 1024], false).await;
        }

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(10)).await;
        assert!(
            outcome.stream_closed.reason.contains("no stdin consumed"),
            "unexpected reason: {}",
            outcome.stream_closed.reason
        );
        assert!(outcome.completed.canceled);
    }

    #[tokio::test]
    async fn graceful_stop_of_a_stalled_child_is_reported_as_canceled() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 30);
        let limits = StdinLimits {
            stall_timeout: Duration::from_secs(2),
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;

        for sequence in 0..1024 {
            dispatch(&registry, "job", sequence, vec![b'x'; 1024], false).await;
        }

        // The stall timeout elapses during the graceful exit timeout, after stdin was closed.
        tokio::time::sleep(limits.stall_timeout / 2).await;
        registry.stop_process("job", false).await;

        let outcome = collect_outcome(task, outgoing_rx, GRACEFUL_EXIT_TIMEOUT + Duration::from_secs(5)).await;
        assert_eq!(outcome.stream_closed.reason, "child process canceled");
        assert!(outcome.completed.canceled);
    }

    #[tokio::test]
    async fn kill_applies_while_process_started_is_held_back() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let marker = temp_dir.path().join("child-survived");
        let script = write_script(
            temp_dir.path(),
            "child",
            &format!(
                "@echo started\n@ping -n 4 127.0.0.1 >nul\n@echo done> \"{}\"\n@ping -n 31 127.0.0.1 >nul\n",
                marker.display()
            ),
            &format!("echo started\nsleep 3\ntouch '{}'\nsleep 30\n", marker.display()),
        );
        let registry = ProcessRegistry::default();
        let request = start_request("job", &script);
        let channels = registry.register("job", "job").await.expect("register");

        // The server connection holds back every message.
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(1);
        outgoing_tx
            .send(agent_message(
                "agent-id",
                "connection-id",
                AgentPayload::Diagnostic(diagnostic("info", "filler".to_owned())),
            ))
            .await
            .expect("fill outgoing queue");
        let task = tokio::spawn(run_process(
            request,
            channels,
            outgoing_tx,
            registry.clone(),
            "agent-id".to_owned(),
            "connection-id".to_owned(),
            "pwsh".to_owned(),
        ));

        tokio::time::sleep(Duration::from_millis(500)).await;
        registry.stop_process("job", true).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            !marker.exists(),
            "the child process kept running while ProcessStarted was held back"
        );

        let filler = outgoing_rx.recv().await.expect("filler message");
        assert!(matches!(filler.payload, Some(AgentPayload::Diagnostic(_))));
        let first = outgoing_rx.recv().await.expect("first message");
        assert!(
            matches!(first.payload, Some(AgentPayload::ProcessStarted(_))),
            "ProcessStarted must come first: {:?}",
            first.payload
        );
        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(10)).await;
        assert!(outcome.completed.canceled);
    }

    #[tokio::test]
    async fn failure_to_start_the_child_is_reported_without_process_started() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let marker = temp_dir.path().join("child-ran");
        let script = write_script(
            temp_dir.path(),
            "child",
            &format!("@ping -n 3 127.0.0.1 >nul\n@echo done> \"{}\"\n", marker.display()),
            &format!("sleep 2\ntouch '{}'\n", marker.display()),
        );
        let registry = ProcessRegistry::default();

        // The process task runs on this thread, so the next child process fails to start.
        crate::psu_agent::process_tree::tests::FAIL_NEXT_START.set(true);
        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 8).await;
        let error = task.await.expect("process task panicked").expect_err("start failure");
        assert!(format!("{error:#}").contains("injected child process start failure"));

        match outgoing_rx.recv().await.expect("stream closed message").payload {
            Some(AgentPayload::StreamClosed(closed)) => {
                assert!(closed.error);
                assert!(closed.reason.contains("injected child process start failure"));
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }
        match outgoing_rx.recv().await.expect("process completed message").payload {
            Some(AgentPayload::ProcessCompleted(completed)) => {
                assert_eq!(completed.exit_code, -1);
                assert!(completed.error_message.contains("injected child process start failure"));
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }
        assert!(outgoing_rx.recv().await.is_none());

        registry
            .register("job", "job")
            .await
            .expect("identifiers are released after a start failure");

        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(!marker.exists(), "the child process that failed to start kept running");
    }

    #[tokio::test]
    async fn backlog_just_above_the_stall_threshold_still_times_out() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 30);
        let limits = StdinLimits {
            stall_threshold_bytes: MIB,
            pipe_allowance_bytes: 256 * 1024,
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;

        // Part of the backlog fits in the stdin pipe and counts as consumed, bringing it below the threshold.
        let frame = stream_data("job".to_owned(), 0, vec![b'x'; 1024], false);
        let frames = limits.stall_threshold_bytes / frame_charge(&frame) + 1;
        for sequence in 0..frames {
            let mut frame = frame.clone();
            frame.sequence = u64::try_from(sequence).expect("sequence");
            registry.dispatch_stream_data(frame).await;
        }

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(10)).await;
        assert!(
            outcome.stream_closed.reason.contains("no stdin consumed"),
            "unexpected reason: {}",
            outcome.stream_closed.reason
        );
        assert!(outcome.completed.canceled);
    }

    #[tokio::test]
    async fn frame_rejected_by_a_closed_stdin_queue_is_not_charged() {
        let registry = ProcessRegistry::default();
        let channels = registry.register("job", "job").await.expect("register");
        let backlog = Arc::clone(&channels.backlog);

        // The stdin pump is gone.
        drop(channels);
        dispatch(&registry, "job", 0, vec![b'x'; 1024], false).await;

        assert_eq!(registry.total_pending_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(backlog.unwritten_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn queued_input_is_released_before_output_delivery() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 30);
        let registry = ProcessRegistry::default();

        // The outgoing queue fills up with the final messages and is never read, like a server that stopped reading.
        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 2).await;
        wait_for_process_started(&mut outgoing_rx).await;

        for sequence in 0..64 {
            dispatch(&registry, "job", sequence, vec![b'x'; 64 * 1024], false).await;
        }
        assert!(registry.total_pending_bytes.load(Ordering::Relaxed) > 0);

        registry.stop_process("job", true).await;

        tokio::time::timeout(Duration::from_secs(10), async {
            while registry.total_pending_bytes.load(Ordering::Relaxed) != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("queued input stayed charged while output delivery was blocked");

        drop(outgoing_rx);
        let _ = task.await;
    }

    #[tokio::test]
    async fn stream_id_stays_reserved_until_the_process_completes() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        // The background process keeps stdout open, so output is still drained after the child process exits.
        let script = write_script(
            temp_dir.path(),
            "exit",
            "@start \"\" /B ping -n 4 127.0.0.1\n@exit /b 0\n",
            "sleep 3 &\nexit 0\n",
        );
        let registry = ProcessRegistry::default();
        let channels = registry.register("job", "job").await.expect("register");
        let backlog = Arc::clone(&channels.backlog);

        let (task, outgoing_rx) = spawn_with_channels(&registry, start_request("job", &script), channels, 64);
        tokio::time::timeout(Duration::from_secs(20), async {
            while backlog.input_state.load(Ordering::Acquire) != CHILD_EXITED {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("child process exit was not observed");

        registry
            .register("other-job", "job")
            .await
            .expect_err("the stream ID is reserved while the output of the previous process is delivered");

        collect_outcome(task, outgoing_rx, Duration::from_secs(20)).await;
        registry
            .register("other-job", "job")
            .await
            .expect("the stream ID is released once the process completes");
    }

    #[tokio::test]
    async fn partially_written_frame_counts_only_unwritten_bytes_toward_a_stall() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        // Reads 600 000 bytes, then stops reading while staying alive.
        let script = write_script(
            temp_dir.path(),
            "partial-reader",
            "@powershell -NoLogo -NoProfile -NonInteractive -Command \"$stdin = [Console]::OpenStandardInput(); [Console]::Out.WriteLine('started'); [Console]::Out.Flush(); $buffer = New-Object byte[] 600000; $read = 0; while ($read -lt 600000) { $count = $stdin.Read($buffer, $read, 600000 - $read); if ($count -le 0) { break }; $read += $count }; Start-Sleep -Seconds 30\"\n",
            "echo started\nhead -c 600000 >/dev/null\nsleep 30\n",
        );
        let limits = StdinLimits {
            stall_threshold_bytes: MIB,
            ..LIMITS_FOR_TESTS
        };
        let registry = ProcessRegistry::new(limits);

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let message = outgoing_rx.recv().await.expect("outgoing channel closed");
                if matches!(message.payload, Some(AgentPayload::StreamData(data)) if data.data == b"started") {
                    break;
                }
            }
        })
        .await
        .expect("child process did not start");

        // The frame is charged in full while it is retained, but only its unwritten part is below the threshold.
        registry
            .dispatch_stream_data(stream_data("job".to_owned(), 0, vec![b'x'; MIB], false))
            .await;
        tokio::time::sleep(limits.stall_timeout * 10).await;
        assert!(
            !task.is_finished(),
            "a child process that consumed most of its input was killed"
        );

        registry.stop_process("job", true).await;
        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(10)).await;
        assert_eq!(outcome.stream_closed.reason, "child process canceled");
    }

    #[tokio::test]
    async fn stop_requested_while_the_child_exits_still_applies() {
        for kill in [false, true] {
            let temp_dir = tempfile::tempdir().expect("create temp dir");
            let marker = temp_dir.path().join("background-survived");
            let background = write_script(
                temp_dir.path(),
                "background",
                &format!("@ping -n 4 127.0.0.1 >nul\n@echo done> \"{}\"\n", marker.display()),
                &format!("sleep 3\ntouch '{}'\n", marker.display()),
            );
            let script = write_script(
                temp_dir.path(),
                "exit",
                &format!("@start \"\" /B \"{}\"\n@exit /b 0\n", background.display()),
                &format!("sh '{}' &\nexit 0\n", background.display()),
            );
            let registry = ProcessRegistry::default();
            let mut channels = registry.register("job", "job").await.expect("register");

            // Mark the request as seen to model a child process exit selected before the stop request.
            registry.stop_process("job", kill).await;
            assert!(channels.control.borrow_and_update().is_some());

            let (task, outgoing_rx) = spawn_with_channels(&registry, start_request("job", &script), channels, 64);
            let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(20)).await;
            assert!(outcome.completed.canceled, "kill: {kill}");

            tokio::time::sleep(Duration::from_secs(5)).await;
            assert!(
                !marker.exists(),
                "a process started by a stopped job survived (kill: {kill})"
            );
        }
    }

    #[tokio::test]
    async fn kill_is_not_lost_after_repeated_graceful_stops() {
        let registry = ProcessRegistry::default();
        let channels = registry.register("job", "job").await.expect("register");

        for _ in 0..100 {
            registry.stop_process("job", false).await;
        }
        registry.stop_process("job", true).await;

        assert_eq!(*channels.control.borrow(), Some(StopRequest::Kill));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_graceful_stops_do_not_delay_the_exit_deadline() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = sleeping_script(temp_dir.path(), 30);
        let registry = ProcessRegistry::default();

        let (task, mut outgoing_rx) = spawn_process(&registry, start_request("job", &script), 64).await;
        wait_for_process_started(&mut outgoing_rx).await;

        let spam = tokio::spawn({
            let registry = registry.clone();
            async move {
                loop {
                    registry.stop_process("job", false).await;
                }
            }
        });

        let outcome = collect_outcome(task, outgoing_rx, GRACEFUL_EXIT_TIMEOUT + Duration::from_secs(5)).await;
        spam.abort();
        assert!(outcome.completed.canceled);
    }

    #[tokio::test]
    async fn overflow_dispatched_while_the_exit_is_being_handled_is_ignored() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = write_script(temp_dir.path(), "exit", "@exit /b 0\n", "exit 0\n");
        let registry = ProcessRegistry::new(StdinLimits {
            max_buffered_bytes: 1024,
            ..LIMITS_FOR_TESTS
        });
        let channels = registry.register("job", "job").await.expect("register");
        let backlog = Arc::clone(&channels.backlog);

        // Holding the registry lock models a dispatch in progress when the child process exits.
        let mut inner = registry.inner.lock().await;
        let (task, outgoing_rx) = spawn_with_channels(&registry, start_request("job", &script), channels, 64);

        tokio::time::timeout(Duration::from_secs(20), async {
            while backlog.input_state.load(Ordering::Acquire) != CHILD_EXITED {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("child process exit was not observed while the registry was locked");

        dispatch_locked(
            &mut inner,
            registry.limits,
            &registry.total_pending_bytes,
            stream_data("job".to_owned(), 0, vec![b'x'; 2048], false),
        );
        drop(inner);

        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(20)).await;
        assert!(!outcome.stream_closed.error, "{}", outcome.stream_closed.reason);
        assert!(!outcome.completed.canceled);
    }

    #[tokio::test]
    async fn run_process_cleans_registry_and_reports_spawn_failure() {
        let registry = ProcessRegistry::default();
        let mut request = start_request("job", Path::new("unused"));
        request.executable = "definitely-not-a-devolutions-agent-test-command".to_owned();
        request.arguments = Vec::new();
        request.correlation_id = "correlation-id".to_owned();
        request.stream_id = "stream-id".to_owned();

        let (task, mut outgoing_rx) = spawn_process(&registry, request, 8).await;
        let result = task.await.expect("process task panicked");
        assert!(result.is_err());

        let inner = registry.inner.lock().await;
        assert!(inner.streams.is_empty());
        assert!(inner.processes.is_empty());
        drop(inner);

        let stream_message = outgoing_rx.recv().await.expect("stream closed message");
        match stream_message.payload {
            Some(AgentPayload::StreamClosed(closed)) => {
                assert_eq!(closed.stream_id, "stream-id");
                assert!(closed.error);
                assert!(closed.reason.contains("failed to start PSU gRPC child process"));
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }

        let completed_message = outgoing_rx.recv().await.expect("process completed message");
        match completed_message.payload {
            Some(AgentPayload::ProcessCompleted(completed)) => {
                assert_eq!(completed.correlation_id, "correlation-id");
                assert_eq!(completed.exit_code, -1);
                assert!(!completed.canceled);
                assert!(
                    completed
                        .error_message
                        .contains("failed to start PSU gRPC child process")
                );
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }
    }
}
