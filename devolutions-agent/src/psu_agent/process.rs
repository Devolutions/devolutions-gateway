use std::collections::HashMap;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tokio::sync::{Mutex, mpsc};
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
/// to apply flow control to the input it sends, keeping each backlog well below `max_buffered_bytes`.
#[derive(Debug, Clone, Copy)]
pub(super) struct StdinLimits {
    /// A child process is considered stalled while at least this many bytes are pending and none are consumed.
    pub(super) stall_threshold_bytes: usize,
    /// How long a child process may stay stalled before it is stopped.
    ///
    /// Time during which the child process output is held back by the server connection does not count, because
    /// a child process blocked writing its output cannot read its input.
    pub(super) stall_timeout: Duration,
    /// Pending bytes beyond which the stream is failed immediately to bound memory usage.
    pub(super) max_buffered_bytes: usize,
}

impl Default for StdinLimits {
    fn default() -> Self {
        Self {
            stall_threshold_bytes: 16 * MIB,
            stall_timeout: Duration::from_secs(30),
            max_buffered_bytes: 64 * MIB,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StopRequest {
    /// Close stdin and let the child process exit on its own.
    Graceful,
    Kill,
    /// The stdin backlog exceeded [`StdinLimits::max_buffered_bytes`].
    StdinOverflow,
}

/// Why the agent killed a child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillReason {
    ServerRequest,
    ExitTimeout,
    StdinOverflow,
    StdinStalled,
}

/// Stdin backlog accounting shared by the registry, the stdin pump, and the stall watchdog.
#[derive(Debug, Default)]
struct StdinBacklog {
    pending_bytes: AtomicUsize,
    consumed_bytes: AtomicU64,
    /// Set under the registry lock when input was dropped because the backlog exceeded its limit.
    overflowed: AtomicBool,
    /// Set by the stdin pump before it closes stdin because the server ended the stream.
    end_of_stream: AtomicBool,
}

/// Memory charged against the stdin backlog for a queued frame, so that empty frames are bounded too.
fn frame_charge(frame: &StreamData) -> usize {
    size_of::<StreamData>() + frame.stream_id.len() + frame.data.len()
}

impl StdinBacklog {
    fn consume(&self, bytes: usize) {
        self.pending_bytes.fetch_sub(bytes, Ordering::Relaxed);
        self.consumed_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
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
    stalled_for: Duration,
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
        }
    }

    fn check_period(&self) -> Duration {
        (self.limits.stall_timeout / 4).clamp(Duration::from_millis(10), Duration::from_secs(1))
    }

    /// Returns whether the child process has been stalled for longer than the stall timeout.
    fn is_stalled(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now - self.last_check;
        self.last_check = now;

        let consumed_bytes = self.backlog.consumed_bytes.load(Ordering::Relaxed);
        let progressed = consumed_bytes != self.last_consumed_bytes;
        self.last_consumed_bytes = consumed_bytes;

        let output_held_back = self.output.take_observed();
        let backlog_full = self.backlog.pending_bytes.load(Ordering::Relaxed) >= self.limits.stall_threshold_bytes;

        if progressed || !backlog_full {
            self.stalled_for = Duration::ZERO;
        } else if !output_held_back {
            self.stalled_for += elapsed;
        }

        self.stalled_for >= self.limits.stall_timeout
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct ProcessRegistry {
    inner: Arc<Mutex<ProcessRegistryInner>>,
    limits: StdinLimits,
}

#[derive(Debug, Default)]
struct ProcessRegistryInner {
    streams: HashMap<String, StreamEntry>,
    processes: HashMap<String, ProcessEntry>,
    last_registration: u64,
}

#[derive(Debug)]
struct StreamEntry {
    registration: u64,
    stdin: mpsc::UnboundedSender<StreamData>,
    backlog: Arc<StdinBacklog>,
    stop: mpsc::Sender<StopRequest>,
}

#[derive(Debug)]
struct ProcessEntry {
    registration: u64,
    stop: mpsc::Sender<StopRequest>,
}

/// Channels of a registered process, consumed by [`run_process`].
#[derive(Debug)]
pub(super) struct ProcessChannels {
    registration: u64,
    stdin: mpsc::UnboundedReceiver<StreamData>,
    backlog: Arc<StdinBacklog>,
    control: mpsc::Receiver<StopRequest>,
}

impl ProcessRegistry {
    #[cfg(test)]
    fn new(limits: StdinLimits) -> Self {
        Self {
            inner: Arc::default(),
            limits,
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
        let (control_tx, control_rx) = mpsc::channel(8);
        let backlog = Arc::new(StdinBacklog::default());

        inner.streams.insert(
            stream_id.to_owned(),
            StreamEntry {
                registration,
                stdin: stdin_tx,
                backlog: Arc::clone(&backlog),
                stop: control_tx.clone(),
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
        let Some(entry) = inner.streams.get(&stream_data.stream_id) else {
            return;
        };
        let stream_id = stream_data.stream_id.clone();
        let end_of_stream = stream_data.end_of_stream;
        let frame_bytes = frame_charge(&stream_data);

        let pending_bytes = entry.backlog.pending_bytes.load(Ordering::Relaxed);
        let keep_stream = if pending_bytes.saturating_add(frame_bytes) > self.limits.max_buffered_bytes {
            // Recorded under the registry lock, so `run_process` can tell whether input was dropped before it
            // observed the child process exit.
            entry.backlog.overflowed.store(true, Ordering::Relaxed);
            let _ = entry.stop.try_send(StopRequest::StdinOverflow);
            false
        } else {
            entry.backlog.pending_bytes.fetch_add(frame_bytes, Ordering::Relaxed);
            entry.stdin.send(stream_data).is_ok() && !end_of_stream
        };

        // Close the stream when it is the last frame, when the receiver is gone, or when the backlog overflows, so
        // the mapping is never leaked in the registry.
        if !keep_stream {
            inner.streams.remove(&stream_id);
        }
    }

    pub(super) async fn stop_process(&self, correlation_id: &str, kill_process: bool) {
        let control = {
            let mut inner = self.inner.lock().await;
            if kill_process {
                inner.processes.remove(correlation_id).map(|entry| entry.stop)
            } else {
                inner.processes.get(correlation_id).map(|entry| entry.stop.clone())
            }
        };

        let request = if kill_process {
            StopRequest::Kill
        } else {
            StopRequest::Graceful
        };

        // Never wait here: a full queue means the process is already being stopped, and a graceful stop
        // escalates to a kill on its own.
        if let Some(Err(error)) = control.map(|control| control.try_send(request)) {
            debug!(correlation_id, %error, "PSU gRPC stop request not queued");
        }
    }

    /// Closes the stream on server request; the child process sees the end of its stdin.
    pub(super) async fn close_stream(&self, stream_id: &str) {
        self.inner.lock().await.streams.remove(stream_id);
    }

    async fn close_registered_stream(&self, stream_id: &str, registration: u64) {
        let mut inner = self.inner.lock().await;
        if inner
            .streams
            .get(stream_id)
            .is_some_and(|entry| entry.registration == registration)
        {
            inner.streams.remove(stream_id);
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

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let error =
                anyhow::Error::new(error).context(format!("failed to start PSU gRPC child process using {executable}"));
            let error_message = format!("{error:#}");
            let _ = outgoing_tx
                .send(agent_message(
                    &agent_id,
                    &connection_id,
                    AgentPayload::StreamClosed(stream_closed(request.stream_id.clone(), error_message.clone(), true)),
                ))
                .await;
            let _ = send_process_completed(
                &outgoing_tx,
                &agent_id,
                &connection_id,
                &request.correlation_id,
                -1,
                false,
                error_message,
            )
            .await;
            return Err(error);
        }
    };
    let mut process_tree = ProcessTree::attach(&mut child);
    let process_id_u32 = child.id().unwrap_or(0);
    let process_id = i32::try_from(process_id_u32).unwrap_or(i32::MAX);

    outgoing_tx
        .send(agent_message(
            &agent_id,
            &connection_id,
            AgentPayload::ProcessStarted(ProcessStarted {
                correlation_id: request.correlation_id.clone(),
                process_id,
            }),
        ))
        .await
        .context("failed to send PSU gRPC ProcessStarted message")?;

    let stdin = child.stdin.take().context("child process stdin was not piped")?;
    let stdout = child.stdout.take().context("child process stdout was not piped")?;
    let stderr = child.stderr.take().context("child process stderr was not piped")?;

    let output_backpressure = Arc::new(OutputBackpressure::default());
    let stdout_task = tokio::spawn(pump_stdout_to_server(
        stdout,
        request.stream_id.clone(),
        outgoing_tx.clone(),
        Arc::clone(&output_backpressure),
        agent_id.clone(),
        connection_id.clone(),
        process_id,
    ));
    let stderr_task = tokio::spawn(pump_stderr_diagnostics(
        stderr,
        outgoing_tx.clone(),
        Arc::clone(&output_backpressure),
        agent_id.clone(),
        connection_id.clone(),
        process_id,
    ));
    let mut stdin_task = tokio::spawn(pump_server_to_stdin(stdin_rx, stdin, Arc::clone(&backlog), process_id));
    let _abort_pumps = [
        stdout_task.abort_handle(),
        stderr_task.abort_handle(),
        stdin_task.abort_handle(),
    ]
    .map(AbortOnDrop);

    let mut watchdog = StallWatchdog::new(limits, Arc::clone(&backlog), output_backpressure);
    let mut watchdog_interval = tokio::time::interval(watchdog.check_period());
    watchdog_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut stdin_task_completed = false;
    let mut control_open = true;
    let mut graceful_stop_requested = false;
    let mut exit_deadline = None;
    let mut kill_reason = None;

    // Every branch returns promptly, so stop requests are handled while waiting for the child process to exit.
    let status = loop {
        tokio::select! {
            biased;

            stop_request = control_rx.recv(), if control_open => match stop_request {
                Some(StopRequest::Kill) => {
                    info!(process_id, correlation_id = %request.correlation_id, "Killing PSU gRPC child process on server request");
                    kill_reason = Some(KillReason::ServerRequest);
                    break kill_process_tree(&mut child, &mut process_tree).await?;
                }
                Some(StopRequest::StdinOverflow) => {
                    warn!(
                        process_id,
                        correlation_id = %request.correlation_id,
                        max_buffered_bytes = limits.max_buffered_bytes,
                        "Killing PSU gRPC child process because its stdin backlog exceeded the limit"
                    );
                    kill_reason = Some(KillReason::StdinOverflow);
                    break kill_process_tree(&mut child, &mut process_tree).await?;
                }
                Some(StopRequest::Graceful) => {
                    if !graceful_stop_requested {
                        info!(process_id, correlation_id = %request.correlation_id, "Gracefully stopping PSU gRPC child process by closing stdin");
                        graceful_stop_requested = true;
                        if !stdin_task_completed {
                            stdin_task.abort();
                            let _ = (&mut stdin_task).await;
                            stdin_task_completed = true;
                        }
                        exit_deadline.get_or_insert_with(|| Instant::now() + GRACEFUL_EXIT_TIMEOUT);
                    }
                }
                // All stop request senders are gone; stop polling the closed channel.
                None => control_open = false,
            },
            status = child.wait() => break status.context("failed to wait for PSU gRPC child process")?,
            _ = &mut stdin_task, if !stdin_task_completed => {
                stdin_task_completed = true;
                info!(process_id, "Finished receiving PSU gRPC stdin data; waiting for graceful child process exit");
                exit_deadline.get_or_insert_with(|| Instant::now() + GRACEFUL_EXIT_TIMEOUT);
            }
            () = sleep_until(exit_deadline) => {
                warn!(process_id, "PSU gRPC child process did not exit after stdin closed; killing child process");
                kill_reason = Some(KillReason::ExitTimeout);
                break kill_process_tree(&mut child, &mut process_tree).await?;
            }
            _ = watchdog_interval.tick() => {
                if watchdog.is_stalled() {
                    warn!(
                        process_id,
                        correlation_id = %request.correlation_id,
                        stall_timeout = ?limits.stall_timeout,
                        "Killing PSU gRPC child process because its stdin backlog made no progress"
                    );
                    kill_reason = Some(KillReason::StdinStalled);
                    break kill_process_tree(&mut child, &mut process_tree).await?;
                }
            }
        }
    };

    // Input that arrives once the child process has exited could not be delivered anyway, so only an overflow
    // recorded before this point counts. Closing the stream takes the registry lock that dispatch holds while
    // recording an overflow, so the flag is final once the stream is closed.
    registry.close_registered_stream(&request.stream_id, registration).await;
    let stdin_overflowed = backlog.overflowed.load(Ordering::Relaxed);
    let stdin_closed_from_end_of_stream = backlog.end_of_stream.load(Ordering::Relaxed);

    // Only a child process that exited on its own leaves its background processes running.
    if kill_reason.is_none() && !graceful_stop_requested {
        process_tree.release();
    } else {
        process_tree.terminate();
    }

    if !stdin_task_completed {
        stdin_task.abort();
        let _ = stdin_task.await;
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
    let stream_reason = if kill_reason == Some(KillReason::StdinStalled) {
        format!(
            "no stdin consumed for {:?} while at least {} was pending",
            limits.stall_timeout,
            format_bytes(limits.stall_threshold_bytes)
        )
    } else if kill_reason == Some(KillReason::StdinOverflow) || stdin_overflowed {
        format!(
            "stdin backlog exceeded the {} limit",
            format_bytes(limits.max_buffered_bytes)
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
            info!(process_id, "Received PSU gRPC stdin end-of-stream; closing child stdin");
            // Recorded before stdin is closed, so it is visible by the time the child process exits.
            backlog.end_of_stream.store(true, Ordering::Relaxed);
            break;
        }

        if let Err(error) = write_stdin_frame(&mut stdin, &frame, &backlog).await {
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
            backlog.consume(written);
            chunk = &chunk[written..];
        }
    }

    if !ends_with_line_ending(&frame.data) {
        stdin.write_all(b"\n").await?;
    }
    stdin.flush().await?;

    backlog.consume(frame_charge(frame) - frame.data.len());

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
        stall_timeout: Duration::from_millis(300),
        max_buffered_bytes: 64 * MIB,
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
    async fn graceful_stop_keeps_process_registered_for_later_kill() {
        let registry = ProcessRegistry::default();
        let mut channels = registry
            .register("correlation-id", "stream-id")
            .await
            .expect("register");

        registry.stop_process("correlation-id", false).await;
        assert_eq!(channels.control.recv().await, Some(StopRequest::Graceful));
        assert!(registry.inner.lock().await.processes.contains_key("correlation-id"));

        registry.stop_process("correlation-id", true).await;
        assert_eq!(channels.control.recv().await, Some(StopRequest::Kill));
        assert!(!registry.inner.lock().await.processes.contains_key("correlation-id"));
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
        assert_eq!(channels.control.try_recv().ok(), Some(StopRequest::Kill));
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

        assert_eq!(stalled.control.try_recv().ok(), Some(StopRequest::StdinOverflow));
        assert!(stalled.backlog.overflowed.load(Ordering::Relaxed));
        assert!(!registry.inner.lock().await.streams.contains_key("stalled"));

        assert_eq!(healthy.stdin.try_recv().expect("healthy frame").data, b"data");
        assert!(healthy.control.try_recv().is_err());
        assert!(registry.inner.lock().await.streams.contains_key("healthy"));
    }

    #[tokio::test]
    async fn stdin_overflow_before_exit_is_reported_when_the_child_exits_successfully_first() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let script = write_script(temp_dir.path(), "exit", "@exit /b 0\n", "exit 0\n");
        let registry = ProcessRegistry::new(StdinLimits {
            max_buffered_bytes: 1024,
            ..LIMITS_FOR_TESTS
        });
        let request = start_request("job", &script);
        let mut channels = registry.register("job", "job").await.expect("register");

        dispatch(&registry, "job", 0, vec![b'x'; 2048], false).await;

        // Consume the notification to model a child process that exits before the stop request is read.
        assert_eq!(channels.control.try_recv().ok(), Some(StopRequest::StdinOverflow));

        let (task, outgoing_rx) = spawn_with_channels(&registry, request, channels, 64);
        let outcome = collect_outcome(task, outgoing_rx, Duration::from_secs(20)).await;

        assert!(outcome.stream_closed.error);
        assert!(
            outcome.stream_closed.reason.contains("stdin backlog exceeded"),
            "unexpected reason: {}",
            outcome.stream_closed.reason
        );
        assert!(outcome.completed.canceled);
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

        assert_eq!(channels.control.try_recv().ok(), Some(StopRequest::StdinOverflow));
        assert!(channels.backlog.overflowed.load(Ordering::Relaxed));
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
