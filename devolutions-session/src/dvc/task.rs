use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use devolutions_agent_shared::temp_file::{BATCH_UTF8_PREAMBLE, POWERSHELL_UTF8_ENCODING_PREAMBLE, TmpFileGuard};
use devolutions_gateway_task::{ChildTask, ShutdownSignal, Task};
use now_proto_pdu::ironrdp_core::IntoOwned;
use now_proto_pdu::{
    ComApartmentStateKind, NowChannelCapsetMsg, NowChannelCloseMsg, NowChannelHeartbeatMsg, NowChannelMessage,
    NowExecBatchMsg, NowExecCancelRspMsg, NowExecCapsetFlags, NowExecDataMsg, NowExecDataStreamKind, NowExecMessage,
    NowExecProcessMsg, NowExecPwshMsg, NowExecResultMsg, NowExecRunMsg, NowExecStartedMsg, NowExecWinPsMsg, NowMessage,
    NowMsgBoxResponse, NowProtoError, NowProtoVersion, NowRdmMessage, NowSessionCapsetFlags, NowSessionMessage,
    NowSessionMsgBoxRspMsg, NowSessionWindowRecStartMsg, NowStatusError, NowSystemCapsetFlags, NowSystemMessage,
    OwnedNowExecResultMsg, OwnedNowMessage, OwnedNowSessionMsgBoxReqMsg, OwnedNowSessionWindowRecEventMsg,
    SetKbdLayoutOption, WindowRecStartFlags,
};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tracing::{error, info, warn};
use win_api_wrappers::event::Event;
use win_api_wrappers::process::Process;
use win_api_wrappers::security::privilege::ScopedPrivileges;
use win_api_wrappers::utils::WideString;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::Storage::FileSystem::SearchPathW;
use windows::Win32::System::Shutdown::{
    EWX_FORCE, EWX_LOGOFF, EWX_POWEROFF, EWX_REBOOT, ExitWindowsEx, InitiateSystemShutdownW, LockWorkStation,
    SHUTDOWN_REASON,
};
use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows::Win32::UI::Input::KeyboardAndMouse::GetFocus;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowThreadProcessId, HKL_NEXT, HKL_PREV, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE,
    MessageBoxW, PostMessageW, SW_RESTORE, WM_INPUTLANGCHANGEREQUEST,
};
use windows::core::PCWSTR;

use crate::dvc::channel::{WinapiSignaledSender, bounded_mpsc_channel, winapi_signaled_mpsc_channel};
use crate::dvc::encoding::DataEncoding;
use crate::dvc::io::{DvcInitializationProgress, run_dvc_io};
use crate::dvc::process::{ExecError, ServerChannelEvent, WinApiProcess, WinApiProcessBuilder};
use crate::dvc::rdm::RdmMessageProcessor;
use crate::dvc::window_monitor::{WindowMonitorConfig, run_window_monitor};

// One minute heartbeat interval by default
const DEFAULT_HEARTBEAT_INTERVAL: core::time::Duration = core::time::Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(5);

/// Delay before reopening a channel after the first failure; it doubles with each consecutive failed reopen.
const REOPEN_DELAY_FLOOR: core::time::Duration = core::time::Duration::from_secs(1);
const REOPEN_DELAY_CAP: core::time::Duration = core::time::Duration::from_secs(10);
/// Number of consecutive reopened channels that may fail to negotiate before the process gives up.
const MAX_CONSECUTIVE_FAILED_REOPENS: usize = 5;
/// Time the IO thread of a lost channel has to release it before the process gives up.
const IO_THREAD_STOP_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);

const GENERIC_ERROR_CODE_ENCODING: u32 = 0x00000001;
const GENERIC_ERROR_CODE_TOO_LONG_ERROR: u32 = 0x00000002;
const GENERIC_ERROR_CODE_OTHER: u32 = 0xFFFFFFFF;

#[derive(Default)]
pub struct DvcIoTask {}

#[async_trait]
impl Task for DvcIoTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "DVC processing";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        let channel_shutdown_signal = shutdown_signal.clone();

        serve_dvc(move || serve_channel(channel_shutdown_signal.clone()), shutdown_signal).await
    }
}

/// How serving one DVC channel ended.
#[derive(Debug)]
enum ChannelOutcome {
    /// The channel was closed on purpose, by either peer or by shutdown, and must not be reopened.
    Ended,
    /// The channel failed before the client completed negotiation.
    NotNegotiated(anyhow::Error),
    /// The channel failed after the client completed negotiation.
    Lost(anyhow::Error),
}

impl ChannelOutcome {
    fn new(result: anyhow::Result<()>, init_progress: &DvcInitializationProgress) -> Self {
        match result {
            Ok(()) => Self::Ended,
            Err(error) if init_progress.negotiated() => Self::Lost(error),
            Err(error) => Self::NotNegotiated(error),
        }
    }
}

/// Serves DVC channels until one ends on purpose, reopening a channel lost after negotiation.
///
/// A first channel that never negotiates is not reopened: the client likely has no NOW listener, and reopening would
/// keep a process alive that nobody can reach.
/// Once a client has negotiated, a failed channel is reopened after a delay that grows with each consecutive reopen
/// that fails to negotiate, until [`MAX_CONSECUTIVE_FAILED_REOPENS`] of them.
///
/// Errors only when a negotiated client can no longer be served, which makes the process exit with a failure code
/// that the agent answers by relaunching it.
async fn serve_dvc<F, Fut>(mut serve_channel: F, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<ChannelOutcome>>,
{
    // `None` until a negotiated channel is lost.
    let mut failed_reopens: Option<usize> = None;

    loop {
        if let Some(failed_reopens) = failed_reopens {
            select! {
                () = tokio::time::sleep(reopen_delay(failed_reopens)) => {}
                _ = shutdown_signal.wait() => return Ok(()),
            }
        }

        match serve_channel().await? {
            ChannelOutcome::Ended => return Ok(()),
            ChannelOutcome::Lost(error) => {
                warn!(
                    error = format!("{error:#}"),
                    "Lost the negotiated DVC channel; reopening it"
                );
                failed_reopens = Some(0);
            }
            ChannelOutcome::NotNegotiated(error) => {
                let Some(previous_failures) = failed_reopens else {
                    // Not a failure: the client likely has no NOW listener, and the agent relaunches a process that
                    // exits with an error.
                    warn!(
                        error = format!("{error:#}"),
                        "The client did not negotiate the DVC channel"
                    );
                    return Ok(());
                };

                let failures = previous_failures + 1;

                if failures < MAX_CONSECUTIVE_FAILED_REOPENS {
                    warn!(
                        error = format!("{error:#}"),
                        failures, "Failed to reopen the DVC channel"
                    );
                    failed_reopens = Some(failures);
                } else {
                    return Err(error.context(format!("failed to reopen the DVC channel {failures} consecutive times")));
                }
            }
        }
    }
}

fn reopen_delay(failed_reopens: usize) -> core::time::Duration {
    let factor = u32::try_from(failed_reopens)
        .ok()
        .and_then(|exponent| 2u32.checked_pow(exponent))
        .unwrap_or(u32::MAX);

    REOPEN_DELAY_FLOOR.saturating_mul(factor).min(REOPEN_DELAY_CAP)
}

/// Opens one DVC channel and serves it until it ends.
///
/// Errors only when the process cannot go on serving channels at all.
async fn serve_channel(mut shutdown_signal: ShutdownSignal) -> anyhow::Result<ChannelOutcome> {
    let (write_tx, write_rx) = winapi_signaled_mpsc_channel()?;
    let (read_tx, read_rx) = bounded_mpsc_channel()?;

    // WinAPI event to terminate DVC IO thread.
    let io_thread_shutdown_event = Event::new_unnamed()?;

    let cloned_shutdown_event = io_thread_shutdown_event.clone();

    // Each channel gets its own progress, and therefore its own negotiation deadline.
    let init_progress = Arc::new(DvcInitializationProgress::default());
    let io_thread_progress = Arc::clone(&init_progress);
    let (io_loop_ended_tx, io_loop_ended_rx) = tokio::sync::oneshot::channel();

    info!(
        "Starting NowProto DVC v{}.{}",
        NowProtoVersion::CURRENT.major,
        NowProtoVersion::CURRENT.minor
    );

    // Spawning thread is relatively short operation, so it could be executed synchronously.
    let io_thread = std::thread::spawn(move || {
        let io_thread_result = run_dvc_io(
            write_rx,
            read_tx,
            cloned_shutdown_event,
            &io_thread_progress,
            io_loop_ended_tx,
        );

        if let Err(error) = io_thread_result {
            error!(%error, "DVC IO thread failed");
        }
    });

    // Joined on a plain thread rather than the blocking pool, because the runtime waits for its blocking tasks when it
    // shuts down, so an IO thread that never stops would keep the process alive.
    let (io_thread_stopped_tx, io_thread_stopped_rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        if let Err(panic_payload) = io_thread.join() {
            if let Some(s) = panic_payload.downcast_ref::<&dyn std::fmt::Debug>() {
                error!("DVC IO thread panic: {:?}", s);
            } else {
                error!("DVC IO thread join failed.");
            }
        }

        let _ = io_thread_stopped_tx.send(());
    });

    info!("Processing DVC messages...");

    let process_result = process_until_io_ends(
        process_messages(read_rx, write_tx, shutdown_signal.clone(), &init_progress),
        io_loop_ended_rx,
    )
    .await;

    // Send shutdown signal to IO thread to release WTS channel resources.
    info!("Shutting down DVC IO thread");
    let _ = io_thread_shutdown_event.set();

    let outcome = ChannelOutcome::new(process_result, &init_progress);

    // UNTESTED: a failed channel may be reopened, so its IO thread must release the WTS handle before the next open,
    // and a thread that does not stop must end the process, because the agent does not replace a process that is
    // still running.
    // An ended channel is never reopened, so the process exits without depending on the thread.
    // The thread waits for its cancelled overlapped IO to finish before it stops; when changing the IO thread or its
    // join, check that the timeout still bounds that wait and that nothing on the runtime still waits for the thread.
    if let ChannelOutcome::Lost(error) | ChannelOutcome::NotNegotiated(error) = &outcome {
        select! {
            stopped = tokio::time::timeout(IO_THREAD_STOP_TIMEOUT, io_thread_stopped_rx) => {
                if stopped.is_err() {
                    error!(error = format!("{error:#}"), "DVC channel failed");
                    bail!("DVC IO thread did not stop within {IO_THREAD_STOP_TIMEOUT:?}");
                }
            }
            _ = shutdown_signal.wait() => return Ok(ChannelOutcome::Ended),
        }
    }

    Ok(outcome)
}

async fn process_until_io_ends(
    processing: impl Future<Output = anyhow::Result<()>>,
    io_loop_ended: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    select! {
        biased;
        result = processing => result,
        _ = io_loop_ended => bail!("DVC IO loop ended"),
    }
}

async fn process_messages(
    mut read_rx: Receiver<OwnedNowMessage>,
    dvc_tx: WinapiSignaledSender<OwnedNowMessage>,
    mut shutdown_signal: ShutdownSignal,
    init_progress: &DvcInitializationProgress,
) -> anyhow::Result<()> {
    let (io_notification_tx, mut task_rx) = mpsc::channel(100);

    // Detect pwsh (PowerShell 7+) availability once on DVC start, so that the
    // corresponding capability flag is only advertised when it is actually installed.
    let pwsh_executable = find_pwsh_executable();

    match &pwsh_executable {
        Some(path) => info!(path, "Found pwsh executable"),
        None => warn!("pwsh executable was not found; pwsh execution capability is disabled"),
    }

    // A channel that never opens is not covered by this deadline: the IO thread drops its sender
    // when it gives up, which surfaces below as a closed read channel.
    let negotiation_deadline = init_progress.negotiation_deadline(HANDSHAKE_TIMEOUT);

    // Wait for channel negotiation message and send downgraded capabilities back.
    let client_caps = select! {
        message = read_rx.recv() => {
            match message {
                Some(NowMessage::Channel(NowChannelMessage::Capset(caps))) => caps,
                Some(message) => {
                    return Err(anyhow::anyhow!("Unexpected negotiation message: {:?}", message));
                }
                None => {
                    error!(
                        channel_opened = init_progress.channel_opened(),
                        open_attempts = init_progress.open_attempts(),
                        "DVC IO thread ended before negotiation"
                    );
                    return Err(anyhow::anyhow!("read channel has been closed before negotiation"));
                }
            }
        }
        () = negotiation_deadline =>
        {
            error!(
                open_attempts = init_progress.open_attempts(),
                timeout_ms = HANDSHAKE_TIMEOUT.as_millis(),
                "Timeout waiting for DVC negotiation"
            );
            return Err(anyhow::anyhow!("timeout waiting for DVC negotiation"));
        }
        // Without this arm, a shutdown requested while the IO thread is still retrying the open
        // is not honoured until the retry ladder runs out.
        _ = shutdown_signal.wait() => {
            info!("Shutting down before DVC negotiation completed");
            return Ok(());
        }
    };

    if client_caps.version().major != NowProtoVersion::CURRENT.major {
        let error = NowStatusError::new_proto(NowProtoError::ProtocolVersion);
        let msg =
            NowChannelCloseMsg::from_error(error).expect("NowProtoError without message serialization always succeeds");

        dvc_tx.send(msg.into_owned().into()).await?;

        return Ok(());
    }

    let server_caps = default_server_caps(pwsh_executable.is_some());
    let downgraded_caps = client_caps.downgrade(&server_caps);
    // Held only to stop the heartbeats on renegotiation and when this loop ends.
    #[expect(
        clippy::collection_is_never_read,
        reason = "the task handle is a drop guard; it is assigned, never inspected"
    )]
    let mut _heartbeat = spawn_heartbeat(dvc_tx.clone(), downgraded_caps.heartbeat_interval());
    init_progress.set_heartbeats_enabled(heartbeats_enabled(downgraded_caps.heartbeat_interval()));

    // Reply with the negotiated capset so the client sees the capabilities and heartbeat interval
    // the agent applies, not the server default that omits the interval.
    dvc_tx.send(downgraded_caps.clone().into()).await?;

    let mut processor = MessageProcessor::new(
        downgraded_caps,
        dvc_tx.clone(),
        io_notification_tx.clone(),
        pwsh_executable.clone(),
    );

    init_progress.mark_negotiated();
    info!("DVC negotiation completed");

    // Process output keeps being served while stdin waits, because the process may not read stdin until its output
    // is drained.
    let mut pending_stdin: Option<(u32, StdinSend)> = None;

    loop {
        select! {
            () = async {
                match pending_stdin.as_mut() {
                    Some((_, send)) => send.await,
                    None => std::future::pending().await,
                }
            } => {
                pending_stdin = None;
            }
            read_result = read_rx.recv(), if pending_stdin.is_none() => {
                match read_result {
                    Some(message) => {
                        match processor.process_message(message).await {
                            Ok(ProcessMessageAction::Continue) => {}
                            Ok(ProcessMessageAction::SendStdin { session_id, send }) => {
                                pending_stdin = Some((session_id, send));
                            }
                            Ok(ProcessMessageAction::Shutdown) => {
                                info!("Received channel shutdown message...");
                                return Ok(());
                            }
                            Ok(ProcessMessageAction::Restart(client_caps)) => {
                                info!("Restarting DVC IO thread with new capabilities...");

                                // Re-negotiate capabilities with the client and initialize new
                                // message processor.
                                let server_caps = default_server_caps(pwsh_executable.is_some());
                                let downgraded_caps = client_caps.downgrade(&server_caps);
                                _heartbeat = spawn_heartbeat(dvc_tx.clone(), downgraded_caps.heartbeat_interval());
                                init_progress.set_heartbeats_enabled(heartbeats_enabled(downgraded_caps.heartbeat_interval()));

                                // Old exec sessions will be abandoned (IO loops will terminate
                                // on old processor `Drop`).
                                processor = MessageProcessor::new(
                                    downgraded_caps.clone(),
                                    dvc_tx.clone(),
                                    io_notification_tx.clone(),
                                    pwsh_executable.clone(),
                                );

                                dvc_tx.send(downgraded_caps.into()).await?;
                            }
                            Err(error) => {
                                error!(%error, "Failed to process DVC message");
                                return Err(error);
                            }
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Read channel has been closed"));
                    }
                }
            }
            task_rx = task_rx.recv() => {
                match task_rx {
                    Some(notification) => {
                        match notification {
                            ServerChannelEvent::SessionStarted { session_id } => {
                                info!(session_id, "Session started");
                                let message = NowExecStartedMsg::new(session_id);
                                dvc_tx.send(message.into()).await?;
                            }
                            ServerChannelEvent::SessionDataOut { session_id, stream, last, data } => {
                                let message = NowExecDataMsg::new(session_id, stream, last, data)?;
                                dvc_tx.send(message.into()).await?;
                            }
                            ServerChannelEvent::SessionCancelSuccess { session_id } => {
                                info!(session_id, "Session cancelled");
                                let message = NowExecCancelRspMsg::new_success(session_id);
                                dvc_tx.send(message.into()).await?;
                            }
                            ServerChannelEvent::SessionCancelFailed { session_id, error } => {
                                error!(session_id, %error, "Session cancel failed");
                                let message = NowExecCancelRspMsg::new_error(session_id, error)?;
                                dvc_tx.send(message.into()).await?;
                            }
                            ServerChannelEvent::SessionExited { session_id, exit_code } => {
                                info!(session_id, %exit_code, "Session exited");
                                processor.remove_session(session_id);
                                discard_pending_stdin(&mut pending_stdin, session_id);

                                let message = NowExecResultMsg::new_success(session_id, exit_code);
                                dvc_tx.send(message.into()).await?;
                            }
                            ServerChannelEvent::SessionFailed { session_id, error } => {
                                error!(session_id, %error, "Session error");
                                processor.remove_session(session_id);
                                discard_pending_stdin(&mut pending_stdin, session_id);

                                handle_exec_error(&dvc_tx, session_id, error).await;
                            }
                            ServerChannelEvent::WindowRecordingEvent { message } => {
                                if let Err(error) = handle_window_recording_event(&dvc_tx, message).await {
                                    error!(%error, "Failed to handle window recording event");
                                }
                            }
                            ServerChannelEvent::CloseChannel => {
                                info!("Received close channel notification, shutting down...");

                                let message = NowChannelCloseMsg::default();
                                dvc_tx.send(message.into()).await?;

                                processor.shutdown_all_sessions().await;

                                return Ok(());
                            }
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Task channel has been closed"));
                    }
                }
            }
            _ = shutdown_signal.wait() => {
                processor.shutdown_all_sessions().await;
                return Ok(());
            }
        }
    }
}

/// Emits heartbeats on a dedicated task for a negotiated interval.
///
/// Message handlers run inside the processing loop and can pend for a long time, for instance when a child process
/// stops reading its stdin; a heartbeat driven by that loop would stall with them while the outbound transport stays
/// usable.
/// Returns `None` when heartbeats are disabled.
/// Dropping the returned task stops the heartbeats.
fn spawn_heartbeat(
    dvc_tx: WinapiSignaledSender<OwnedNowMessage>,
    negotiated_interval: Option<core::time::Duration>,
) -> Option<ChildTask<()>> {
    let mut timer = heartbeat_timer(negotiated_interval)?;

    Some(ChildTask::spawn(async move {
        loop {
            timer.tick().await;

            if let Err(error) = dvc_tx.send(NowChannelHeartbeatMsg::default().into()).await {
                // The processing loop observes the same closed channel and ends the task.
                warn!(%error, "Failed to queue heartbeat; stopping heartbeats");
                return;
            }
        }
    }))
}

/// Builds the heartbeat timer for a negotiated interval.
///
/// The first tick is one period away, and a zero interval disables heartbeats entirely, as specified for
/// `NOW_CHANNEL_SET_HEARTBEAT`.
/// Without a negotiated interval, [`DEFAULT_HEARTBEAT_INTERVAL`] applies.
fn heartbeat_timer(negotiated_interval: Option<core::time::Duration>) -> Option<Interval> {
    if !heartbeats_enabled(negotiated_interval) {
        return None;
    }

    let period = negotiated_interval.unwrap_or(DEFAULT_HEARTBEAT_INTERVAL);
    let mut timer = tokio::time::interval_at(Instant::now() + period, period);
    timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

    Some(timer)
}

/// Whether the server may send heartbeats for a negotiated interval.
///
/// Only a zero interval disables them; without a negotiated interval, [`DEFAULT_HEARTBEAT_INTERVAL`] applies.
fn heartbeats_enabled(negotiated_interval: Option<core::time::Duration>) -> bool {
    !negotiated_interval.unwrap_or(DEFAULT_HEARTBEAT_INTERVAL).is_zero()
}

fn default_server_caps(pwsh_available: bool) -> NowChannelCapsetMsg {
    let mut exec_flags = NowExecCapsetFlags::STYLE_RUN
        | NowExecCapsetFlags::STYLE_PROCESS
        | NowExecCapsetFlags::STYLE_BATCH
        | NowExecCapsetFlags::STYLE_WINPS
        | NowExecCapsetFlags::IO_REDIRECTION
        | NowExecCapsetFlags::UNICODE_CONSOLE;

    if pwsh_available {
        exec_flags |= NowExecCapsetFlags::STYLE_PWSH;
    }

    NowChannelCapsetMsg::default()
        .with_system_capset(NowSystemCapsetFlags::SHUTDOWN)
        .with_session_capset(
            NowSessionCapsetFlags::LOCK
                | NowSessionCapsetFlags::LOGOFF
                | NowSessionCapsetFlags::MSGBOX
                | NowSessionCapsetFlags::SET_KBD_LAYOUT
                | NowSessionCapsetFlags::WINDOW_RECORDING,
        )
        .with_exec_capset(exec_flags)
}

/// Resolves the pwsh (PowerShell 7+) executable via `SearchPathW` with a null search path,
/// which follows the same search order as `CreateProcessW` (application directory, current
/// directory, system directories and the `PATH` environment variable).
fn find_pwsh_executable() -> Option<String> {
    let file_name = WideString::from("pwsh.exe");

    // SAFETY: FFI call with no outstanding preconditions; a null search path selects the
    // default `CreateProcessW`-like search order.
    let required_len = unsafe { SearchPathW(PCWSTR::null(), file_name.as_pcwstr(), PCWSTR::null(), None, None) };

    if required_len == 0 {
        return None;
    }

    let mut buffer = vec![0u16; usize::try_from(required_len).ok()?];

    // SAFETY: FFI call; the buffer is valid for writes of `required_len` UTF-16 code units.
    let len = unsafe {
        SearchPathW(
            PCWSTR::null(),
            file_name.as_pcwstr(),
            PCWSTR::null(),
            Some(buffer.as_mut_slice()),
            None,
        )
    };

    let len = usize::try_from(len).ok()?;

    // On success, the returned length excludes the terminating null and must fit the buffer.
    if len == 0 || len >= buffer.len() {
        return None;
    }

    String::from_utf16(&buffer[..len]).ok()
}

type StdinSend = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

/// Drops a stdin send for a session that has ended, so its input no longer holds back other messages.
fn discard_pending_stdin(pending_stdin: &mut Option<(u32, StdinSend)>, ended_session_id: u32) {
    if pending_stdin
        .as_ref()
        .is_some_and(|(session_id, _)| *session_id == ended_session_id)
    {
        *pending_stdin = None;
    }
}

enum ProcessMessageAction {
    Continue,
    Shutdown,
    Restart(NowChannelCapsetMsg),
    /// Stdin for a session; later messages wait for it so input stays ordered and a full stdin queue pushes back.
    SendStdin {
        session_id: u32,
        send: StdinSend,
    },
}

struct MessageProcessor {
    dvc_tx: WinapiSignaledSender<OwnedNowMessage>,
    io_notification_tx: Sender<ServerChannelEvent>,
    #[allow(dead_code)] // Not yet used.
    capabilities: NowChannelCapsetMsg,
    /// Attached execution sessions of this channel.
    ///
    /// Ending the channel or renegotiating capabilities stops only their IO; the processes keep running.
    /// No later channel or negotiation can reach them, because each starts with no sessions.
    sessions: HashMap<u32, WinApiProcess>,
    rdm_handler: RdmMessageProcessor,
    /// Resolved pwsh executable path; `None` when pwsh is not installed.
    pwsh_executable: Option<String>,
    /// Shutdown signal sender for window monitoring task.
    window_monitor_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Handle for the window monitor task.
    window_monitor_handle: Option<tokio::task::JoinHandle<()>>,
}

impl MessageProcessor {
    pub(crate) fn new(
        capabilities: NowChannelCapsetMsg,
        dvc_tx: WinapiSignaledSender<OwnedNowMessage>,
        io_notification_tx: Sender<ServerChannelEvent>,
        pwsh_executable: Option<String>,
    ) -> Self {
        let rdm_handler = RdmMessageProcessor::new(dvc_tx.clone());
        Self {
            dvc_tx,
            io_notification_tx,
            capabilities,
            sessions: HashMap::new(),
            rdm_handler,
            pwsh_executable,
            window_monitor_shutdown_tx: None,
            window_monitor_handle: None,
        }
    }

    async fn ensure_session_id_free(&self, session_id: u32) -> Result<(), ExecError> {
        if self.sessions.contains_key(&session_id) {
            warn!(session_id, "Session ID is in use");
            return Err(ExecError::NowStatus(NowStatusError::new_proto(NowProtoError::InUse)));
        }

        warn!(session_id, "Session ID is free for use");

        Ok(())
    }

    async fn send_detached_process_success(&self, session_id: u32) -> Result<(), ExecError> {
        self.io_notification_tx
            .send(ServerChannelEvent::SessionExited {
                session_id,
                exit_code: 0,
            })
            .await?;
        Ok(())
    }

    pub(crate) async fn process_message(&mut self, message: OwnedNowMessage) -> anyhow::Result<ProcessMessageAction> {
        match message {
            NowMessage::Channel(NowChannelMessage::Capset(client_caps)) => {
                return Ok(ProcessMessageAction::Restart(client_caps));
            }
            NowMessage::Channel(NowChannelMessage::Close(_)) => {
                info!("Received channel close message, shutting down...");
                return Ok(ProcessMessageAction::Shutdown);
            }
            NowMessage::Exec(NowExecMessage::Run(exec_msg)) => {
                let session_id = exec_msg.session_id();
                // Execute synchronously; ShellExecute will not block the calling thread,
                // For "Run" we are only interested in fire-and-forget execution.
                match self.process_exec_run(exec_msg).await {
                    Ok(()) => {}
                    Err(error) => {
                        handle_exec_error(&self.dvc_tx, session_id, error).await;
                    }
                }
            }
            NowMessage::Exec(NowExecMessage::Process(exec_msg)) => {
                let session_id = exec_msg.session_id();
                match self.process_exec_process(exec_msg).await {
                    Ok(()) => {}
                    Err(error) => {
                        handle_exec_error(&self.dvc_tx, session_id, error).await;
                    }
                }
            }
            NowMessage::Exec(NowExecMessage::Batch(batch_msg)) => {
                let session_id = batch_msg.session_id();
                match self.process_exec_batch(batch_msg).await {
                    Ok(()) => {}
                    Err(error) => {
                        handle_exec_error(&self.dvc_tx, session_id, error).await;
                    }
                }
            }
            NowMessage::Exec(NowExecMessage::WinPs(winps_msg)) => {
                let session_id = winps_msg.session_id();
                match self.process_exec_winps(winps_msg).await {
                    Ok(()) => {}
                    Err(error) => {
                        handle_exec_error(&self.dvc_tx, session_id, error).await;
                    }
                }
            }
            NowMessage::Exec(NowExecMessage::Pwsh(pwsh_msg)) => {
                let session_id = pwsh_msg.session_id();
                match self.process_exec_pwsh(pwsh_msg).await {
                    Ok(()) => {}
                    Err(error) => {
                        handle_exec_error(&self.dvc_tx, session_id, error).await;
                    }
                }
            }
            NowMessage::Exec(NowExecMessage::Abort(abort_msg)) => {
                let session_id = abort_msg.session_id();

                let process = match self.sessions.get_mut(&session_id) {
                    Some(process) => process,
                    None => {
                        warn!(session_id, "Session not found (abort)");
                        return Ok(ProcessMessageAction::Continue);
                    }
                };

                process.abort_execution(abort_msg.exit_code()).await?;

                // We could drop session immediately after abort as client do not expect any further
                // communication.
                let _ = self.sessions.remove(&session_id);
            }
            NowMessage::Exec(NowExecMessage::CancelReq(cancel_msg)) => {
                let session_id = cancel_msg.session_id();

                let process = match self.sessions.get_mut(&session_id) {
                    Some(process) => process,
                    None => {
                        warn!(session_id, "Session not found (cancel)");

                        let error = NowStatusError::new_proto(NowProtoError::NotFound);
                        let message = NowExecCancelRspMsg::new_error(session_id, error)
                            .expect("NowStatusError without message serialization always succeeds")
                            .into_owned();

                        self.dvc_tx.send(message.into()).await?;

                        return Ok(ProcessMessageAction::Continue);
                    }
                };

                process.cancel_execution().await?;
            }
            NowMessage::Exec(NowExecMessage::Data(data_msg)) => {
                let session_id = data_msg.session_id();

                if data_msg.stream_kind()? != NowExecDataStreamKind::Stdin {
                    warn!(session_id, "Only STDIN data input is supported");
                    return Ok(ProcessMessageAction::Continue);
                }

                let process = match self.sessions.get_mut(&session_id) {
                    Some(process) => process,
                    None => {
                        warn!(session_id, "Session not found (data)");

                        // Ignore data for non-existing session.
                        return Ok(ProcessMessageAction::Continue);
                    }
                };

                let send = process.send_stdin(data_msg.data().to_vec(), data_msg.is_last());

                return Ok(ProcessMessageAction::SendStdin {
                    session_id,
                    send: Box::pin(send),
                });
            }
            NowMessage::Session(NowSessionMessage::MsgBoxReq(request)) => {
                let tx = self.dvc_tx.clone();

                // Spawn separate async task for message box to avoid blocking the IO loop.
                let _task = tokio::task::spawn(process_msg_box_req(request, tx));
            }
            NowMessage::Session(NowSessionMessage::Logoff(_logoff_msg)) => {
                // SAFETY: FFI call with no outstanding preconditions.
                if let Err(error) = unsafe { ExitWindowsEx(EWX_LOGOFF, SHUTDOWN_REASON(0)) } {
                    error!(%error, "Failed to logoff user session");
                }
            }
            NowMessage::Session(NowSessionMessage::Lock(_lock_msg)) => {
                // SAFETY: FFI call with no outstanding preconditions.
                if let Err(error) = unsafe { LockWorkStation() } {
                    error!(%error, "Failed to lock workstation");
                }
            }
            NowMessage::Session(NowSessionMessage::SetKbdLayout(message)) => {
                if let Err(error) = set_kbd_layout(message.layout()) {
                    error!(%error, "Failed to set keyboard layout");
                }
            }
            NowMessage::Session(NowSessionMessage::WindowRecStart(start_msg)) => {
                if let Err(error) = self.start_window_recording(start_msg).await {
                    error!(%error, "Failed to start window recording");
                }
            }
            NowMessage::Session(NowSessionMessage::WindowRecStop(_stop_msg)) => {
                self.stop_window_recording().await;
            }
            NowMessage::System(NowSystemMessage::Shutdown(shutdown_msg)) => {
                let mut current_process_token =
                    Process::current_process().token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
                let mut _priv_tcb = ScopedPrivileges::enter(
                    &mut current_process_token,
                    &[win_api_wrappers::security::privilege::SE_SHUTDOWN_NAME],
                )?;

                let mut shutdown_flags = if shutdown_msg.is_reboot() {
                    EWX_REBOOT
                } else {
                    EWX_POWEROFF
                };

                if shutdown_msg.is_force_shutdown() {
                    shutdown_flags |= EWX_FORCE;
                }

                let message = (!shutdown_msg.message().is_empty()).then(|| WideString::from(shutdown_msg.message()));

                let timeout = match u32::try_from(shutdown_msg.timeout().as_secs()) {
                    Ok(timeout) => timeout,
                    Err(_) => {
                        error!("Invalid shutdown timeout");
                        return Ok(ProcessMessageAction::Continue);
                    }
                };

                // SAFETY: lpmessage is a valid null-terminated string.
                let shutdown_result = unsafe {
                    InitiateSystemShutdownW(
                        PCWSTR::null(),
                        message.map(|m| m.as_pcwstr()).unwrap_or(PCWSTR::null()),
                        timeout,
                        shutdown_msg.is_force_shutdown(),
                        shutdown_msg.is_reboot(),
                    )
                };

                if let Err(err) = shutdown_result {
                    warn!(%err, "Failed to initiate system shutdown");
                    return Ok(ProcessMessageAction::Continue);
                }

                // TODO: Adjust `NowSession` token privileges in NowAgent to make shutdown possible
                // from this process.
            }
            NowMessage::Rdm(NowRdmMessage::Capabilities(rdm_caps_msg)) => {
                // Capability responses are matched by send order, so the request is answered even
                // when processing fails; only an unbuildable fallback reply ends the channel.
                let processed = self.rdm_handler.process_capabilities(rdm_caps_msg).await;
                let response_msg = RdmMessageProcessor::capabilities_reply(processed)?;

                self.dvc_tx.send(response_msg).await?;
            }
            NowMessage::Rdm(NowRdmMessage::AppStart(rdm_app_start_msg)) => {
                // Start RDM in background task (non-blocking) - needs capabilities
                self.rdm_handler
                    .process_app_start(rdm_app_start_msg, self.capabilities.clone());
                info!("RDM application start initiated in background");
            }
            NowMessage::Rdm(other_rdm_msg) => {
                // Forward all other RDM messages (including AppAction) to RDM via pipe
                match self.rdm_handler.forward_message(other_rdm_msg).await {
                    Ok(()) => {
                        info!("RDM message forwarded to pipe successfully");
                    }
                    Err(error) => {
                        error!(%error, "Failed to forward RDM message to pipe");
                    }
                }
            }
            _ => {
                warn!("Unsupported message: {:?}", message);
            }
        }

        Ok(ProcessMessageAction::Continue)
    }

    async fn process_exec_run(&self, params: NowExecRunMsg<'_>) -> Result<(), ExecError> {
        self.ensure_session_id_free(params.session_id()).await?;

        let session_id = params.session_id();

        // Empty null-terminated string.
        let parameters = WideString::from("");
        let operation = WideString::from("open");
        let command: WideString = WideString::from(params.command());
        let directory = params.directory().map(WideString::from);

        info!(session_id, "Executing ShellExecuteW");

        // UNTESTED: Keep the directory buffer alive through ShellExecuteW; consuming it creates a dangling pointer.
        // Check the borrow when changing argument conversion; a successful launch cannot prove pointer validity.
        // SAFETY: All buffers are borrowed from locals that remain alive through the call.
        let hinstance = unsafe {
            ShellExecuteW(
                None,
                operation.as_pcwstr(),
                command.as_pcwstr(),
                parameters.as_pcwstr(),
                directory.as_ref().map_or_else(PCWSTR::null, WideString::as_pcwstr),
                // Activate and show window
                SW_RESTORE,
            )
        };

        if hinstance.0 as usize <= 32 {
            #[allow(clippy::cast_sign_loss)] // Not relevant for error codes.
            let code = win_api_wrappers::Error::last_error().code() as u32;
            error!("ShellExecuteW failed, error code: {}", code);

            return Err(ExecError::NowStatus(NowStatusError::new_winapi(code)));
        };

        let message = NowExecResultMsg::new_success(session_id, 0).into_owned().into();

        self.dvc_tx.send(message).await?;

        // We do not need to track this session, as it is fire-and-forget.

        Ok(())
    }

    async fn process_exec_process(&mut self, exec_msg: NowExecProcessMsg<'_>) -> Result<(), ExecError> {
        self.ensure_session_id_free(exec_msg.session_id()).await?;

        // Process exec: no assumptions about encoding by default (raw passthrough).
        // When ENCODING_UTF8 is set, transcode IO between OEM codepage and UTF-8.
        let io_encoding = if exec_msg.is_encoding_utf8() {
            DataEncoding::from_oem_codepage()
        } else {
            DataEncoding::Raw
        };

        let mut run_process = WinApiProcessBuilder::new(exec_msg.filename()).with_encoding(io_encoding);

        if let Some(parameters) = exec_msg.parameters() {
            run_process = run_process.with_command_line(parameters);
        }

        if let Some(directory) = exec_msg.directory() {
            run_process = run_process.with_current_directory(directory);
        }

        if exec_msg.is_detached() {
            // Detached mode: fire-and-forget, no IO redirection
            run_process.run_detached(exec_msg.session_id())?;
            self.send_detached_process_success(exec_msg.session_id()).await?;
            return Ok(());
        }

        let process = run_process
            .with_io_redirection(exec_msg.is_with_io_redirection())
            .run(exec_msg.session_id(), self.io_notification_tx.clone())?;

        self.sessions.insert(exec_msg.session_id(), process);

        Ok(())
    }

    async fn process_exec_batch(&mut self, batch_msg: NowExecBatchMsg<'_>) -> Result<(), ExecError> {
        self.ensure_session_id_free(batch_msg.session_id()).await?;

        let mut script = batch_msg.command().to_owned();

        // Batch exec encoding logic:
        // - Default: transcode OEM ↔ UTF-8
        // - RAW_ENCODING: pass through raw bytes without transcoding.
        // - UNICODE_CONSOLE: inject `@chcp 65001`, write file as BOM-less UTF-8, IO passthrough.
        let (file_encoding, io_encoding) = if batch_msg.is_unicode_console() {
            script = format!("{BATCH_UTF8_PREAMBLE}\r\n{script}");
            (DataEncoding::Raw, DataEncoding::Raw)
        } else if batch_msg.is_raw_encoding() {
            (DataEncoding::from_oem_codepage(), DataEncoding::Raw)
        } else {
            (DataEncoding::from_oem_codepage(), DataEncoding::from_oem_codepage())
        };

        let tmp_file = TmpFileGuard::new("bat")?;
        tmp_file.write_bytes(&file_encoding.encode_str(&script))?;

        let parameters = format!("/Q /C \"{}\"", tmp_file.path_string());

        let mut run_batch = WinApiProcessBuilder::new("cmd.exe")
            .with_temp_file(tmp_file)
            .with_command_line(&parameters)
            .with_encoding(io_encoding);

        if let Some(directory) = batch_msg.directory() {
            run_batch = run_batch.with_current_directory(directory);
        }

        if batch_msg.is_detached() {
            run_batch.run_detached(batch_msg.session_id())?;
            self.send_detached_process_success(batch_msg.session_id()).await?;
            return Ok(());
        }

        let process = run_batch
            .with_io_redirection(batch_msg.is_with_io_redirection())
            .run(batch_msg.session_id(), self.io_notification_tx.clone())?;

        self.sessions.insert(batch_msg.session_id(), process);

        Ok(())
    }

    async fn process_exec_winps(&mut self, winps_msg: NowExecWinPsMsg<'_>) -> Result<(), ExecError> {
        self.ensure_session_id_free(winps_msg.session_id()).await?;

        let mut params = Vec::new();
        append_ps_args(&mut params, &winps_msg);

        // WinPs exec encoding logic:
        // - Script file is ALWAYS written as UTF-8 with BOM (PS 5.x needs BOM to detect UTF-8).
        // - Default IO: transcode OEM ↔ UTF-8
        // - RAW_ENCODING or UNICODE_CONSOLE: pass through raw bytes (UTF-8 passthrough).
        let io_encoding = if winps_msg.is_unicode_console() || winps_msg.is_raw_encoding() {
            DataEncoding::Raw
        } else {
            DataEncoding::from_oem_codepage()
        };

        let tmp_file = if winps_msg.is_server_mode() {
            params.push("-s".to_owned());
            None
        } else {
            let mut script = winps_msg.command().to_owned();
            if winps_msg.is_unicode_console() {
                // Inject UTF-8 encoding setup for Windows PowerShell.
                script = format!("{POWERSHELL_UTF8_ENCODING_PREAMBLE}\r\n{script}");
            }
            let tmp_file = TmpFileGuard::new("ps1")?;
            tmp_file.write_content_utf8_bom(&script)?;
            params.push("-Command".to_owned());
            params.push(format!("\"{}\"", tmp_file.path_string()));
            Some(tmp_file)
        };

        let params_str = params.join(" ");
        let mut run_process = WinApiProcessBuilder::new("powershell.exe")
            .with_command_line(&params_str)
            .with_encoding(io_encoding);

        if let Some(tmp_file) = tmp_file {
            run_process = run_process.with_temp_file(tmp_file);
        }

        if let Some(directory) = winps_msg.directory() {
            run_process = run_process.with_current_directory(directory);
        }

        if winps_msg.is_detached() {
            run_process.run_detached(winps_msg.session_id())?;
            self.send_detached_process_success(winps_msg.session_id()).await?;
            return Ok(());
        }

        let process = run_process
            .with_io_redirection(winps_msg.is_with_io_redirection())
            .run(winps_msg.session_id(), self.io_notification_tx.clone())?;

        self.sessions.insert(winps_msg.session_id(), process);

        Ok(())
    }

    async fn process_exec_pwsh(&mut self, pwsh_msg: NowExecPwshMsg<'_>) -> Result<(), ExecError> {
        let Some(pwsh_executable) = self.pwsh_executable.clone() else {
            return Err(ExecError::NowStatus(NowStatusError::new_proto(
                NowProtoError::NotImplemented,
            )));
        };

        self.ensure_session_id_free(pwsh_msg.session_id()).await?;

        let mut params = Vec::new();
        append_pwsh_args(&mut params, &pwsh_msg);

        // Pwsh exec encoding logic (mirrors winps behavior):
        // - Script file is written as plain UTF-8 (pwsh reads UTF-8 natively, no BOM needed).
        // - Default IO: transcode OEM ↔ UTF-8 (pwsh still uses OEM encoding for console).
        // - RAW_ENCODING or UNICODE_CONSOLE: pass through raw bytes (UTF-8 passthrough).
        let io_encoding = if pwsh_msg.is_unicode_console() || pwsh_msg.is_raw_encoding() {
            DataEncoding::Raw
        } else {
            DataEncoding::from_oem_codepage()
        };

        let tmp_file = if pwsh_msg.is_server_mode() {
            params.push("-s".to_owned());
            None
        } else {
            let mut script = pwsh_msg.command().to_owned();
            if pwsh_msg.is_unicode_console() {
                // Inject UTF-8 encoding setup for PowerShell 7+.
                script = format!("{POWERSHELL_UTF8_ENCODING_PREAMBLE}\r\n{script}");
            }
            let tmp_file = TmpFileGuard::new("ps1")?;
            tmp_file.write_content(&script)?;
            params.push("-Command".to_owned());
            params.push(format!("\"{}\"", tmp_file.path_string()));
            Some(tmp_file)
        };

        let params_str = params.join(" ");
        let mut run_process = WinApiProcessBuilder::new(&pwsh_executable)
            .with_command_line(&params_str)
            .with_encoding(io_encoding)
            .with_env("NO_COLOR", "1");

        if let Some(tmp_file) = tmp_file {
            run_process = run_process.with_temp_file(tmp_file);
        }

        if let Some(directory) = pwsh_msg.directory() {
            run_process = run_process.with_current_directory(directory);
        }

        if pwsh_msg.is_detached() {
            run_process.run_detached(pwsh_msg.session_id())?;
            self.send_detached_process_success(pwsh_msg.session_id()).await?;
            return Ok(());
        }

        let process = run_process
            .with_io_redirection(pwsh_msg.is_with_io_redirection())
            .run(pwsh_msg.session_id(), self.io_notification_tx.clone())?;

        self.sessions.insert(pwsh_msg.session_id(), process);

        Ok(())
    }

    pub(crate) fn remove_session(&mut self, session_id: u32) {
        let _ = self.sessions.remove(&session_id);
    }

    pub(crate) async fn shutdown_all_sessions(&mut self) {
        for session in self.sessions.values() {
            let _ = session.shutdown().await;
        }

        self.sessions.clear();
    }

    async fn start_window_recording(&mut self, start_msg: NowSessionWindowRecStartMsg) -> anyhow::Result<()> {
        // Stop any existing window recording first.
        self.stop_window_recording().await;

        info!("Starting window recording");

        let track_title_changes = start_msg.flags.contains(WindowRecStartFlags::TRACK_TITLE_CHANGE);

        // Create shutdown channel for window monitor.
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Store shutdown sender so we can stop monitoring later.
        self.window_monitor_shutdown_tx = Some(shutdown_tx);

        // Spawn window monitor task.
        let event_tx = self.io_notification_tx.clone();
        let poll_interval = start_msg.poll_interval;
        let window_monitor_handle = tokio::task::spawn(async move {
            let mut config = WindowMonitorConfig::new(event_tx, track_title_changes, shutdown_rx);

            // Only set custom poll interval if specified (non-zero).
            if poll_interval > 0 {
                config = config.with_poll_interval_ms(u64::from(poll_interval));
            }

            if let Err(error) = run_window_monitor(config).await {
                error!(%error, "Window monitor failed");
            }
        });

        self.window_monitor_handle = Some(window_monitor_handle);

        Ok(())
    }

    async fn stop_window_recording(&mut self) {
        if let Some(shutdown_tx) = self.window_monitor_shutdown_tx.take() {
            info!("Stopping window recording");
            // Send shutdown signal (ignore errors if receiver was already dropped).
            let _ = shutdown_tx.send(());

            // Wait for the task to finish.
            if let Some(handle) = self.window_monitor_handle.take()
                && let Err(error) = handle.await
            {
                error!(%error, "Window monitor task panicked");
            }
        }
    }
}

fn append_ps_args(args: &mut Vec<String>, msg: &NowExecWinPsMsg<'_>) {
    if let Some(execution_policy) = msg.execution_policy() {
        args.push("-ExecutionPolicy".to_owned());
        args.push(execution_policy.to_owned());
    }

    if let Some(configuration_name) = msg.configuration_name() {
        args.push("-ConfigurationName".to_owned());
        args.push(configuration_name.to_owned());
    }

    if msg.is_no_logo() {
        args.push("-NoLogo".to_owned());
    }

    if msg.is_no_exit() {
        args.push("-NoExit".to_owned());
    }

    match msg.apartment_state() {
        Ok(Some(ComApartmentStateKind::Sta)) => {
            args.push("-Sta".to_owned());
        }
        Ok(Some(ComApartmentStateKind::Mta)) => {
            args.push("-Mta".to_owned());
        }
        Err(error) => {
            let session = msg.session_id();
            error!(%error, %session, "Failed to parse apartment state");
        }
        Ok(None) => {}
    }

    if msg.is_no_profile() {
        args.push("-NoProfile".to_owned());
    }

    if msg.is_non_interactive() {
        args.push("-NonInteractive".to_owned());
    }
}

fn append_pwsh_args(args: &mut Vec<String>, msg: &NowExecPwshMsg<'_>) {
    if let Some(execution_policy) = msg.execution_policy() {
        args.push("-ExecutionPolicy".to_owned());
        args.push(execution_policy.to_owned());
    }

    if let Some(configuration_name) = msg.configuration_name() {
        args.push("-ConfigurationName".to_owned());
        args.push(configuration_name.to_owned());
    }

    if msg.is_no_logo() {
        args.push("-NoLogo".to_owned());
    }

    if msg.is_no_exit() {
        args.push("-NoExit".to_owned());
    }

    match msg.apartment_state() {
        Ok(Some(ComApartmentStateKind::Sta)) => {
            args.push("-Sta".to_owned());
        }
        Ok(Some(ComApartmentStateKind::Mta)) => {
            args.push("-Mta".to_owned());
        }
        Err(error) => {
            let session = msg.session_id();
            error!(%error, %session, "Failed to parse apartment state");
        }
        Ok(None) => {}
    }

    if msg.is_no_profile() {
        args.push("-NoProfile".to_owned());
    }

    if msg.is_non_interactive() {
        args.push("-NonInteractive".to_owned());
    }
}

fn show_message_box<'a>(request: &OwnedNowSessionMsgBoxReqMsg) -> NowSessionMsgBoxRspMsg<'a> {
    info!("Processing message box request `{}`", request.request_id());

    let title = WideString::from(request.title().unwrap_or("Devolutions Session"));

    let text = WideString::from(request.message());

    let timeout = match request.timeout() {
        Some(timeout) => match u32::try_from(timeout.as_millis()) {
            Ok(timeout) => timeout,
            Err(_) => {
                return NowSessionMsgBoxRspMsg::new_error(
                    request.request_id(),
                    NowStatusError::new_proto(NowProtoError::InvalidRequest),
                )
                .expect("always fits into NowMessage frame");
            }
        },
        None => 0,
    };

    let result = if timeout == 0 {
        // SAFETY: text and title point to valid null-terminated strings.
        unsafe {
            MessageBoxW(
                None,
                text.as_pcwstr(),
                title.as_pcwstr(),
                MESSAGEBOX_STYLE(request.style().value()),
            )
        }
    } else {
        // Using undocumented message box with timeout API
        // (stable since Windows XP).

        // SAFETY: text and title point to valid null-terminated strings.
        unsafe {
            MessageBoxTimeOutW(
                HWND::default(),
                text.as_pcwstr(),
                title.as_pcwstr(),
                MESSAGEBOX_STYLE(request.style().value()),
                0,
                timeout,
            )
        }
    };

    #[allow(clippy::cast_sign_loss)]
    let message_box_response = result.0 as u32;

    NowSessionMsgBoxRspMsg::new_success(request.request_id(), NowMsgBoxResponse::new(message_box_response))
}

async fn process_msg_box_req(request: OwnedNowSessionMsgBoxReqMsg, dvc_tx: WinapiSignaledSender<OwnedNowMessage>) {
    let response = show_message_box(&request).into_owned();

    if !request.is_response_expected() {
        return;
    }

    if let Err(error) = dvc_tx.send(NowMessage::from(response)).await {
        error!(%error, "Failed to send MessageBox response");
    }
}

fn make_status_error_failsafe(session_id: u32, error: NowStatusError) -> OwnedNowExecResultMsg {
    NowExecResultMsg::new_error(session_id, error)
        .unwrap_or_else(|error| {
            warn!(%error, "Now status error message do not fit into NOW-PROTO error message; sending error without message");
            NowExecResultMsg::new_error(session_id, NowStatusError::new_generic(GENERIC_ERROR_CODE_TOO_LONG_ERROR))
                .expect("generic error without message always fits into NowMessage frame")
        })
}

fn make_generic_error_failsafe(session_id: u32, code: u32, message: String) -> OwnedNowExecResultMsg {
    let error = NowStatusError::new_generic(code);

    error
        .with_message(message.clone())
        .and_then(|error| NowExecResultMsg::new_error(session_id, error))
        .unwrap_or_else(|error| {
            warn!(%error, %code, %message, "Generic error message do not fit into NOW-PROTO error message; sending error without message");
            NowExecResultMsg::new_error(session_id, NowStatusError::new_generic(code))
                .expect("generic error without message always fits into NowMessage frame")
        })
}

async fn handle_window_recording_event(
    dvc_tx: &WinapiSignaledSender<OwnedNowMessage>,
    message: OwnedNowSessionWindowRecEventMsg,
) -> anyhow::Result<()> {
    dvc_tx.send(NowMessage::from(message.into_owned())).await?;

    Ok(())
}

async fn handle_exec_error(dvc_tx: &WinapiSignaledSender<OwnedNowMessage>, session_id: u32, error: ExecError) {
    let msg = match error {
        ExecError::NowStatus(status) => {
            warn!(%session_id, %status, "Process execution failed with NOW-PROTO error");
            make_status_error_failsafe(session_id, status)
        }
        ExecError::Aborted => {
            info!(%session_id, "Process execution was aborted due to service shutdown");
            make_status_error_failsafe(session_id, NowStatusError::new_proto(NowProtoError::Aborted))
        }
        ExecError::Encode(error) => {
            error!(%error, session_id, "Process execution thread failed with encoding error");

            // Convert to anyhow for pretty formatting with source.
            let error = anyhow::Error::from(error);

            make_generic_error_failsafe(session_id, GENERIC_ERROR_CODE_ENCODING, format!("{error:#}"))
        }
        ExecError::Other(error) => {
            error!(%error, session_id, "Process execution thread failed with unknown error");

            make_generic_error_failsafe(session_id, GENERIC_ERROR_CODE_OTHER, format!("{error:#}"))
        }
    }
    .into_owned();

    if let Err(error) = dvc_tx.send(msg.into()).await {
        error!(%error, "Failed to send error message");
    }
}

fn set_kbd_layout(layout: SetKbdLayoutOption<'_>) -> anyhow::Result<()> {
    // In contrast what many sources suggest, HWND returned by `GetForegroundWindow` is not reliable
    // for sending `WM_INPUTLANGCHANGEREQUEST` message to.
    // `GetFocus` API should be used instead to find thread which have keyboard input focus.
    let focused_window = get_focused_window()?;

    let locale = match layout {
        SetKbdLayoutOption::Next => isize::try_from(HKL_NEXT).expect("HKL_NEXT fits into isize"),
        SetKbdLayoutOption::Prev => isize::try_from(HKL_PREV).expect("HKL_PREV fits into isize"),
        SetKbdLayoutOption::Specific(layout) => {
            // IMPORTANT: WM_INPUTLANGCHANGEREQUEST message only respects low word of the layout
            // (locale) and high word (device) should be zero. Non-zero high word could produce
            // unexpected results (e.g. switching to next layout instead of specific one).
            //
            // Loading locale via LoadKeyboardLayoutW and passing it to WM_INPUTLANGCHANGEREQUEST
            // will not work as expected (even if dozen of sources suggest this approach) and
            // easily breaks with some layouts.

            let hex = u32::from_str_radix(layout, 16).context("invalid keyboard layout value")?;
            // device == (hex >> 16) && 0xFFFF
            let locale = u16::try_from(hex & 0xFFFF).expect("locale <= 0xFFFF");

            isize::try_from(locale).expect("locale fits into isize")
        }
    };

    // SAFETY: hwnd is valid window handle.
    unsafe {
        PostMessageW(
            Some(focused_window),
            WM_INPUTLANGCHANGEREQUEST,
            WPARAM(0),      // wParam is not used.
            LPARAM(locale), // lParam is locale (low word of layout identifier).
        )
        .context("failed to post WM_INPUTLANGCHANGEREQUEST message")
    }?;

    Ok(())
}

fn get_focused_window() -> anyhow::Result<HWND> {
    // SAFETY: FFI call with no outstanding preconditions.
    let foreground_window = unsafe { GetForegroundWindow() };

    if foreground_window.is_invalid() {
        bail!("Failed to get foreground window handle");
    }

    // SAFETY: FFI call with no outstanding preconditions.
    let foreground_thread = unsafe { GetWindowThreadProcessId(foreground_window, None) };

    if foreground_thread == 0 {
        bail!("Failed to get foreground window thread info");
    }

    // SAFETY: FFI call with no outstanding preconditions.
    let current_thread = unsafe { GetCurrentThreadId() };

    // SAFETY: FFI call with no outstanding preconditions.
    if unsafe { AttachThreadInput(current_thread, foreground_thread, true) } == false {
        bail!("Failed to attach thread input");
    }

    // SAFETY: FFI call with no outstanding preconditions.
    let focused_window = unsafe { GetFocus() };

    // SAFETY: Threads were successfully attached above.
    let _ = unsafe { AttachThreadInput(current_thread, foreground_thread, false) };

    // Bail only after we detach threads to avoid leaking resources.
    if focused_window.is_invalid() {
        bail!("Failed to get focused window handle");
    }

    Ok(focused_window)
}

#[link(name = "user32", kind = "dylib")]
unsafe extern "C" {
    #[link_name = "MessageBoxTimeoutW"]
    unsafe fn MessageBoxTimeOutW(
        hwnd: HWND,
        lptext: PCWSTR,
        lpcaption: PCWSTR,
        utype: MESSAGEBOX_STYLE,
        wlanguageid: u16,
        dwmillisedonds: u32,
    ) -> MESSAGEBOX_RESULT;
}

#[cfg(test)]
mod tests {
    use core::task::Poll;
    use core::time::Duration;
    use std::collections::VecDeque;

    use anyhow::anyhow;
    use devolutions_gateway_task::{ShutdownHandle, ShutdownSignal};
    use futures::poll;
    use now_proto_pdu::{
        NowChannelCapsetMsg, NowChannelCloseMsg, NowChannelMessage, NowExecCapsetFlags, NowExecMessage,
        NowExecProcessMsg, NowExecResultMsg, NowMessage, NowSessionCapsetFlags, NowSystemCapsetFlags, OwnedNowMessage,
    };
    use tokio::time::Instant;

    use super::{
        ChannelOutcome, DEFAULT_HEARTBEAT_INTERVAL, MAX_CONSECUTIVE_FAILED_REOPENS, REOPEN_DELAY_CAP,
        REOPEN_DELAY_FLOOR, heartbeat_timer, process_messages, process_until_io_ends, serve_dvc, spawn_heartbeat,
    };
    use crate::dvc::channel::{bounded_mpsc_channel, winapi_signaled_mpsc_channel};
    use crate::dvc::io::DvcInitializationProgress;

    // oracle: regression #2156 detached Process must leave the channel alive for subsequent execution.
    #[tokio::test]
    async fn detached_process_keeps_channel_available_for_execution() {
        let (write_tx, mut write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let (read_tx, read_rx) = bounded_mpsc_channel().expect("create inbound channel");
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let init_progress = DvcInitializationProgress::default();

        read_tx
            .send(NowChannelCapsetMsg::default().into())
            .await
            .expect("queue client capset");
        read_tx
            .send(
                NowExecProcessMsg::new(1, "cmd.exe")
                    .expect("valid executable")
                    .with_parameters("/d /c exit 0")
                    .expect("valid parameters")
                    .with_detached()
                    .into(),
            )
            .await
            .expect("queue detached process");

        let mut processing = Box::pin(process_messages(read_rx, write_tx, shutdown_signal, &init_progress));
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    result = &mut processing => panic!("processing ended before fresh execution completed: {result:?}"),
                    () = tokio::time::sleep(Duration::from_millis(10)) => {}
                }

                while let Ok(message) = write_rx.try_recv() {
                    if let NowMessage::Exec(NowExecMessage::Result(result)) = message {
                        if result.session_id() == 1 {
                            assert_eq!(result, NowExecResultMsg::new_success(1, 0));
                            read_tx
                                .send(
                                    NowExecProcessMsg::new(2, "cmd.exe")
                                        .expect("valid executable")
                                        .with_parameters("/d /c exit 7")
                                        .expect("valid parameters")
                                        .into(),
                                )
                                .await
                                .expect("queue fresh execution after detached acknowledgment");
                        } else {
                            assert_eq!(result, NowExecResultMsg::new_success(2, 7));
                            return;
                        }
                    }
                }
            }
        })
        .await
        .expect("fresh execution completes without the detached launch killing the host");

        read_tx
            .send(NowChannelCloseMsg::default().into())
            .await
            .expect("queue channel close");
        processing.await.expect("channel still accepts a normal close");
    }

    // oracle: mutant a full stdin queue prevents a closed DVC from interrupting the processing loop.
    #[tokio::test]
    async fn io_loss_interrupts_processing_while_stdin_is_backpressured() {
        let (stdin_tx, _stdin_rx) = tokio::sync::mpsc::channel(1);
        stdin_tx.send(()).await.expect("fill stdin queue");
        let processing = async move {
            stdin_tx.send(()).await.expect("stdin queue remains open");
            Ok(())
        };
        let (io_loop_ended_tx, io_loop_ended_rx) = tokio::sync::oneshot::channel();
        io_loop_ended_tx.send(()).expect("publish IO loop exit");

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            process_until_io_ends(processing, io_loop_ended_rx),
        )
        .await
        .expect("IO loss interrupts the blocked stdin send");

        assert!(result.is_err(), "transport loss must enter channel recovery");
    }

    // oracle: mutant IO teardown changes an already-completed normal protocol close into a transport failure.
    #[tokio::test]
    async fn completed_protocol_close_stays_normal_when_io_also_ends() {
        let (io_loop_ended_tx, io_loop_ended_rx) = tokio::sync::oneshot::channel();
        io_loop_ended_tx.send(()).expect("publish IO loop exit");

        process_until_io_ends(async { Ok(()) }, io_loop_ended_rx)
            .await
            .expect("normal protocol close remains normal");
    }

    /// A negotiated channel whose IO ends, as when the client tears the DVC down while the RDP connection stays up,
    /// must be told apart from one that never negotiated, because only the former is reopened.
    // oracle: scaffold
    #[tokio::test]
    async fn read_channel_closing_after_negotiation_loses_the_channel() {
        let (write_tx, _write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let (read_tx, read_rx) = bounded_mpsc_channel().expect("create inbound channel");
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let init_progress = DvcInitializationProgress::default();

        read_tx
            .send(NowChannelCapsetMsg::default().into())
            .await
            .expect("queue client capset");
        drop(read_tx);

        let result = process_messages(read_rx, write_tx, shutdown_signal, &init_progress).await;

        let outcome = ChannelOutcome::new(result, &init_progress);
        assert!(matches!(outcome, ChannelOutcome::Lost(_)), "{outcome:?}");
    }

    /// A channel whose IO ends before the client negotiates, as with a client that has no NOW listener, must not be
    /// classified as lost, so it is never reopened.
    // oracle: scaffold
    #[tokio::test]
    async fn read_channel_closing_before_negotiation_is_not_negotiated() {
        let (write_tx, _write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let (read_tx, read_rx) = bounded_mpsc_channel().expect("create inbound channel");
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let init_progress = DvcInitializationProgress::default();

        drop(read_tx);

        let result = process_messages(read_rx, write_tx, shutdown_signal, &init_progress).await;

        let outcome = ChannelOutcome::new(result, &init_progress);
        assert!(matches!(outcome, ChannelOutcome::NotNegotiated(_)), "{outcome:?}");
    }

    /// A channel the client closes on purpose must end rather than be reopened against the client's will.
    // oracle: spec Devolutions/now-proto@7519c6ff6cfa45bb70c3a3c67df2024d482eda53:protocols/docs/NOW-spec.md §NOW_CHANNEL_CLOSE_MSG
    #[tokio::test]
    async fn client_channel_close_ends_the_channel() {
        let (write_tx, _write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let (read_tx, read_rx) = bounded_mpsc_channel().expect("create inbound channel");
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let init_progress = DvcInitializationProgress::default();

        read_tx
            .send(NowChannelCapsetMsg::default().into())
            .await
            .expect("queue client capset");
        read_tx
            .send(NowChannelCloseMsg::default().into())
            .await
            .expect("queue channel close");

        let result = process_messages(read_rx, write_tx, shutdown_signal, &init_progress).await;

        let outcome = ChannelOutcome::new(result, &init_progress);
        assert!(matches!(outcome, ChannelOutcome::Ended), "{outcome:?}");
    }

    /// A first channel that never negotiates must end the loop, so a client without a NOW listener does not keep the
    /// process alive reopening a channel nobody serves.
    /// It ends without an error, because the agent relaunches a process that exits with one.
    // oracle: scaffold
    #[tokio::test(start_paused = true)]
    async fn unnegotiated_first_channel_is_not_reopened() {
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();

        let (result, _) = serve_script([not_negotiated()], shutdown_signal).await;

        result.expect("a client without a NOW listener is not a failure");
    }

    // oracle: scaffold
    #[tokio::test(start_paused = true)]
    async fn ended_channel_is_not_reopened() {
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();

        let (result, _) = serve_script([ChannelOutcome::Ended], shutdown_signal).await;

        result.expect("an ended channel ends the loop cleanly");
    }

    // oracle: scaffold
    #[tokio::test(start_paused = true)]
    async fn lost_channel_is_reopened_after_a_delay() {
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();

        let (result, served_at) = serve_script([lost(), ChannelOutcome::Ended], shutdown_signal).await;

        result.expect("the reopened channel ends the loop cleanly");
        assert!(REOPEN_DELAY_FLOOR <= served_at[1] - served_at[0]);
    }

    /// A client that stopped serving NOW must not be retried forever, nor in a tight loop.
    #[tokio::test(start_paused = true)]
    async fn reopen_gives_up_after_consecutive_unnegotiated_channels() {
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let script = core::iter::once(lost())
            .chain(core::iter::repeat_with(not_negotiated).take(MAX_CONSECUTIVE_FAILED_REOPENS));

        let (result, served_at) = serve_script(script, shutdown_signal).await;

        // oracle: scaffold
        assert!(result.is_err());

        let delays = served_at.windows(2).map(|w| w[1] - w[0]).collect::<Vec<_>>();
        // oracle: property monotonic
        assert!(delays.windows(2).all(|w| w[0] <= w[1]), "{delays:?}");
        // oracle: scaffold
        assert!(
            delays
                .iter()
                .all(|delay| REOPEN_DELAY_FLOOR <= *delay && *delay <= REOPEN_DELAY_CAP),
            "{delays:?}"
        );
    }

    /// A reopened channel that negotiates shows the client serves NOW again, so earlier failures must not count
    /// toward giving up.
    // oracle: scaffold
    #[tokio::test(start_paused = true)]
    async fn negotiated_reopen_resets_the_failure_budget() {
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let failures = || core::iter::repeat_with(not_negotiated).take(MAX_CONSECUTIVE_FAILED_REOPENS - 1);
        let script = core::iter::once(lost())
            .chain(failures())
            .chain(core::iter::once(lost()))
            .chain(failures())
            .chain(core::iter::once(ChannelOutcome::Ended));

        let (result, _) = serve_script(script, shutdown_signal).await;

        result.expect("failures before a negotiated reopen do not end the loop");
    }

    /// A shutdown requested while waiting to reopen must end the loop at once, without opening another channel.
    // oracle: scaffold
    #[tokio::test(start_paused = true)]
    async fn shutdown_during_reopen_delay_stops_without_reopening() {
        let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let mut served = 0;

        let mut serve = Box::pin(serve_dvc(
            || {
                served += 1;
                async { Ok(lost()) }
            },
            shutdown_signal,
        ));

        assert!(poll!(serve.as_mut()).is_pending());
        shutdown_handle.signal();

        let Poll::Ready(result) = poll!(serve.as_mut()) else {
            panic!("the loop is still waiting after shutdown");
        };
        result.expect("shutdown ends the loop cleanly");

        drop(serve);
        assert_eq!(served, 1);
    }

    /// The negotiation reply must be the downgraded capset, so the client sees the capabilities
    /// and heartbeat interval the agent applies rather than the server default, which carries no
    /// interval at all.
    #[tokio::test]
    async fn negotiation_replies_with_downgraded_capset() {
        let (write_tx, mut write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let (read_tx, read_rx) = bounded_mpsc_channel().expect("create inbound channel");
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let init_progress = DvcInitializationProgress::default();

        // STYLE_SHELL is not supported by the agent and must be removed; the agent advertises no
        // interval, so the client's one is the negotiated minimum.
        let client_caps = NowChannelCapsetMsg::default()
            .with_system_capset(NowSystemCapsetFlags::SHUTDOWN)
            .with_session_capset(NowSessionCapsetFlags::LOCK | NowSessionCapsetFlags::MSGBOX)
            .with_exec_capset(NowExecCapsetFlags::STYLE_RUN | NowExecCapsetFlags::STYLE_SHELL)
            .with_heartbeat_interval(Duration::from_secs(30))
            .expect("30 s is a valid heartbeat interval");

        let expected_caps = NowChannelCapsetMsg::default()
            .with_system_capset(NowSystemCapsetFlags::SHUTDOWN)
            .with_session_capset(NowSessionCapsetFlags::LOCK | NowSessionCapsetFlags::MSGBOX)
            .with_exec_capset(NowExecCapsetFlags::STYLE_RUN)
            .with_heartbeat_interval(Duration::from_secs(30))
            .expect("30 s is a valid heartbeat interval");

        read_tx.send(client_caps.into()).await.expect("queue client capset");
        read_tx
            .send(NowChannelCloseMsg::default().into())
            .await
            .expect("queue channel close");

        process_messages(read_rx, write_tx, shutdown_signal, &init_progress)
            .await
            .expect("negotiation followed by close completes cleanly");

        let reply = write_rx.try_recv().expect("negotiation reply was sent");

        let NowMessage::Channel(NowChannelMessage::Capset(reply)) = reply else {
            panic!("expected a NOW_CHANNEL_CAPSET reply, got {reply:?}");
        };

        assert_eq!(reply, expected_caps);
    }

    /// A zero interval means "heartbeat disabled" per `NOW_CHANNEL_SET_HEARTBEAT`; a timer for it
    /// would be always ready and flood the channel.
    #[test]
    fn zero_interval_disables_heartbeat() {
        assert!(heartbeat_timer(Some(Duration::ZERO)).is_none());
    }

    #[tokio::test]
    async fn missing_interval_uses_default() {
        let timer = heartbeat_timer(None).expect("default interval creates a timer");

        assert_eq!(timer.period(), DEFAULT_HEARTBEAT_INTERVAL);
    }

    #[tokio::test]
    async fn negotiated_interval_is_used() {
        let timer = heartbeat_timer(Some(Duration::from_secs(30))).expect("nonzero interval creates a timer");

        assert_eq!(timer.period(), Duration::from_secs(30));
    }

    /// Heartbeats must keep flowing while the processing loop is stuck inside a message handler,
    /// for instance on a child process that stopped reading its stdin; the outbound transport is
    /// still usable and a client watchdog must not drop the connection.
    #[tokio::test(start_paused = true)]
    async fn heartbeats_continue_while_processing_loop_is_blocked() {
        const PERIOD: Duration = Duration::from_secs(10);

        let (write_tx, mut write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let _heartbeat = spawn_heartbeat(write_tx, Some(PERIOD)).expect("nonzero interval spawns heartbeats");

        // Nothing else is polled from here on, which is exactly what a pending handler looks like.
        // The first heartbeat is a full period away, never immediate.
        tokio::task::yield_now().await;
        assert!(write_rx.try_recv().is_err(), "heartbeat sent immediately");

        for _ in 0..3 {
            tokio::time::advance(PERIOD).await;
            tokio::task::yield_now().await;

            assert_heartbeat(write_rx.try_recv().expect("heartbeat sent after one period"));
            assert!(write_rx.try_recv().is_err(), "more than one heartbeat per period");
        }
    }

    /// Dropping the heartbeat task, as renegotiation and loop exit do, must stop the heartbeats.
    #[tokio::test(start_paused = true)]
    async fn dropping_heartbeat_task_stops_heartbeats() {
        const PERIOD: Duration = Duration::from_secs(10);

        let (write_tx, mut write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let heartbeat = spawn_heartbeat(write_tx, Some(PERIOD)).expect("nonzero interval spawns heartbeats");

        // Let the task run and emit once, so the drop cancels a running task rather than one that never started.
        tokio::time::advance(PERIOD).await;
        tokio::task::yield_now().await;
        write_rx.try_recv().expect("heartbeat sent after one period");

        drop(heartbeat);

        tokio::time::advance(PERIOD * 3).await;
        tokio::task::yield_now().await;
        assert!(
            write_rx.try_recv().is_err(),
            "heartbeat sent after the task was dropped"
        );
    }

    #[tokio::test]
    async fn zero_interval_spawns_no_heartbeat_task() {
        let (write_tx, _write_rx) = winapi_signaled_mpsc_channel::<OwnedNowMessage>().expect("create outbound channel");

        assert!(spawn_heartbeat(write_tx, Some(Duration::ZERO)).is_none());
    }

    /// The processing loop must heartbeat at the negotiated interval, switch to the renegotiated one and stop the
    /// previous task when the client sends a new capset, and stop heartbeating when it exits.
    #[tokio::test(start_paused = true)]
    async fn processing_loop_heartbeats_follow_negotiation_and_stop_on_exit() {
        const FIRST_PERIOD: Duration = Duration::from_secs(30);
        const SECOND_PERIOD: Duration = Duration::from_secs(10);

        let (write_tx, mut write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let (read_tx, read_rx) = bounded_mpsc_channel().expect("create inbound channel");
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let init_progress = DvcInitializationProgress::default();

        let capset_with_interval = |period| {
            NowChannelCapsetMsg::default()
                .with_heartbeat_interval(period)
                .expect("valid heartbeat interval")
        };

        let mut loop_future = Box::pin(process_messages(read_rx, write_tx, shutdown_signal, &init_progress));

        read_tx
            .send(capset_with_interval(FIRST_PERIOD).into())
            .await
            .expect("queue client capset");
        assert!(poll!(loop_future.as_mut()).is_pending());
        write_rx.try_recv().expect("negotiation reply was sent");

        // Nothing polls the loop while time advances, like a pending handler.
        tokio::time::advance(FIRST_PERIOD).await;
        tokio::task::yield_now().await;
        assert_heartbeat(write_rx.try_recv().expect("heartbeat sent after the first period"));
        assert!(write_rx.try_recv().is_err(), "more than one heartbeat per period");

        read_tx
            .send(capset_with_interval(SECOND_PERIOD).into())
            .await
            .expect("queue renegotiation capset");
        assert!(poll!(loop_future.as_mut()).is_pending());
        write_rx.try_recv().expect("renegotiation reply was sent");

        // Three short periods cover the moment the first task would have fired again had it survived.
        for _ in 0..3 {
            tokio::time::advance(SECOND_PERIOD).await;
            tokio::task::yield_now().await;
            assert_heartbeat(
                write_rx
                    .try_recv()
                    .expect("heartbeat sent after the renegotiated period"),
            );
            assert!(write_rx.try_recv().is_err(), "more than one heartbeat per period");
        }

        read_tx
            .send(NowChannelCloseMsg::default().into())
            .await
            .expect("queue channel close");
        assert!(poll!(loop_future.as_mut()).is_ready());

        tokio::time::advance(SECOND_PERIOD * 3).await;
        tokio::task::yield_now().await;
        assert!(
            write_rx.try_recv().is_err(),
            "heartbeat sent after the processing loop ended"
        );
    }

    fn assert_heartbeat(message: OwnedNowMessage) {
        assert!(
            matches!(message, NowMessage::Channel(NowChannelMessage::Heartbeat(_))),
            "expected a heartbeat, got {message:?}"
        );
    }

    /// The IO thread probes a held-back channel with heartbeats only while this flag is set, so it must follow every
    /// negotiation: on by default, off for a zero interval, and on again when renegotiated to a nonzero one.
    // oracle: mutant
    #[tokio::test(start_paused = true)]
    async fn processing_loop_publishes_whether_heartbeats_are_enabled() {
        let (write_tx, mut write_rx) = winapi_signaled_mpsc_channel().expect("create outbound channel");
        let (read_tx, read_rx) = bounded_mpsc_channel().expect("create inbound channel");
        let (_shutdown_handle, shutdown_signal) = ShutdownHandle::new();
        let init_progress = DvcInitializationProgress::default();

        let mut loop_future = Box::pin(process_messages(read_rx, write_tx, shutdown_signal, &init_progress));

        let capsets = [
            (NowChannelCapsetMsg::default(), true),
            (capset_with_zero_heartbeat_interval(), false),
            (
                NowChannelCapsetMsg::default()
                    .with_heartbeat_interval(Duration::from_secs(30))
                    .expect("30 s is a valid heartbeat interval"),
                true,
            ),
        ];

        for (capset, expected) in capsets {
            read_tx.send(capset.into()).await.expect("queue client capset");
            assert!(poll!(loop_future.as_mut()).is_pending());
            write_rx.try_recv().expect("negotiation reply was sent");

            assert_eq!(init_progress.heartbeats_enabled(), expected);
        }
    }

    /// A client capset that disables heartbeats.
    ///
    /// `with_heartbeat_interval` refuses zero, but the wire format still carries it, so it is decoded from bytes.
    fn capset_with_zero_heartbeat_interval() -> NowChannelCapsetMsg {
        const NOW_CHANNEL_SET_HEARTBEAT: u8 = 0x01;
        const MSG_FLAGS_OFFSET: usize = 6;

        // The default capset already encodes a zero interval; only the flag announcing it is missing.
        let mut bytes = now_proto_pdu::ironrdp_core::encode_vec(&OwnedNowMessage::from(NowChannelCapsetMsg::default()))
            .expect("encode a capset");
        *bytes.get_mut(MSG_FLAGS_OFFSET).expect("the capset has a header") |= NOW_CHANNEL_SET_HEARTBEAT;

        let message: NowMessage<'_> = now_proto_pdu::ironrdp_core::decode(&bytes).expect("decode the capset");
        let NowMessage::Channel(NowChannelMessage::Capset(capset)) = message else {
            panic!("expected a capset, got {message:?}");
        };
        assert_eq!(capset.heartbeat_interval(), Some(Duration::ZERO));

        capset
    }

    /// Serves `outcomes` in order and returns the loop result with the instant each channel was served.
    ///
    /// Panics unless the loop serves every outcome and no more.
    async fn serve_script(
        outcomes: impl IntoIterator<Item = ChannelOutcome>,
        shutdown_signal: ShutdownSignal,
    ) -> (anyhow::Result<()>, Vec<Instant>) {
        let mut outcomes = outcomes.into_iter().collect::<VecDeque<_>>();
        let mut served_at = Vec::new();

        let result = serve_dvc(
            || {
                served_at.push(Instant::now());
                let outcome = outcomes.pop_front().expect("channel served more times than scripted");
                async { Ok(outcome) }
            },
            shutdown_signal,
        )
        .await;

        assert!(
            outcomes.is_empty(),
            "{} scripted channels were never served",
            outcomes.len()
        );

        (result, served_at)
    }

    fn lost() -> ChannelOutcome {
        ChannelOutcome::Lost(anyhow!("channel lost"))
    }

    fn not_negotiated() -> ChannelOutcome {
        ChannelOutcome::NotNegotiated(anyhow!("channel not negotiated"))
    }
}
