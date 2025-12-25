use std::collections::HashMap;

use anyhow::{Context, bail};
use async_trait::async_trait;
use devolutions_gateway_task::Task;
use now_proto_pdu::ironrdp_core::IntoOwned;
use now_proto_pdu::{
    ComApartmentStateKind, NowChannelCapsetMsg, NowChannelCloseMsg, NowChannelHeartbeatMsg, NowChannelMessage,
    NowExecBatchMsg, NowExecCancelRspMsg, NowExecCapsetFlags, NowExecDataMsg, NowExecDataStreamKind, NowExecMessage,
    NowExecProcessMsg, NowExecPwshMsg, NowExecResultMsg, NowExecRunMsg, NowExecStartedMsg, NowExecWinPsMsg, NowMessage,
    NowMsgBoxResponse, NowProtoError, NowProtoVersion, NowRdmMessage, NowSessionCapsetFlags, NowSessionMessage,
    NowSessionMsgBoxReqMsg, NowSessionMsgBoxRspMsg, NowStatusError, NowSystemCapsetFlags, NowSystemMessage,
    SetKbdLayoutOption,
};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, info, warn};
use win_api_wrappers::event::Event;
use win_api_wrappers::process::Process;
use win_api_wrappers::security::privilege::ScopedPrivileges;
use win_api_wrappers::utils::WideString;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
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
use crate::dvc::fs::TmpFileGuard;
use crate::dvc::io::run_dvc_io;
use crate::dvc::process::{ExecError, ServerChannelEvent, WinApiProcess, WinApiProcessBuilder};
use crate::dvc::rdm::RdmMessageProcessor;

// One minute heartbeat interval by default
const DEFAULT_HEARTBEAT_INTERVAL: core::time::Duration = core::time::Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(5);

const GENERIC_ERROR_CODE_ENCODING: u32 = 0x00000001;
const GENERIC_ERROR_CODE_TOO_LONG_ERROR: u32 = 0x00000002;
const GENERIC_ERROR_CODE_OTHER: u32 = 0xFFFFFFFF;

#[derive(Default)]
pub struct DvcIoTask {}

#[async_trait]
impl Task for DvcIoTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "DVC processing";

    async fn run(self, shutdown_signal: devolutions_gateway_task::ShutdownSignal) -> Self::Output {
        let (write_tx, write_rx) = winapi_signaled_mpsc_channel()?;
        let (read_tx, read_rx) = bounded_mpsc_channel()?;

        // WinAPI event to terminate DVC IO thread.
        let io_thread_shutdown_event = Event::new_unnamed()?;

        let cloned_shutdown_event = io_thread_shutdown_event.clone();

        info!(
            "Starting NowProto DVC v{}.{}",
            NowProtoVersion::CURRENT.major,
            NowProtoVersion::CURRENT.minor
        );

        // Spawning thread is relatively short operation, so it could be executed synchronously.
        let io_thread = std::thread::spawn(move || {
            let io_thread_result = run_dvc_io(write_rx, read_tx, cloned_shutdown_event);

            if let Err(error) = io_thread_result {
                error!(%error, "DVC IO thread failed");
            }
        });

        // Join thread some time in future.
        tokio::task::spawn_blocking(move || {
            if let Err(panic_payload) = io_thread.join() {
                if let Some(s) = panic_payload.downcast_ref::<&dyn std::fmt::Debug>() {
                    error!("DVC IO thread panic: {:?}", s);
                } else {
                    error!("DVC IO thread join failed.");
                }
            }
        });

        info!("Processing DVC messages...");

        let process_result = process_messages(read_rx, write_tx, shutdown_signal).await;

        // Send shutdown signal to IO thread to release WTS channel resources.
        info!("Shutting down DVC IO thread");
        let _ = io_thread_shutdown_event.set();

        process_result?;

        Ok(())
    }
}

async fn process_messages(
    mut read_rx: Receiver<NowMessage<'static>>,
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
    mut shutdown_signal: devolutions_gateway_task::ShutdownSignal,
) -> anyhow::Result<()> {
    let (io_notification_tx, mut task_rx) = mpsc::channel(100);

    // Wait for channel negotiation message and send downgraded capabilities back.
    let client_caps = select! {
        message = read_rx.recv() => {
            match message {
                Some(NowMessage::Channel(NowChannelMessage::Capset(caps))) => caps,
                Some(message) => {
                    return Err(anyhow::anyhow!("Unexpected negotiation message: {:?}", message));
                }
                None => {
                    return Err(anyhow::anyhow!("read channel has been closed before negotiation"));
                }
            }
        }
        _timeout = tokio::time::sleep(HANDSHAKE_TIMEOUT) =>
        {
            error!("Timeout waiting for DVC negotiation");
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

    let server_caps = default_server_caps();
    let heartbeat_interval = client_caps.heartbeat_interval().unwrap_or(DEFAULT_HEARTBEAT_INTERVAL);
    let downgraded_caps = client_caps.downgrade(&server_caps);

    // Send server capabilities back to the client.
    dvc_tx.send(server_caps.into()).await?;

    let mut processor = MessageProcessor::new(downgraded_caps, dvc_tx.clone(), io_notification_tx.clone());

    info!("DVC negotiation completed");

    loop {
        select! {
            read_result = read_rx.recv() => {
                match read_result {
                    Some(message) => {
                        match processor.process_message(message).await {
                            Ok(ProcessMessageAction::Continue) => {}
                            Ok(ProcessMessageAction::Shutdown) => {
                                info!("Received channel shutdown message...");
                                return Ok(());
                            }
                            Ok(ProcessMessageAction::Restart(client_caps)) => {
                                info!("Restarting DVC IO thread with new capabilities...");

                                // Re-negotiate capabilities with the client and initialize new
                                // message processor.
                                let server_caps = default_server_caps();
                                let downgraded_caps = client_caps.downgrade(&server_caps);

                                // Old exec sessions will be abandoned (IO loops will terminate
                                // on old processor `Drop`).
                                processor = MessageProcessor::new(
                                    downgraded_caps,
                                    dvc_tx.clone(),
                                    io_notification_tx.clone()
                                );

                                dvc_tx.send(server_caps.into()).await?;
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

                                let message = NowExecResultMsg::new_success(session_id, exit_code);
                                dvc_tx.send(message.into()).await?;
                            }
                            ServerChannelEvent::SessionFailed { session_id, error } => {
                                error!(session_id, %error, "Session error");
                                processor.remove_session(session_id);

                                handle_exec_error(&dvc_tx, session_id, error).await;
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
            _ = tokio::time::sleep(heartbeat_interval) => {
                // Send periodic heartbeat message to the client.
                dvc_tx.send(NowChannelHeartbeatMsg::default().into()).await?;
            }
            _ = shutdown_signal.wait() => {
                processor.shutdown_all_sessions().await;
                return Ok(());
            }
        }
    }
}

fn default_server_caps() -> NowChannelCapsetMsg {
    NowChannelCapsetMsg::default()
        .with_system_capset(NowSystemCapsetFlags::SHUTDOWN)
        .with_session_capset(
            NowSessionCapsetFlags::LOCK
                | NowSessionCapsetFlags::LOGOFF
                | NowSessionCapsetFlags::MSGBOX
                | NowSessionCapsetFlags::SET_KBD_LAYOUT,
        )
        .with_exec_capset(
            NowExecCapsetFlags::STYLE_RUN
                | NowExecCapsetFlags::STYLE_PROCESS
                | NowExecCapsetFlags::STYLE_BATCH
                | NowExecCapsetFlags::STYLE_PWSH
                | NowExecCapsetFlags::STYLE_WINPS
                | NowExecCapsetFlags::IO_REDIRECTION,
        )
}

enum ProcessMessageAction {
    Continue,
    Shutdown,
    Restart(NowChannelCapsetMsg),
}

struct MessageProcessor {
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
    io_notification_tx: Sender<ServerChannelEvent>,
    #[allow(dead_code)] // Not yet used.
    capabilities: NowChannelCapsetMsg,
    sessions: HashMap<u32, WinApiProcess>,
    rdm_handler: RdmMessageProcessor,
}

impl MessageProcessor {
    pub(crate) fn new(
        capabilities: NowChannelCapsetMsg,
        dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
        io_notification_tx: Sender<ServerChannelEvent>,
    ) -> Self {
        let rdm_handler = RdmMessageProcessor::new(dvc_tx.clone());
        Self {
            dvc_tx,
            io_notification_tx,
            capabilities,
            sessions: HashMap::new(),
            rdm_handler,
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

    pub(crate) async fn process_message(
        &mut self,
        message: NowMessage<'static>,
    ) -> anyhow::Result<ProcessMessageAction> {
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

                process.send_stdin(data_msg.data().to_vec(), data_msg.is_last()).await?;
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
                match self.rdm_handler.process_capabilities(rdm_caps_msg).await {
                    Ok(response_msg) => {
                        self.dvc_tx.send(response_msg).await?;
                    }
                    Err(error) => {
                        error!(%error, "Failed to process RDM capabilities message");
                    }
                }
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

        // SAFETY: All buffers are valid, therefore `ShellExecuteW` is safe to call.
        let hinstance = unsafe {
            ShellExecuteW(
                None,
                operation.as_pcwstr(),
                command.as_pcwstr(),
                parameters.as_pcwstr(),
                directory.map(|d| d.as_pcwstr()).unwrap_or(PCWSTR::null()),
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

        let mut run_process = WinApiProcessBuilder::new(exec_msg.filename());

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

        let tmp_file = TmpFileGuard::new("bat")?;
        tmp_file.write_content(batch_msg.command())?;

        // "/Q" - Turns command echo off.
        // "/C" - Carries out the command specified by string and then terminates.
        let parameters = format!("/Q /C \"{}\"", tmp_file.path_string());

        let mut run_batch = WinApiProcessBuilder::new("cmd.exe")
            .with_temp_file(tmp_file)
            .with_command_line(&parameters);

        if let Some(directory) = batch_msg.directory() {
            run_batch = run_batch.with_current_directory(directory);
        }

        if batch_msg.is_detached() {
            // Detached mode: fire-and-forget, no IO redirection
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

        let tmp_file = if winps_msg.is_server_mode() {
            // IMPORTANT: It is absolutely necessary to pass "-s" as the last parameter to make
            // PowerShell run in server mode.
            params.push("-s".to_owned());
            None
        } else {
            let tmp_file = TmpFileGuard::new("ps1")?;
            tmp_file.write_content(winps_msg.command())?;

            // "-Command" runs script without command echo and terminates.
            params.push("-Command".to_owned());
            params.push(format!("\"{}\"", tmp_file.path_string()));

            Some(tmp_file)
        };

        let params_str = params.join(" ");

        let mut run_process = WinApiProcessBuilder::new("powershell.exe").with_command_line(&params_str);

        if let Some(tmp_file) = tmp_file {
            run_process = run_process.with_temp_file(tmp_file);
        }

        if let Some(directory) = winps_msg.directory() {
            run_process = run_process.with_current_directory(directory);
        }

        if winps_msg.is_detached() {
            // Detached mode: fire-and-forget, no IO redirection
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

    async fn process_exec_pwsh(&mut self, winps_msg: NowExecPwshMsg<'_>) -> Result<(), ExecError> {
        self.ensure_session_id_free(winps_msg.session_id()).await?;

        let mut params = Vec::new();

        append_pwsh_args(&mut params, &winps_msg);

        let tmp_file = if winps_msg.is_server_mode() {
            // IMPORTANT: It is absolutely necessary to pass "-s" as the last parameter to make
            // PowerShell run in server mode.
            params.push("-s".to_owned());
            None
        } else {
            let tmp_file = TmpFileGuard::new("ps1")?;
            tmp_file.write_content(winps_msg.command())?;

            // "-Command" runs script without command echo and terminates.
            params.push("-Command".to_owned());
            params.push(format!("\"{}\"", tmp_file.path_string()));

            Some(tmp_file)
        };

        let params_str = params.join(" ");

        let mut run_process = WinApiProcessBuilder::new("pwsh.exe")
            .with_command_line(&params_str)
            .with_env("NO_COLOR", "1"); // Suppress ANSI escape codes in pwsh output.

        if let Some(tmp_file) = tmp_file {
            run_process = run_process.with_temp_file(tmp_file);
        }

        if let Some(directory) = winps_msg.directory() {
            run_process = run_process.with_current_directory(directory);
        }

        if winps_msg.is_detached() {
            // Detached mode: fire-and-forget, no IO redirection
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

    pub(crate) fn remove_session(&mut self, session_id: u32) {
        let _ = self.sessions.remove(&session_id);
    }

    pub(crate) async fn shutdown_all_sessions(&mut self) {
        for session in self.sessions.values() {
            let _ = session.shutdown().await;
        }

        self.sessions.clear();
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

fn show_message_box<'a>(request: &NowSessionMsgBoxReqMsg<'static>) -> NowSessionMsgBoxRspMsg<'a> {
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

async fn process_msg_box_req(
    request: NowSessionMsgBoxReqMsg<'static>,
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
) {
    let response = show_message_box(&request).into_owned();

    if !request.is_response_expected() {
        return;
    }

    if let Err(error) = dvc_tx.send(NowMessage::from(response)).await {
        error!(%error, "Failed to send MessageBox response");
    }
}

fn make_status_error_failsafe(session_id: u32, error: NowStatusError) -> NowExecResultMsg<'static> {
    NowExecResultMsg::new_error(session_id, error)
        .unwrap_or_else(|error| {
            warn!(%error, "Now status error message do not fit into NOW-PROTO error message; sending error without message");
            NowExecResultMsg::new_error(session_id, NowStatusError::new_generic(GENERIC_ERROR_CODE_TOO_LONG_ERROR))
                .expect("generic error without message always fits into NowMessage frame")
        })
}

fn make_generic_error_failsafe(session_id: u32, code: u32, message: String) -> NowExecResultMsg<'static> {
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

async fn handle_exec_error(dvc_tx: &WinapiSignaledSender<NowMessage<'static>>, session_id: u32, error: ExecError) {
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
