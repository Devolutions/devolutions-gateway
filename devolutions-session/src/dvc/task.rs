use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, bail};
use async_trait::async_trait;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM, CloseHandle};
use windows::Win32::Security::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::Shutdown::{
    EWX_FORCE, EWX_LOGOFF, EWX_POWEROFF, EWX_REBOOT, ExitWindowsEx, InitiateSystemShutdownW, LockWorkStation,
    SHUTDOWN_REASON,
};
use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId, CreateProcessW, WaitForSingleObject, PROCESS_INFORMATION, STARTUPINFOW, CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_QUERY_INFORMATION, TerminateProcess};
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::UI::Input::KeyboardAndMouse::GetFocus;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowThreadProcessId, HKL_NEXT, HKL_PREV, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE,
    MessageBoxW, PostMessageW, SW_RESTORE, SW_MAXIMIZE, SW_MINIMIZE, SW_SHOWMAXIMIZED, SW_SHOWNORMAL,
    ShowWindow, WM_INPUTLANGCHANGEREQUEST, WM_CLOSE, EnumWindows,
};
use windows::core::{PCWSTR, PWSTR};


use devolutions_gateway_task::Task;
use now_proto_pdu::ironrdp_core::IntoOwned;
use now_proto_pdu::{
    ComApartmentStateKind, NowChannelCapsetMsg, NowChannelCloseMsg, NowChannelHeartbeatMsg, NowChannelMessage,
    NowExecBatchMsg, NowExecCancelRspMsg, NowExecCapsetFlags, NowExecDataMsg, NowExecDataStreamKind, NowExecMessage,
    NowExecProcessMsg, NowExecPwshMsg, NowExecResultMsg, NowExecRunMsg, NowExecStartedMsg, NowExecWinPsMsg, NowMessage,
    NowMsgBoxResponse, NowProtoError, NowProtoVersion, NowRdmAppActionMsg, NowRdmAppAction, NowRdmAppNotifyMsg, NowRdmAppStartMsg, NowRdmCapabilitiesMsg, NowRdmMessage, NowRdmAppState, NowRdmReason, NowSessionCapsetFlags, NowSessionMessage,
    NowSessionMsgBoxReqMsg, NowSessionMsgBoxRspMsg, NowStatusError, NowSystemCapsetFlags, NowSystemMessage,
    SetKbdLayoutOption,
};
use win_api_wrappers::event::Event;
use win_api_wrappers::security::privilege::ScopedPrivileges;
use win_api_wrappers::utils::WideString;
use win_api_wrappers::process::{Process, ProcessEntry32Iterator};
use win_api_wrappers::handle::HandleWrapper;

use devolutions_agent_shared::windows::registry::{get_install_location, get_installed_product_version, ProductVersionEncoding};
use uuid::Uuid;

const RDM_UPDATE_CODE_UUID: &str = "2707F3BF-4D7B-40C2-882F-14B0ED869EE8";



use crate::dvc::channel::{WinapiSignaledSender, bounded_mpsc_channel, winapi_signaled_mpsc_channel};

use crate::dvc::fs::TmpFileGuard;
use crate::dvc::io::run_dvc_io;
use crate::dvc::process::{ExecError, ServerChannelEvent, WinApiProcess, WinApiProcessBuilder};

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

#[derive(Debug, Clone, Copy)]
enum WindowCommand {
    Minimize,
    Maximize,
    Restore,
}

struct MessageProcessor {
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
    io_notification_tx: Sender<ServerChannelEvent>,
    #[allow(dead_code)] // Not yet used.
    capabilities: NowChannelCapsetMsg,
    sessions: HashMap<u32, WinApiProcess>,
    rdm_process_spawned: Arc<AtomicBool>,
}

/// RAII wrapper for RDM process handle
struct RdmProcessHandle {
    handle: windows::Win32::Foundation::HANDLE,
}

// SAFETY: HANDLE is just a pointer and can be safely sent between threads
unsafe impl Send for RdmProcessHandle {}
unsafe impl Sync for RdmProcessHandle {}

impl RdmProcessHandle {
    fn new(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> windows::Win32::Foundation::HANDLE {
        self.handle
    }
}

impl Drop for RdmProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

impl MessageProcessor {
    pub(crate) fn new(
        capabilities: NowChannelCapsetMsg,
        dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
        io_notification_tx: Sender<ServerChannelEvent>,
    ) -> Self {
        Self {
            dvc_tx,
            io_notification_tx,
            capabilities,
            sessions: HashMap::new(),
            rdm_process_spawned: Arc::new(AtomicBool::new(false)),
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
                let mut current_process_token = Process::current_process()
                    .token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
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
                match self.process_rdm_capabilities(rdm_caps_msg).await {
                    Ok(response_msg) => {
                        self.dvc_tx.send(response_msg.into()).await?;
                    }
                    Err(error) => {
                        error!(%error, "Failed to process RDM capabilities message");
                    }
                }
            }
            NowMessage::Rdm(NowRdmMessage::AppStart(rdm_app_start_msg)) => {
                match self.process_rdm_app_start(rdm_app_start_msg).await {
                    Ok(()) => {
                        info!("RDM application started successfully");
                    }
                    Err(error) => {
                        error!(%error, "Failed to start RDM application");
                    }
                }
            }
            NowMessage::Rdm(NowRdmMessage::AppAction(rdm_app_action_msg)) => {
                match self.process_rdm_app_action(rdm_app_action_msg).await {
                    Ok(()) => {
                        info!("RDM application action processed successfully");
                    }
                    Err(error) => {
                        error!(%error, "Failed to process RDM application action");
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
        let directory = params.directory().map(|dir| WideString::from(dir));

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

    async fn process_rdm_capabilities(&self, rdm_caps_msg: NowRdmCapabilitiesMsg<'_>) -> anyhow::Result<NowMessage<'static>> {
        let client_timestamp = rdm_caps_msg.timestamp();
        let server_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Failed to get current timestamp")?
            .as_secs();

        info!(client_timestamp, server_timestamp, "Processing RDM capabilities message");

        // Check if RDM is available by looking for the installation
        let (is_rdm_available, rdm_version) = {
            let update_code_uuid = Uuid::parse_str(RDM_UPDATE_CODE_UUID)
                .context("Failed to parse RDM update code UUID")?;
            match get_installed_product_version(update_code_uuid, ProductVersionEncoding::Rdm) {
                Ok(Some(date_version)) => {
                    info!(version = %date_version, "RDM installation found via MSI registry");
                    (true, date_version.to_string())
                }
                Ok(None) => {
                    info!("RDM not found in MSI registry");
                    (false, String::new())
                }
                Err(error) => {
                    warn!(%error, "Failed to check RDM via MSI registry");
                    (false, String::new())
                }
            }
        };

        // Create response message with server timestamp
        let mut response = NowRdmCapabilitiesMsg::new(server_timestamp, rdm_version)
            .context("Failed to create RDM capabilities response")?;

        if is_rdm_available {
            response = response.with_app_available();
            info!("RDM application is available on system");
        } else {
            info!("RDM application is not available");
        }

        Ok(NowMessage::Rdm(NowRdmMessage::Capabilities(response)))
    }

    async fn process_rdm_app_start(&mut self, rdm_app_start_msg: NowRdmAppStartMsg) -> anyhow::Result<()> {
        info!("Processing RDM app start message");

        // Check if RDM is already running (either spawned by us or externally)
        if self.rdm_process_spawned.load(Ordering::Acquire) || is_rdm_running() {
            info!("RDM application is already running");
            send_rdm_app_notify(&self.dvc_tx, NowRdmAppState::READY, NowRdmReason::NOT_SPECIFIED).await?;
            return Ok(());
        }

        // Get RDM executable path with proper error handling
        let rdm_exe_path = match get_rdm_exe_path() {
            Ok(Some(path)) => path,
            Ok(None) => {
                error!("RDM is not installed - cannot start application");
                send_rdm_app_notify(&self.dvc_tx, NowRdmAppState::FAILED, NowRdmReason::NOT_INSTALLED).await?;
                bail!("RDM is not installed");
            }
            Err(error) => {
                error!("Failed to get RDM executable path: {}", error);
                send_rdm_app_notify(&self.dvc_tx, NowRdmAppState::FAILED, NowRdmReason::STARTUP_FAILURE).await?;
                return Err(error);
            }
        };

        let install_location = rdm_exe_path.parent()
            .context("Failed to get RDM installation directory")?
            .to_string_lossy()
            .to_string();

            // Build environment variables for fullscreen and jump mode
            let mut env_vars = HashMap::new();

            if rdm_app_start_msg.is_fullscreen() {
                env_vars.insert("RDM_OPT_FULLSCREEN".to_string(), "1".to_string());
                info!("Starting RDM in fullscreen mode");
            }

            if rdm_app_start_msg.is_jump_mode() {
                env_vars.insert("RDM_OPT_JUMP".to_string(), "1".to_string());
                info!("Starting RDM in jump mode");
            }

            // Create environment block
            let env_block = crate::dvc::env::make_environment_block(env_vars)?;

            // Convert command line to wide string
            let current_dir = WideString::from(&install_location);

            info!(
                exe_path = %rdm_exe_path.display(),
                fullscreen = rdm_app_start_msg.is_fullscreen(),
                maximized = rdm_app_start_msg.is_maximized(),
                jump_mode = rdm_app_start_msg.is_jump_mode(),
                "Starting RDM application with CreateProcess"
            );

            // Create process using CreateProcessW in a scoped block
            let create_process_result = {
                let startup_info = STARTUPINFOW {
                    cb: size_of::<STARTUPINFOW>() as u32,
                    wShowWindow: if rdm_app_start_msg.is_maximized() { SW_MAXIMIZE.0 as u16 } else { SW_RESTORE.0 as u16 },
                    dwFlags: windows::Win32::System::Threading::STARTF_USESHOWWINDOW,
                    ..Default::default()
                };

                let mut process_info = PROCESS_INFORMATION::default();

                // Create a mutable copy of the command line for CreateProcessW
                let mut command_line_buffer: Vec<u16> = format!("\"{}\"", rdm_exe_path.display())
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                // SAFETY: All pointers are valid and properly initialized
                let success = unsafe {
                    CreateProcessW(
                        None, // lpApplicationName
                        Some(PWSTR(command_line_buffer.as_mut_ptr())), // lpCommandLine
                        None, // lpProcessAttributes
                        None, // lpThreadAttributes
                        false.into(), // bInheritHandles
                        CREATE_UNICODE_ENVIRONMENT, // dwCreationFlags
                        Some(env_block.as_ptr() as *const std::ffi::c_void), // lpEnvironment
                        PCWSTR(current_dir.as_pcwstr().as_ptr()), // lpCurrentDirectory
                        &startup_info, // lpStartupInfo
                        &mut process_info, // lpProcessInformation
                    )
                };

                if success.is_err() {
                    let error = win_api_wrappers::Error::last_error();
                    let error_msg = format!("Failed to start RDM application: {}", error);
                    Err(error_msg)
                } else {
                    // Extract the handles and process ID immediately as raw values
                    Ok((process_info.hProcess.0 as usize, process_info.dwProcessId, process_info.hThread.0 as usize))
                }
            };

            let (process_handle_raw, process_id, thread_handle_raw) = match create_process_result {
                Ok(result) => result,
                Err(error_msg) => {
                    error!("{}", error_msg);
                    send_rdm_app_notify(&self.dvc_tx, NowRdmAppState::FAILED, NowRdmReason::STARTUP_FAILURE).await?;
                    bail!(error_msg);
                }
            };

            // Handle any errors from process creation
            if process_handle_raw == 0 {
                let error_msg = "Failed to start RDM application: Invalid process handle";
                error!("{}", error_msg);
                send_rdm_app_notify(&self.dvc_tx, NowRdmAppState::FAILED, NowRdmReason::STARTUP_FAILURE).await?;
                bail!(error_msg);
            }

            // Close thread handle as we don't need it
            let thread_handle = windows::Win32::Foundation::HANDLE(thread_handle_raw as *mut std::ffi::c_void);
            unsafe { let _ = CloseHandle(thread_handle); };

            // Create RAII wrapper for process handle
            let process_handle = windows::Win32::Foundation::HANDLE(process_handle_raw as *mut std::ffi::c_void);
            let rdm_handle = RdmProcessHandle::new(process_handle);

            // Set process spawned status
            self.rdm_process_spawned.store(true, Ordering::Release);

            info!("RDM application started successfully with PID: {}", process_id);

            // Send ready notification
            send_rdm_app_notify(&self.dvc_tx, NowRdmAppState::READY, NowRdmReason::NOT_SPECIFIED).await?;

            // Spawn task to monitor the process
            let dvc_tx = self.dvc_tx.clone();
            let spawned_status = self.rdm_process_spawned.clone();

            tokio::task::spawn_blocking(move || {
                monitor_rdm_process(dvc_tx, rdm_handle, process_id, spawned_status);
            });

            Ok(())
    }

    async fn process_rdm_app_action(&mut self, rdm_app_action_msg: NowRdmAppActionMsg<'_>) -> anyhow::Result<()> {
        let action = rdm_app_action_msg.app_action();
        info!(?action, "Processing RDM app action message");

        // Find the running RDM process
        let process_id = match find_rdm_pid() {
            Some(pid) => pid,
            None => {
                warn!("No running RDM process found for action");
                send_rdm_app_notify(&self.dvc_tx, NowRdmAppState::FAILED, NowRdmReason::NOT_SPECIFIED).await?;
                bail!("RDM application is not running");
            }
        };

        match action {
            NowRdmAppAction::CLOSE => {
                info!(process_id, "Closing RDM application");

                // Send WM_CLOSE message to all RDM windows
                let window_count = send_message_to_all_windows(process_id, WM_CLOSE, WPARAM(0), LPARAM(0));

                if window_count == 0 {
                    // If no windows found, try process termination
                    if let Ok(process) = Process::get_by_pid(process_id, PROCESS_QUERY_INFORMATION) {
                        let handle = process.handle();
                        unsafe {
                            let _ = TerminateProcess(handle.raw(), 0);
                        }
                        info!("Terminated RDM process");
                    }
                }

                send_rdm_app_notify(&self.dvc_tx, NowRdmAppState::CLOSED, NowRdmReason::NOT_SPECIFIED).await?;
            }
            NowRdmAppAction::MINIMIZE => {
                info!(process_id, "Minimizing RDM application");
                let window_count = exec_window_command(process_id, WindowCommand::Minimize);

                if window_count == 0 {
                    warn!("No windows found for minimize action");
                }
            }
            NowRdmAppAction::MAXIMIZE => {
                info!(process_id, "Maximizing RDM application");
                let window_count = exec_window_command(process_id, WindowCommand::Maximize);

                if window_count == 0 {
                    warn!("No windows found for maximize action");
                }
            }
            NowRdmAppAction::RESTORE => {
                info!(process_id, "Restoring RDM application");
                let window_count = exec_window_command(process_id, WindowCommand::Restore);

                if window_count == 0 {
                    warn!("No windows found for restore action");
                }
            }
            NowRdmAppAction::FULLSCREEN => {
                info!(process_id, "Toggling RDM fullscreen mode");
                // For fullscreen toggle, we would need to send a specific message or key combination
                // This depends on RDM's specific implementation - for now just log
                warn!("Fullscreen toggle not yet implemented - requires RDM-specific message protocol");
            }
            _ => {
                warn!(?action, "Unsupported RDM app action");
                bail!("Unsupported RDM application action");
            }
        }

        Ok(())
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



/// Check if RDM process is already running by comparing executable paths
fn is_rdm_running() -> bool {
    // Get RDM installation path internally
    let rdm_exe_path = match get_rdm_executable_path() {
        Some(path) => path,
        None => {
            warn!("Could not determine RDM executable path for process detection");
            return false;
        }
    };

    match ProcessEntry32Iterator::new() {
        Ok(process_iter) => {
            for process_entry in process_iter {
                let pid = process_entry.process_id();
                if let Ok(process) = Process::get_by_pid(pid, PROCESS_QUERY_INFORMATION) {
                    if let Ok(exe_path) = process.exe_path() {
                        // Compare the full paths case-insensitively
                        if exe_path.to_string_lossy().to_lowercase()
                            == rdm_exe_path.to_string_lossy().to_lowercase() {
                            info!(
                                rdm_path = %rdm_exe_path.display(),
                                found_path = %exe_path.display(),
                                "Found already running RDM process"
                            );
                            return true;
                        }
                    }
                }
            }
            false
        }
        Err(error) => {
            warn!(%error, "Failed to enumerate processes for RDM detection");
            false
        }
    }
}

/// Get the RDM executable path from installation location
fn get_rdm_executable_path() -> Option<std::path::PathBuf> {
    let update_code_uuid = Uuid::parse_str(RDM_UPDATE_CODE_UUID).ok()?;

    match get_install_location(update_code_uuid) {
        Ok(Some(install_location)) => {
            let rdm_exe_path = std::path::Path::new(&install_location).join("RemoteDesktopManager.exe");
            Some(rdm_exe_path)
        }
        Ok(None) => None,
        Err(_) => None,
    }
}

/// Get RDM executable path with proper error handling for startup scenarios
fn get_rdm_exe_path() -> anyhow::Result<Option<std::path::PathBuf>> {
    let update_code_uuid = Uuid::parse_str(RDM_UPDATE_CODE_UUID)
        .context("Failed to parse RDM update code UUID")?;

    let install_location = match get_install_location(update_code_uuid) {
        Ok(Some(location)) => location,
        Ok(None) => {
            return Ok(None); // RDM is not installed
        }
        Err(error) => {
            bail!("Failed to get RDM installation location: {}", error);
        }
    };

    let rdm_exe_path = std::path::Path::new(&install_location).join("RemoteDesktopManager.exe");

    if !rdm_exe_path.exists() {
        bail!("RDM executable not found at: {}", rdm_exe_path.display());
    }

    Ok(Some(rdm_exe_path))
}/// Send RDM app notification message
async fn send_rdm_app_notify(
    dvc_tx: &WinapiSignaledSender<NowMessage<'static>>,
    state: NowRdmAppState,
    reason: NowRdmReason,
) -> anyhow::Result<()> {
    info!(?state, ?reason, "Sending RDM app state notification");

    let message = NowRdmAppNotifyMsg::new(state, reason);
    dvc_tx.send(NowMessage::Rdm(NowRdmMessage::AppNotify(message))).await?;
    Ok(())
}

/// Monitor RDM process and send notifications when state changes
fn monitor_rdm_process(
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
    rdm_handle: RdmProcessHandle,
    process_id: u32,
    spawned_status: Arc<AtomicBool>,
) {
    info!(process_id, "Starting RDM process monitor");

    // Wait for process to exit
    let wait_result = unsafe { WaitForSingleObject(rdm_handle.handle(), INFINITE) };

    // Check if the wait was successful (process exited)
    if wait_result == WAIT_OBJECT_0 {
        info!(process_id, "RDM process has exited");
        // Send closed notification - we need to block on this since we're in sync context
        let rt = tokio::runtime::Handle::current();
        if let Err(error) = rt.block_on(send_rdm_app_notify(&dvc_tx, NowRdmAppState::CLOSED, NowRdmReason::NOT_SPECIFIED)) {
            error!(%error, "Failed to send RDM app closed notification");
        }
    } else {
        error!(process_id, wait_event = ?wait_result, "Failed to wait for RDM process");
    }

    // Clear the spawned status since our spawned process has exited
    spawned_status.store(false, Ordering::Release);

    // The rdm_handle will be automatically closed when it goes out of scope
}



/// Find running RDM process and return its process ID
fn find_rdm_pid() -> Option<u32> {
    // Get RDM installation path internally
    let rdm_exe_path = get_rdm_executable_path()?;

    match ProcessEntry32Iterator::new() {
        Ok(process_iter) => {
            for process_entry in process_iter {
                let pid = process_entry.process_id();
                if let Ok(process) = Process::get_by_pid(pid, PROCESS_QUERY_INFORMATION) {
                    if let Ok(exe_path) = process.exe_path() {
                        // Compare the full paths case-insensitively
                        if exe_path.to_string_lossy().to_lowercase()
                            == rdm_exe_path.to_string_lossy().to_lowercase() {

                            info!(
                                rdm_path = %rdm_exe_path.display(),
                                found_path = %exe_path.display(),
                                process_id = pid,
                                "Found running RDM process"
                            );

                            return Some(pid);
                        }
                    }
                }
            }
            None
        }
        Err(error) => {
            warn!(%error, "Failed to enumerate processes for RDM detection");
            None
        }
    }
}

/// Send a message to all windows belonging to a specific process
fn send_message_to_all_windows(process_id: u32, message: u32, wparam: WPARAM, lparam: LPARAM) -> u32 {
    // Context for window enumeration callback
    struct MessageSendContext {
        target_process_id: u32,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        window_count: u32,
    }

    unsafe extern "system" fn enum_windows_proc(
        hwnd: HWND,
        lparam: LPARAM
    ) -> windows::core::BOOL {
        unsafe {
            let context = &mut *(lparam.0 as *mut MessageSendContext);

            // Get the process ID of this window
            let mut window_process_id = 0u32;
            let _ = GetWindowThreadProcessId(hwnd, Some(&mut window_process_id));

            // Check if this window belongs to our target process
            if window_process_id == context.target_process_id {
                // Send message directly to this window
                let _ = PostMessageW(Some(hwnd), context.message, context.wparam, context.lparam);
                context.window_count += 1;
                info!(
                    process_id = context.target_process_id,
                    window_handle = hwnd.0 as isize,
                    message = context.message,
                    "Sent message to RDM window"
                );
            }

            windows::core::BOOL(1) // Continue enumeration to find all windows
        }
    }

    let mut context = MessageSendContext {
        target_process_id: process_id,
        message,
        wparam,
        lparam,
        window_count: 0,
    };

    unsafe {
        let _ = EnumWindows(
            Some(enum_windows_proc),
            LPARAM(&mut context as *mut _ as isize),
        );
    }

    if context.window_count > 0 {
        info!(process_id, window_count = context.window_count, "Sent message to RDM windows");
    } else {
        warn!(process_id, "Could not find any windows for RDM process");
    }

    context.window_count
}

/// Execute a window command on all windows belonging to a specific process
fn exec_window_command(process_id: u32, command: WindowCommand) -> u32 {
    // Context for window enumeration callback
    struct WindowCommandContext {
        target_process_id: u32,
        command: WindowCommand,
        window_count: u32,
    }

    unsafe extern "system" fn enum_windows_proc(
        hwnd: HWND,
        lparam: LPARAM
    ) -> windows::core::BOOL {
        unsafe {
            let context = &mut *(lparam.0 as *mut WindowCommandContext);

            // Get the process ID of this window
            let mut window_process_id = 0u32;
            let _ = GetWindowThreadProcessId(hwnd, Some(&mut window_process_id));

            // Check if this window belongs to our target process
            if window_process_id == context.target_process_id {
                // Apply ShowWindow command directly to this window
                let show_command = match context.command {
                    WindowCommand::Minimize => SW_MINIMIZE,
                    WindowCommand::Maximize => SW_SHOWMAXIMIZED,
                    WindowCommand::Restore => SW_SHOWNORMAL,
                };
                let _ = ShowWindow(hwnd, show_command);
                context.window_count += 1;
                info!(
                    process_id = context.target_process_id,
                    window_handle = hwnd.0 as isize,
                    command = ?context.command,
                    "Applied window command to RDM window"
                );
            }

            windows::core::BOOL(1) // Continue enumeration to find all windows
        }
    }

    let mut context = WindowCommandContext {
        target_process_id: process_id,
        command,
        window_count: 0,
    };

    unsafe {
        let _ = EnumWindows(
            Some(enum_windows_proc),
            LPARAM(&mut context as *mut _ as isize),
        );
    }

    if context.window_count > 0 {
        info!(process_id, window_count = context.window_count, command = ?command, "Applied window command to RDM windows");
    } else {
        warn!(process_id, "Could not find any windows for RDM process");
    }

    context.window_count
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
