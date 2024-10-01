use std::collections::HashMap;

use anyhow::bail;
use async_trait::async_trait;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Shutdown::{ExitWindowsEx, LockWorkStation, EWX_LOGOFF, SHUTDOWN_REASON};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MESSAGEBOX_STYLE, SW_RESTORE};

use devolutions_gateway_task::Task;
use now_proto_pdu::{
    NowExecBatchMsg, NowExecCapsetFlags, NowExecCapsetMsg, NowExecDataFlags, NowExecMessage, NowExecProcessMsg,
    NowExecPwshMsg, NowExecResultMsg, NowExecRunMsg, NowExecWinPsFlags, NowExecWinPsMsg, NowMessage, NowMsgBoxResponse,
    NowSessionMessage, NowSessionMsgBoxReqMsg, NowSessionMsgBoxRspMsg, NowSeverity, NowStatus, NowStatusCode,
    NowSystemMessage,
};
use win_api_wrappers::event::Event;
use win_api_wrappers::utils::WideString;

use crate::dvc::channel::{bounded_mpsc_channel, winapi_signaled_mpsc_channel, WinapiSignaledSender};
use crate::dvc::fs::TmpFileGuard;
use crate::dvc::io::run_dvc_io;
use crate::dvc::process::{ProcessIoNotification, WinApiProcess, WinApiProcessBuilder};
use crate::dvc::status::{ExecAgentError, ExecResultKind};

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

        // Spawning thread is relatively short operation, so it could be executed synchronously.
        let io_thread = std::thread::spawn(move || {
            let io_thread_result = run_dvc_io(write_rx, read_tx, cloned_shutdown_event);

            if let Err(error) = io_thread_result {
                error!(%error, "DVC IO thread failed");
            }
        });

        // Join thread some time in future.
        tokio::task::spawn_blocking(move || {
            if io_thread.join().is_err() {
                error!("DVC IO thread join failed");
            };
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
    mut read_rx: Receiver<NowMessage>,
    dvc_tx: WinapiSignaledSender<NowMessage>,
    mut shutdown_signal: devolutions_gateway_task::ShutdownSignal,
) -> anyhow::Result<()> {
    let (io_notification_tx, mut task_rx) = mpsc::channel(100);

    let mut processor = MessageProcessor::new(dvc_tx, io_notification_tx);

    processor.send_initialization_sequence().await?;

    loop {
        select! {
            read_result = read_rx.recv() => {
                match read_result {
                    Some(message) => {
                        match processor.process_message(message).await {
                            Ok(()) => {}
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
                            ProcessIoNotification::Terminated { session_id } => {
                                info!(session_id, "Cleaning up session resources");
                                processor.remove_session(session_id);
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

struct MessageProcessor {
    dvc_tx: WinapiSignaledSender<NowMessage>,
    io_notification_tx: Sender<ProcessIoNotification>,
    downgraded_caps: NowExecCapsetFlags,
    sessions: HashMap<u32, WinApiProcess>,
}

impl MessageProcessor {
    pub(crate) fn new(
        dvc_tx: WinapiSignaledSender<NowMessage>,
        io_notification_tx: Sender<ProcessIoNotification>,
    ) -> Self {
        Self {
            dvc_tx,
            io_notification_tx,
            // Caps are empty until negotiated.
            downgraded_caps: NowExecCapsetFlags::empty(),
            sessions: HashMap::new(),
        }
    }

    pub(crate) async fn send_initialization_sequence(&self) -> anyhow::Result<()> {
        // Caps supported by the server
        let capabilities_pdu = NowMessage::from(NowExecCapsetMsg::new(
            NowExecCapsetFlags::STYLE_RUN
                | NowExecCapsetFlags::STYLE_PROCESS
                | NowExecCapsetFlags::STYLE_CMD
                | NowExecCapsetFlags::STYLE_PWSH
                | NowExecCapsetFlags::STYLE_WINPS,
        ));

        self.dvc_tx.send(capabilities_pdu).await?;

        Ok(())
    }

    async fn ensure_session_id_free(&self, session_id: u32) -> anyhow::Result<()> {
        if self.sessions.contains_key(&session_id) {
            self.dvc_tx
                .send(NowMessage::from(NowExecResultMsg::new(
                    session_id,
                    NowStatus::new(NowSeverity::Fatal, NowStatusCode(ExecAgentError::EXISTING_SESSION.0))
                        .with_kind(ExecResultKind::SESSION_ERROR_AGENT.0)
                        .expect("BUG: Exec result kind is out of bounds"),
                )))
                .await?;

            bail!("Session ID is already in use");
        }

        Ok(())
    }

    async fn handle_process_run_result(
        &mut self,
        session_id: u32,
        run_process_result: anyhow::Result<WinApiProcess>,
    ) -> anyhow::Result<()> {
        match run_process_result {
            Ok(process) => {
                info!(session_id, "Process started!");

                self.sessions.insert(session_id, process);
            }
            Err(error) => {
                error!(session_id, %error, "Failed to start process");

                self.dvc_tx
                    .send(NowMessage::from(NowExecResultMsg::new(
                        session_id,
                        NowStatus::new(NowSeverity::Fatal, NowStatusCode(ExecAgentError::START_FAILED.0))
                            .with_kind(ExecResultKind::SESSION_ERROR_AGENT.0)?,
                    )))
                    .await?;
            }
        }

        Ok(())
    }

    pub(crate) async fn process_message(&mut self, message: NowMessage) -> anyhow::Result<()> {
        match message {
            NowMessage::Exec(NowExecMessage::Capset(client_capset_message)) => {
                // Execute downgrade caps sequence.
                let server_flags = NowExecCapsetFlags::STYLE_RUN;
                let downgraded_flags = server_flags & client_capset_message.flags();
                self.downgraded_caps = downgraded_flags;

                let downgraded_caps_pdu = NowMessage::from(NowExecCapsetMsg::new(downgraded_flags));

                self.dvc_tx.send(downgraded_caps_pdu).await?;
            }
            NowMessage::Exec(NowExecMessage::Run(exec_msg)) => {
                // Execute synchronously; ShellExecute will not block the calling thread,
                // For "Run" we are only interested in fire-and-forget execution.
                self.process_exec_run(exec_msg).await?;
            }
            NowMessage::Exec(NowExecMessage::Process(exec_msg)) => {
                self.process_exec_process(exec_msg).await?;
            }
            NowMessage::Exec(NowExecMessage::Batch(batch_msg)) => {
                self.process_exec_batch(batch_msg).await?;
            }
            NowMessage::Exec(NowExecMessage::WinPs(winps_msg)) => {
                self.process_exec_winps(winps_msg).await?;
            }
            NowMessage::Exec(NowExecMessage::Pwsh(pwsh_msg)) => {
                self.process_exec_pwsh(pwsh_msg).await?;
            }
            NowMessage::Exec(NowExecMessage::Abort(abort_msg)) => {
                let session_id = abort_msg.session_id();

                let process = match self.sessions.get_mut(&session_id) {
                    Some(process) => process,
                    None => {
                        warn!(session_id, "Session not found (abort)");
                        return Ok(());
                    }
                };

                process.abort_execution(abort_msg.status().clone()).await?;

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
                        return Ok(());
                    }
                };

                process.cancel_execution().await?;
            }
            NowMessage::Exec(NowExecMessage::Data(data_msg)) => {
                let session_id = data_msg.session_id();
                let flags = data_msg.flags();

                if !flags.contains(NowExecDataFlags::STDIN) {
                    warn!(session_id, "Only STDIN data input is supported");
                    return Ok(());
                }

                let process = match self.sessions.get_mut(&session_id) {
                    Some(process) => process,
                    None => {
                        warn!(session_id, "Session not found (data)");
                        return Ok(());
                    }
                };

                process
                    .send_stdin(data_msg.data().value().to_vec(), flags.contains(NowExecDataFlags::LAST))
                    .await?;
            }
            NowMessage::Session(NowSessionMessage::MsgBoxReq(request)) => {
                let tx = self.dvc_tx.clone();

                // Spawn blocking task for message box to avoid blocking the IO loop.
                let join_handle = tokio::task::spawn_blocking(move || process_msg_box_req(request, tx));
                drop(join_handle);
            }
            NowMessage::Session(NowSessionMessage::Logoff(_logoff_msg)) => {
                // SAFETY: `ExitWindowsEx` is always safe to call.
                if let Err(error) = unsafe { ExitWindowsEx(EWX_LOGOFF, SHUTDOWN_REASON(0)) } {
                    error!(%error, "Failed to logoff user session");
                }
            }
            NowMessage::Session(NowSessionMessage::Lock(_lock_msg)) => {
                // SAFETY: `LockWorkStation` is always safe to call.
                if let Err(error) = unsafe { LockWorkStation() } {
                    error!(%error, "Failed to lock workstation");
                }
            }
            NowMessage::System(NowSystemMessage::Shutdown(_shutdown_msg)) => {
                // TODO: Adjust `NowSession` token privileges in NowAgent to make shutdown possible
                // from this process.
            }
            _ => {
                warn!("Unsupported message: {:?}", message);
            }
        }

        Ok(())
    }

    async fn process_exec_run(&self, params: NowExecRunMsg) -> anyhow::Result<()> {
        let session_id = params.session_id();

        // Empty null-terminated string.
        let parameters = WideString::from("");
        let operation = WideString::from("open");
        let command = WideString::from(params.command().value());

        info!(session_id, "Executing ShellExecuteW");

        // SAFETY: All buffers are valid, therefore `ShellExecuteW` is safe to call.
        let hinstance = unsafe {
            ShellExecuteW(
                None,
                operation.as_pcwstr(),
                command.as_pcwstr(),
                parameters.as_pcwstr(),
                None,
                // Activate and show window
                SW_RESTORE,
            )
        };

        if hinstance.0 as usize <= 32 {
            error!("ShellExecuteW failed, error code: {}", hinstance.0 as usize);

            self.dvc_tx
                .send(NowMessage::from(NowExecResultMsg::new(
                    session_id,
                    NowStatus::new(NowSeverity::Fatal, NowStatusCode(ExecAgentError::OTHER.0))
                        .with_kind(ExecResultKind::SESSION_ERROR_AGENT.0)
                        .expect("BUG: Exec result kind is out of bounds"),
                )))
                .await?;
        } else {
            self.dvc_tx
                .send(NowMessage::from(NowExecResultMsg::new(
                    session_id,
                    NowStatus::new(NowSeverity::Info, NowStatusCode::SUCCESS)
                        .with_kind(ExecResultKind::EXITED.0)
                        .expect("BUG: Exec result kind is out of bounds"),
                )))
                .await?;
        }

        Ok(())
    }

    async fn process_exec_process(&mut self, exec_msg: NowExecProcessMsg) -> anyhow::Result<()> {
        self.ensure_session_id_free(exec_msg.session_id()).await?;

        let run_process_result = WinApiProcessBuilder::new(exec_msg.filename().value())
            .with_command_line(exec_msg.parameters().clone().into())
            .with_current_directory(exec_msg.directory().clone().into())
            .run(
                exec_msg.session_id(),
                self.dvc_tx.clone(),
                self.io_notification_tx.clone(),
            );

        self.handle_process_run_result(exec_msg.session_id(), run_process_result)
            .await?;

        Ok(())
    }

    async fn process_exec_batch(&mut self, batch_msg: NowExecBatchMsg) -> anyhow::Result<()> {
        self.ensure_session_id_free(batch_msg.session_id()).await?;

        let tmp_file = TmpFileGuard::new("bat")?;
        tmp_file.write_content(batch_msg.command().value())?;

        let parameters = format!("/c \"{}\"", tmp_file.path_string());

        let run_process_result = WinApiProcessBuilder::new("cmd.exe")
            .with_temp_file(tmp_file)
            .with_command_line(parameters)
            .run(
                batch_msg.session_id(),
                self.dvc_tx.clone(),
                self.io_notification_tx.clone(),
            );

        self.handle_process_run_result(batch_msg.session_id(), run_process_result)
            .await?;

        Ok(())
    }

    async fn process_exec_winps(&mut self, winps_msg: NowExecWinPsMsg) -> anyhow::Result<()> {
        self.ensure_session_id_free(winps_msg.session_id()).await?;

        let tmp_file = TmpFileGuard::new("ps1")?;
        tmp_file.write_content(winps_msg.command().value())?;

        let mut params = Vec::new();

        if let Some(execution_policy) = winps_msg.execution_policy() {
            params.push("-ExecutionPolicy".to_string());
            params.push(execution_policy.value().to_string());
        }

        if let Some(configuration_name) = winps_msg.configuration_name() {
            params.push("-ConfigurationName".to_string());
            params.push(configuration_name.value().to_string());
        }

        append_ps_flags(&mut params, winps_msg.flags());

        params.push("-File".to_string());
        params.push(format!("\"{}\"", tmp_file.path_string()));

        let params_str = params.join(" ");

        let run_process_result = WinApiProcessBuilder::new("powershell.exe")
            .with_temp_file(tmp_file)
            .with_command_line(params_str)
            .run(
                winps_msg.session_id(),
                self.dvc_tx.clone(),
                self.io_notification_tx.clone(),
            );

        self.handle_process_run_result(winps_msg.session_id(), run_process_result)
            .await?;

        Ok(())
    }

    async fn process_exec_pwsh(&mut self, pwsh_msg: NowExecPwshMsg) -> anyhow::Result<()> {
        self.ensure_session_id_free(pwsh_msg.session_id()).await?;

        let tmp_file = TmpFileGuard::new("ps1")?;
        tmp_file.write_content(pwsh_msg.command().value())?;

        let mut params = Vec::new();

        if let Some(execution_policy) = pwsh_msg.execution_policy() {
            params.push("-ExecutionPolicy".to_string());
            params.push(execution_policy.value().to_string());
        }

        if let Some(configuration_name) = pwsh_msg.configuration_name() {
            params.push("-ConfigurationName".to_string());
            params.push(configuration_name.value().to_string());
        }

        append_ps_flags(&mut params, pwsh_msg.flags());

        params.push("-File".to_string());
        params.push(format!("\"{}\"", tmp_file.path_string()));

        let params_str = params.join(" ");

        let run_process_result = WinApiProcessBuilder::new("pwsh.exe")
            .with_temp_file(tmp_file)
            .with_command_line(params_str)
            .run(
                pwsh_msg.session_id(),
                self.dvc_tx.clone(),
                self.io_notification_tx.clone(),
            );

        self.handle_process_run_result(pwsh_msg.session_id(), run_process_result)
            .await?;

        Ok(())
    }

    pub(crate) fn remove_session(&mut self, session_id: u32) {
        let _ = self.sessions.remove(&session_id);
    }

    pub(crate) async fn shutdown_all_sessions(&mut self) {
        for session in self.sessions.values() {
            let _ = session.shutdown().await;
        }
    }
}

fn append_ps_flags(args: &mut Vec<String>, flags: NowExecWinPsFlags) {
    if flags.contains(NowExecWinPsFlags::NO_LOGO) {
        args.push("-NoLogo".to_string());
    }

    if flags.contains(NowExecWinPsFlags::NO_EXIT) {
        args.push("-NoExit".to_string());
    }

    if flags.contains(NowExecWinPsFlags::STA) {
        args.push("-Sta".to_string());
    }

    if flags.contains(NowExecWinPsFlags::MTA) {
        args.push("-Mta".to_string());
    }

    if flags.contains(NowExecWinPsFlags::NO_PROFILE) {
        args.push("-NoProfile".to_string());
    }

    if flags.contains(NowExecWinPsFlags::NON_INTERACTIVE) {
        args.push("-NonInteractive".to_string());
    }
}

async fn process_msg_box_req(request: NowSessionMsgBoxReqMsg, dvc_tx: WinapiSignaledSender<NowMessage>) {
    info!("Processing message box request `{}`", request.request_id());

    let title = HSTRING::from(
        request
            .title()
            .map(|varstr| varstr.value())
            .unwrap_or("Devolutions Agent"),
    );

    let text = HSTRING::from(request.message().value());

    // TODO: Use undocumented `MessageBoxTimeout` instead
    // or create custom window (?)
    // SAFETY: `MessageBoxW` is always safe to call.
    let result = unsafe {
        MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(title.as_ptr()),
            MESSAGEBOX_STYLE(request.style().value()),
        )
    };

    #[allow(clippy::cast_sign_loss)]
    let message_box_response = result.0 as u32;

    let send_result = dvc_tx
        .send(NowMessage::from(NowSessionMsgBoxRspMsg::new(
            request.request_id(),
            NowMsgBoxResponse::new(message_box_response),
        )))
        .await;

    if let Err(error) = send_result {
        error!(%error, "Failed to send MessageBox response");
    }
}
