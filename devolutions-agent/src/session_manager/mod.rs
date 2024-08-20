//! Module for starting and managing the Devolutions Host process in user sessions.

use tokio::sync::{mpsc, RwLock};

use crate::AgentServiceEvent;
use async_trait::async_trait;
use ceviche::controller::Session;
use devolutions_gateway_task::{ShutdownSignal, Task};
use std::collections::BTreeMap;
use std::fmt::Debug;

use camino::Utf8PathBuf;
use win_api_wrappers::process::{
    create_process_in_session, is_process_running_in_session, terminate_process_by_name_in_session, StartupInfo,
};
use win_api_wrappers::session::session_has_logged_in_user;
use win_api_wrappers::utils::{CommandLine, WideString};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, NORMAL_PRIORITY_CLASS, STARTF_USESHOWWINDOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

const HOST_BINARY: &str = "DevolutionsHost.exe";

#[derive(Debug, Clone, Copy)]
pub enum SessionKind {
    /// Console session. For example, when you connect to a user session on the local computer
    /// by switching users on the computer.
    Console,
    /// Remote session. For example, when a user connects to a user session by using the Remote
    /// Desktop Connection program from a remote computer.
    Remote,
}

struct GatewaySession {
    session: Session,
    kind: SessionKind,
    is_host_ready: bool,
}

// NOTE: `ceviche::controller::Session` do not implement `Debug` for session.
impl Debug for GatewaySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewaySession")
            .field("session", &self.session.id)
            .field("kind", &self.kind)
            .field("is_host_ready", &self.is_host_ready)
            .finish()
    }
}

impl GatewaySession {
    fn new(session: Session, kind: SessionKind) -> Self {
        Self {
            session,
            kind,
            is_host_ready: false,
        }
    }

    fn kind(&self) -> SessionKind {
        self.kind
    }

    fn os_session(&self) -> &Session {
        &self.session
    }

    fn is_host_ready(&self) -> bool {
        self.is_host_ready
    }

    fn set_host_ready(&mut self, is_ready: bool) {
        self.is_host_ready = is_ready;
    }
}

#[derive(Default, Debug)]
struct SessionManagerCtx {
    sessions: BTreeMap<String, GatewaySession>,
}

impl SessionManagerCtx {
    fn register_session(&mut self, session: &Session, kind: SessionKind) {
        self.sessions
            .insert(session.to_string(), GatewaySession::new(Session::new(session.id), kind));
    }

    fn unregister_session(&mut self, session: &Session) {
        self.sessions.remove(&session.to_string());
    }

    fn get_session(&self, session: &Session) -> Option<&GatewaySession> {
        self.sessions.get(&session.to_string())
    }

    fn get_session_mut(&mut self, session: &Session) -> Option<&mut GatewaySession> {
        self.sessions.get_mut(&session.to_string())
    }
}

pub struct SessionManager {
    ctx: RwLock<SessionManagerCtx>,
    service_event_tx: mpsc::UnboundedSender<AgentServiceEvent>,
    service_event_rx: mpsc::UnboundedReceiver<AgentServiceEvent>,
}

impl Default for SessionManager {
    fn default() -> Self {
        let (service_event_tx, service_event_rx) = mpsc::unbounded_channel();

        Self {
            ctx: RwLock::new(SessionManagerCtx::default()),
            service_event_tx,
            service_event_rx,
        }
    }
}

impl SessionManager {
    pub(crate) fn service_event_tx(&self) -> mpsc::UnboundedSender<AgentServiceEvent> {
        self.service_event_tx.clone()
    }
}

#[async_trait]
impl Task for SessionManager {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "SessionManager";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        let Self {
            mut service_event_rx,
            ctx,
            ..
        } = self;

        info!("Starting session manager...");

        loop {
            tokio::select! {
                event = service_event_rx.recv() => {
                    info!("Received service event");

                    let event = if let Some(event) = event {
                        event
                    } else {
                        error!("Service event channel closed");
                        // Channel closed, all senders were dropped
                        break;
                    };

                    match event {
                        AgentServiceEvent::SessionConnect(id) => {
                            info!(%id, "Session connected");
                            let mut ctx = ctx.write().await;
                            ctx.register_session(&id, SessionKind::Console);
                            // We only start the host process for remote sessions (initiated
                            // via RDP), as Host process with DVC handler is only needed for remote
                            // sessions.
                        }
                        AgentServiceEvent::SessionDisconnect(id) => {
                            info!(%id, "Session disconnected");
                            try_terminate_host_process(&id);
                            ctx.write().await.unregister_session(&id);
                        }
                        AgentServiceEvent::SessionRemoteConnect(id) => {
                            info!(%id, "Remote session connected");
                            // Terminate old host process if it is already running
                            try_terminate_host_process(&id);

                            {
                                let mut ctx = ctx.write().await;
                                ctx.register_session(&id, SessionKind::Remote);
                                try_start_host_process(&mut ctx, &id)?;
                            }
                        }
                        AgentServiceEvent::SessionRemoteDisconnect(id) => {
                            info!(%id, "Remote session disconnected");
                            // Terminate host process when remote session is disconnected
                            // (NOTE: depending on the system settings, session could
                            // still be running in the background after RDP disconnect)
                            try_terminate_host_process(&id);
                            ctx.write().await.unregister_session(&id);
                        }
                        AgentServiceEvent::SessionLogon(id) => {
                            info!(%id, "Session logged on");

                            // Terminate old host process if it is already running
                            try_terminate_host_process(&id);


                            // NOTE: In some cases, SessionRemoteConnect is fired before
                            // an actual user is logged in, therefore we need to try start the host
                            // app on logon, if not yet started
                            let mut ctx = ctx.write().await;
                            try_start_host_process(&mut ctx, &id)?;
                        }
                        AgentServiceEvent::SessionLogoff(id) => {
                            info!(%id, "Session logged off");
                            ctx.write().await.get_session_mut(&id).map(|session| {
                                // When a user logs off, host process will be stopped by the system;
                                // Console sessions could be reused for different users, therefore
                                // we should not remove the session from the list, but mark it as
                                // not yet ready (host will be started as soon as new user logs in).
                                session.set_host_ready(false);
                            });
                        }
                        _ => {
                            continue;
                        }
                    }
                }
                _ = shutdown_signal.wait() => {
                    info!("Shutting down session manager");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Starts Devolutions Host process in the target session.
fn try_start_host_process(ctx: &mut SessionManagerCtx, session: &Session) -> anyhow::Result<()> {
    match ctx.get_session_mut(&session) {
        Some(gw_session) => {
            if is_host_running_in_session(&session)? {
                gw_session.set_host_ready(true);
                return Ok(());
            }

            info!(%session, "Starting host process in session");

            match start_host_process(&session) {
                Ok(()) => {
                    info!(%session, "Host process started in session");
                    gw_session.set_host_ready(true);
                }
                Err(err) => {
                    error!(%err, %session, "Failed to start host process for session");
                }
            }
        }
        None => {
            warn!(%session, "Session is not yet registered");
        }
    };

    Ok(())
}

/// Terminates Devolutions Host process in the target session.
fn try_terminate_host_process(session: &Session) {
    match terminate_process_by_name_in_session(HOST_BINARY, session.id) {
        Ok(false) => {
            trace!(%session, "Host process is not running in the session");
        }
        Ok(true) => {
            info!(%session, "Host process terminated in session");
        }
        Err(err) => {
            error!(%err, %session, "Failed to terminate host process in session");
        }
    }
}

fn is_host_running_in_session(session: &Session) -> anyhow::Result<bool> {
    let is_running = is_process_running_in_session(HOST_BINARY, session.id)?;
    Ok(is_running)
}

fn start_host_process(session: &Session) -> anyhow::Result<()> {
    if !session_has_logged_in_user(session.id)? {
        anyhow::bail!("Session {} does not have a logged in user", session);
    }

    let host_app_path = host_app_path();
    let command_line = CommandLine::new(vec!["--session".to_owned(), session.to_string()]);

    info!("Starting `{host_app_path}` in session `{session}`");

    let mut startup_info = StartupInfo::default();

    // Run with GUI access
    startup_info.show_window = SW_SHOW.0 as u16;
    startup_info.flags = STARTF_USESHOWWINDOW;
    startup_info.desktop = WideString::from("WinSta0\\Default");

    let start_result = create_process_in_session(
        session.id,
        Some(host_app_path.as_std_path()),
        Some(&command_line),
        None,
        None,
        false,
        CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT,
        None,
        None,
        &mut startup_info,
    );

    match start_result {
        Ok(_) => {
            info!("{HOST_BINARY} started in session {session}");
            Ok(())
        }
        Err(err) => {
            error!(%err, "Failed to start {HOST_BINARY} in session {session}");
            Err(err)
        }
    }
}

fn host_app_path() -> Utf8PathBuf {
    let mut current_dir = Utf8PathBuf::from_path_buf(std::env::current_exe().expect("BUG: can't get current exe path"))
        .expect("BUG: OS should always return valid UTF-8 executable path");

    current_dir.pop();
    current_dir.push(HOST_BINARY);

    current_dir
}
