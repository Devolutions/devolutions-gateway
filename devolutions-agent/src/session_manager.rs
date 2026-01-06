//! Module for starting and managing the Devolutions Session process in user sessions.

use std::collections::BTreeMap;
use std::fmt::Debug;

use async_trait::async_trait;
use camino::Utf8PathBuf;
use ceviche::controller::Session;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::sync::{RwLock, mpsc};
use win_api_wrappers::process::{
    StartupInfo, create_process_in_session, is_process_running_in_session, terminate_process_by_name_in_session,
};
use win_api_wrappers::utils::{CommandLine, WideString};
use win_api_wrappers::wts::session_has_logged_in_user;
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, NORMAL_PRIORITY_CLASS, STARTF_USESHOWWINDOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

use crate::AgentServiceEvent;

const SESSION_BINARY: &str = "DevolutionsSession.exe";

#[derive(Debug, Clone, Copy)]
enum SessionKind {
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
    is_session_ready: bool,
}

// NOTE: `ceviche::controller::Session` do not implement `Debug` for session.
impl Debug for GatewaySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewaySession")
            .field("session", &self.session.id)
            .field("kind", &self.kind)
            .field("is_session_ready", &self.is_session_ready)
            .finish()
    }
}

impl GatewaySession {
    fn new(session: Session, kind: SessionKind) -> Self {
        Self {
            session,
            kind,
            is_session_ready: false,
        }
    }

    #[allow(dead_code)]
    fn kind(&self) -> SessionKind {
        self.kind
    }

    #[allow(dead_code)]
    fn os_session(&self) -> &Session {
        &self.session
    }

    #[allow(dead_code)]
    fn is_session_ready(&self) -> bool {
        self.is_session_ready
    }

    fn set_session_ready(&mut self, is_ready: bool) {
        self.is_session_ready = is_ready;
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

    fn get_session_mut(&mut self, session: &Session) -> Option<&mut GatewaySession> {
        self.sessions.get_mut(&session.to_string())
    }
}

pub struct SessionManager {
    ctx: RwLock<SessionManagerCtx>,
    service_event_tx: mpsc::Sender<AgentServiceEvent>,
    service_event_rx: mpsc::Receiver<AgentServiceEvent>,
}

impl Default for SessionManager {
    fn default() -> Self {
        let (service_event_tx, service_event_rx) = mpsc::channel(100);

        Self {
            ctx: RwLock::new(SessionManagerCtx::default()),
            service_event_tx,
            service_event_rx,
        }
    }
}

impl SessionManager {
    pub fn service_event_tx(&self) -> mpsc::Sender<AgentServiceEvent> {
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
                        // Channel closed, all senders were dropped.
                        break;
                    };

                    match event {
                        AgentServiceEvent::SessionConnect(id) => {
                            info!(%id, "Session connected");
                            let mut ctx = ctx.write().await;
                            ctx.register_session(&id, SessionKind::Console);
                            // We only start the session process for remote sessions (initiated
                            // via RDP), as session process with DVC handler is only needed for remote
                            // sessions.
                        }
                        AgentServiceEvent::SessionDisconnect(id) => {
                            info!(%id, "Session disconnected");
                            terminate_session_process(&id);
                            ctx.write().await.unregister_session(&id);
                        }
                        AgentServiceEvent::SessionRemoteConnect(id) => {
                            info!(%id, "Remote session connected");
                            // Terminate old session process if it is already running.
                            terminate_session_process(&id);

                            {
                                let mut ctx = ctx.write().await;
                                ctx.register_session(&id, SessionKind::Remote);
                                start_session_process_if_not_running(&mut ctx, &id)?;
                            }
                        }
                        AgentServiceEvent::SessionRemoteDisconnect(id) => {
                            info!(%id, "Remote session disconnected");
                            // Terminate session process when remote session is disconnected
                            // (NOTE: depending on the system settings, session could
                            // still be running in the background after RDP disconnect).
                            terminate_session_process(&id);
                            ctx.write().await.unregister_session(&id);
                        }
                        AgentServiceEvent::SessionLogon(id) => {
                            info!(%id, "Session logged on");

                            // Terminate old session process if it is already running.
                            terminate_session_process(&id);


                            // NOTE: In some cases, SessionRemoteConnect is fired before
                            // an actual user is logged in, therefore we need to try start the
                            // session app on logon, if not yet started.
                            let mut ctx = ctx.write().await;
                            start_session_process_if_not_running(&mut ctx, &id)?;
                        }
                        AgentServiceEvent::SessionLogoff(id) => {
                            info!(%id, "Session logged off");
                            if let Some(session) = ctx.write().await.get_session_mut(&id) {
                                // When a user logs off, session process will be stopped by the system;
                                // Console sessions could be reused for different users, therefore
                                // we should not remove the session from the list, but mark it as
                                // not yet ready (session will be started as soon as new user logs in).
                                session.set_session_ready(false);
                            }
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

/// Starts Devolutions Session process in the target session.
fn start_session_process_if_not_running(ctx: &mut SessionManagerCtx, session: &Session) -> anyhow::Result<()> {
    match ctx.get_session_mut(session) {
        Some(gw_session) => {
            if is_session_running_in_session(session)? {
                gw_session.set_session_ready(true);
                return Ok(());
            }

            info!(%session, "Starting session process");

            match start_session_process(session) {
                Ok(()) => {
                    info!(%session, "Session process started");
                    gw_session.set_session_ready(true);
                }
                Err(error) => {
                    error!(%error, %session, "Failed to start session process");
                }
            }
        }
        None => {
            warn!(%session, "Session is not yet registered");
        }
    };

    Ok(())
}

/// Terminates Devolutions Session process in the target session.
fn terminate_session_process(session: &Session) {
    match terminate_process_by_name_in_session(SESSION_BINARY, session.id) {
        Ok(false) => {
            trace!(%session, "Session process is not running");
        }
        Ok(true) => {
            info!(%session, "Session process terminated");
        }
        Err(error) => {
            error!(%error, %session, "Failed to terminate session process");
        }
    }
}

fn is_session_running_in_session(session: &Session) -> anyhow::Result<bool> {
    let is_running = is_process_running_in_session(SESSION_BINARY, session.id)?;
    Ok(is_running)
}

fn start_session_process(session: &Session) -> anyhow::Result<()> {
    if !session_has_logged_in_user(session.id)? {
        anyhow::bail!("Session {} does not have a logged in user", session);
    }

    let session_app_path = session_app_path();
    let command_line = CommandLine::new(vec!["--session".to_owned(), session.to_string()]);

    info!(%session, "Starting `{session_app_path}`");

    let mut startup_info = StartupInfo::default();

    // Run with GUI access
    // NOTE: silent clippy warning, just to be more explicit about `show_window` value.
    #[allow(clippy::field_reassign_with_default)]
    {
        startup_info.show_window = u16::try_from(SW_SHOW.0).expect("BUG: SW_SHOW always fit u16");
    }
    startup_info.flags = STARTF_USESHOWWINDOW;
    startup_info.desktop = WideString::from("WinSta0\\Default");

    let start_result = create_process_in_session(
        session.id,
        Some(session_app_path.as_std_path()),
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
            info!(%session, "{SESSION_BINARY} started");
            Ok(())
        }
        Err(error) => {
            error!(%error, %session, "Failed to start {SESSION_BINARY}");
            Err(error)
        }
    }
}

fn session_app_path() -> Utf8PathBuf {
    let mut current_dir = Utf8PathBuf::from_path_buf(std::env::current_exe().expect("BUG: can't get current exe path"))
        .expect("BUG: OS should always return valid UTF-8 executable path");

    current_dir.pop();
    current_dir.push(SESSION_BINARY);

    current_dir
}
