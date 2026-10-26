//! Module for starting and managing the Devolutions Session process in user sessions.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use ceviche::controller::Session;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::sync::{RwLock, mpsc};
use win_api_wrappers::process::{
    Process, StartupInfo, create_process_in_session, is_process_running_in_session,
    terminate_process_by_name_in_session_and_wait,
};
use win_api_wrappers::utils::{CommandLine, WideString};
use win_api_wrappers::wts::{WTSConnectState, get_sessions, session_has_logged_in_user, session_uses_rdp};
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

impl SessionKind {
    fn is_remote(self) -> bool {
        matches!(self, Self::Remote)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionReadiness {
    WaitingForLogon,
    WaitingForUnlock,
    WaitingForLogonOrUnlock,
    Ready,
}

impl SessionReadiness {
    fn is_satisfied_by(self, event: SessionReadinessEvent) -> bool {
        matches!(
            (self, event),
            (Self::WaitingForLogon, SessionReadinessEvent::Logon)
                | (
                    Self::WaitingForUnlock,
                    SessionReadinessEvent::Logon | SessionReadinessEvent::Unlock
                )
                | (
                    Self::WaitingForLogonOrUnlock,
                    SessionReadinessEvent::Logon | SessionReadinessEvent::Unlock
                )
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum SessionReadinessEvent {
    Logon,
    Unlock,
}

struct GatewaySession {
    session: Session,
    kind: SessionKind,
    readiness: SessionReadiness,
    /// Launch id of the last process this agent started in the session, if any.
    launch_id: Option<u64>,
    /// Number of consecutive quick failures of the session process.
    consecutive_failures: u32,
    /// A reconnect must finish terminating its old host before lookup can adopt another one.
    termination_pending: bool,
}

// NOTE: `ceviche::controller::Session` do not implement `Debug` for session.
impl Debug for GatewaySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewaySession")
            .field("session", &self.session.id)
            .field("kind", &self.kind)
            .field("readiness", &self.readiness)
            .field("launch_id", &self.launch_id)
            .field("consecutive_failures", &self.consecutive_failures)
            .finish()
    }
}

impl GatewaySession {
    fn new(session: Session, kind: SessionKind, readiness: SessionReadiness) -> Self {
        Self {
            session,
            kind,
            readiness,
            launch_id: None,
            consecutive_failures: 0,
            termination_pending: false,
        }
    }

    fn kind(&self) -> SessionKind {
        self.kind
    }

    #[allow(dead_code)]
    fn os_session(&self) -> &Session {
        &self.session
    }

    /// Whether the Devolutions Session process should be started for this session.
    ///
    /// The process exists to host the DVC handler, which only a remote session can serve: a
    /// console session has no RDP client to open the dynamic virtual channel against, so starting
    /// the process there yields one that fails the open with `ERROR_FILE_NOT_FOUND` and exits.
    fn is_ready_to_start(&self, event: SessionReadinessEvent) -> bool {
        self.kind().is_remote() && self.readiness.is_satisfied_by(event)
    }

    fn set_session_ready(&mut self) {
        self.readiness = SessionReadiness::Ready;
    }

    fn set_waiting_for_logon(&mut self) {
        self.readiness = SessionReadiness::WaitingForLogon;
        self.consecutive_failures = 0;
    }

    /// Whether the process started with `launch_id` is the one this session still wants running.
    fn wants_launch(&self, launch_id: u64) -> bool {
        self.kind().is_remote() && self.readiness == SessionReadiness::Ready && self.launch_id == Some(launch_id)
    }
}

/// Exit of a session process started by this agent.
#[derive(Debug, Clone, Copy)]
struct ProcessExit {
    session_id: u32,
    launch_id: u64,
    exit_code: u32,
    run_time: Duration,
}

/// Events the session manager sends to itself.
#[derive(Debug)]
enum InternalEvent {
    ProcessExited(ProcessExit),
    RelaunchDue { session_id: u32, launch_id: u64 },
}

/// Delay before relaunching a process that failed for the first time.
const RELAUNCH_DELAY_FLOOR: Duration = Duration::from_secs(2);

/// Upper bound of the relaunch delay.
const RELAUNCH_DELAY_CAP: Duration = Duration::from_secs(60);

/// Run time after which a failure no longer counts as failing on start.
const STABLE_RUN_TIME: Duration = Duration::from_secs(60);

/// Number of consecutive quick failures after which relaunching stops until the next logon or unlock.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Delay before relaunching after the `consecutive_failures`-th consecutive quick failure, counting from 1.
fn relaunch_delay(consecutive_failures: u32) -> Duration {
    let doublings = consecutive_failures.saturating_sub(1);
    2u32.checked_pow(doublings)
        .and_then(|factor| RELAUNCH_DELAY_FLOOR.checked_mul(factor))
        .map_or(RELAUNCH_DELAY_CAP, |delay| delay.min(RELAUNCH_DELAY_CAP))
}

#[derive(Default, Debug)]
struct SessionManagerCtx {
    sessions: BTreeMap<String, GatewaySession>,
    last_launch_id: u64,
}

impl SessionManagerCtx {
    fn register_session(&mut self, session: &Session, kind: SessionKind, readiness: SessionReadiness) {
        self.sessions.insert(
            session.to_string(),
            GatewaySession::new(Session::new(session.id), kind, readiness),
        );
    }

    fn unregister_session(&mut self, session: &Session) {
        self.sessions.remove(&session.to_string());
    }

    fn get_session_mut(&mut self, session: &Session) -> Option<&mut GatewaySession> {
        self.sessions.get_mut(&session.to_string())
    }

    fn should_start_session(&self, session: &Session, event: SessionReadinessEvent) -> bool {
        self.sessions
            .get(&session.to_string())
            .is_some_and(|session| session.is_ready_to_start(event))
    }

    /// Starts the session process in a registered session unless it is already running.
    ///
    /// The session is marked ready only once its process is known to run, so that a failure leaves it waiting for the
    /// next readiness event.
    /// A process started here gets a fresh launch id, passed to `start` and recorded on the session, so that reports
    /// about an earlier process can be told apart.
    /// A process found already running keeps the recorded launch id, because nothing tells whether this agent started it.
    fn start_process_if_not_running(
        &mut self,
        session: &Session,
        is_running: impl FnOnce(&Session) -> anyhow::Result<bool>,
        start: impl FnOnce(&Session, u64) -> anyhow::Result<()>,
    ) -> bool {
        let launch_id = self.last_launch_id + 1;

        let Some(gw_session) = self.get_session_mut(session) else {
            warn!(%session, "Session is not yet registered");
            return false;
        };

        match is_running(session) {
            Ok(true) => {
                gw_session.set_session_ready();
                return true;
            }
            Ok(false) => {}
            Err(error) => {
                // Starting a process without knowing whether one already runs could start a second one.
                error!(
                    error = format!("{error:#}"),
                    %session,
                    "Failed to check whether the session process is running"
                );
                return false;
            }
        }

        info!(%session, "Starting session process");

        match start(session, launch_id) {
            Ok(()) => {
                info!(%session, launch_id, "Session process started");
                gw_session.set_session_ready();
                gw_session.launch_id = Some(launch_id);
                self.last_launch_id = launch_id;
                true
            }
            Err(error) => {
                error!(%error, %session, "Failed to start session process");
                false
            }
        }
    }

    /// Decides what to do about the exit of a session process this agent started.
    ///
    /// Returns the delay after which to relaunch the process, or `None` when it must not be relaunched.
    fn handle_process_exit(&mut self, exit: &ProcessExit) -> Option<Duration> {
        let ProcessExit {
            session_id,
            launch_id,
            exit_code,
            run_time,
        } = *exit;

        let Some(gw_session) = self
            .get_session_mut(&Session::new(session_id))
            .filter(|gw_session| gw_session.wants_launch(launch_id))
        else {
            debug!(
                session = session_id,
                launch_id, exit_code, "Ignored exit of an unwanted session process"
            );
            return None;
        };

        if exit_code == 0 {
            info!(session = session_id, launch_id, "Session process ended");
            return None;
        }

        if STABLE_RUN_TIME <= run_time {
            gw_session.consecutive_failures = 0;
        }
        warn!(
            session = session_id,
            launch_id,
            exit_code = format!("{exit_code:#010X}"),
            ?run_time,
            "Session process failed"
        );

        self.retry_failed_launch(session_id, launch_id)
    }

    fn retry_failed_launch(&mut self, session_id: u32, launch_id: u64) -> Option<Duration> {
        let gw_session = self
            .get_session_mut(&Session::new(session_id))
            .filter(|gw_session| gw_session.wants_launch(launch_id))?;
        gw_session.consecutive_failures += 1;

        if MAX_CONSECUTIVE_FAILURES <= gw_session.consecutive_failures {
            error!(
                session = session_id,
                launch_id,
                consecutive_failures = gw_session.consecutive_failures,
                "Session process recovery keeps failing; waiting for the next logon or unlock"
            );
            gw_session.readiness = SessionReadiness::WaitingForLogonOrUnlock;
            gw_session.consecutive_failures = 0;
            return None;
        }

        let delay = relaunch_delay(gw_session.consecutive_failures);
        warn!(
            session = session_id,
            launch_id,
            ?delay,
            "Scheduling session process recovery"
        );

        Some(delay)
    }

    /// Whether a relaunch scheduled after the exit of the process started with `launch_id` is still wanted.
    fn should_relaunch(&self, session_id: u32, launch_id: u64) -> bool {
        self.sessions
            .get(&Session::new(session_id).to_string())
            .is_some_and(|gw_session| gw_session.wants_launch(launch_id))
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

    async fn run(self, shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        self.run_with(shutdown_signal, &WindowsSessionSystem).await
    }
}

trait SessionSystem: Sync {
    fn active_remote_sessions(&self) -> anyhow::Result<Vec<Session>>;
    fn has_logged_in_user(&self, session: &Session) -> anyhow::Result<bool>;
    fn is_running(&self, session: &Session) -> anyhow::Result<bool>;
    fn start_watched(
        &self,
        session: &Session,
        launch_id: u64,
        internal_tx: &mpsc::UnboundedSender<InternalEvent>,
    ) -> anyhow::Result<()>;
    fn terminate(&self, session: &Session) -> anyhow::Result<()>;
}

struct WindowsSessionSystem;

impl SessionSystem for WindowsSessionSystem {
    fn active_remote_sessions(&self) -> anyhow::Result<Vec<Session>> {
        let mut active_sessions = Vec::new();
        for session in get_sessions()? {
            if session.state != WTSConnectState::Active {
                continue;
            }

            match session_uses_rdp(session.session_id) {
                Ok(true) => active_sessions.push(Session::new(session.session_id)),
                Ok(false) => {}
                Err(error) => {
                    warn!(
                        session_id = session.session_id,
                        %error,
                        "Failed to query the protocol of an existing session"
                    );
                }
            }
        }
        Ok(active_sessions)
    }

    fn has_logged_in_user(&self, session: &Session) -> anyhow::Result<bool> {
        session_has_logged_in_user(session.id)
    }

    fn is_running(&self, session: &Session) -> anyhow::Result<bool> {
        is_session_running_in_session(session)
    }

    fn start_watched(
        &self,
        session: &Session,
        launch_id: u64,
        internal_tx: &mpsc::UnboundedSender<InternalEvent>,
    ) -> anyhow::Result<()> {
        let process = start_session_process(session)?;
        watch_session_process(process, session.id, launch_id, internal_tx.clone());
        Ok(())
    }

    fn terminate(&self, session: &Session) -> anyhow::Result<()> {
        terminate_session_process(session)
    }
}

impl SessionManager {
    async fn run_with(self, mut shutdown_signal: ShutdownSignal, system: &dyn SessionSystem) -> anyhow::Result<()> {
        let Self {
            mut service_event_rx,
            ctx,
            ..
        } = self;

        info!("Starting session manager...");

        // The loop keeps a sender, so the receiver never reports a closed channel.
        let (internal_tx, mut internal_rx) = mpsc::unbounded_channel();

        // Keep queued SCM events so disconnects during enumeration still stop their hosts.
        // UNTESTED: SCM delivers session changes while WTS enumeration runs.
        // When changing service startup, verify this ordering in a live RDP session.
        match system.active_remote_sessions() {
            Ok(sessions) => {
                let mut ctx = ctx.write().await;
                for session in sessions {
                    ctx.register_session(&session, SessionKind::Remote, SessionReadiness::WaitingForLogonOrUnlock);
                    start_session_process_if_not_running(&mut ctx, system, &session, &internal_tx);
                }
            }
            Err(error) => {
                error!(%error, "Failed to enumerate existing remote sessions");
            }
        }

        loop {
            tokio::select! {
                Some(event) = internal_rx.recv() => {
                    let mut ctx = ctx.write().await;
                    match event {
                        InternalEvent::ProcessExited(exit) => {
                            if let Some(delay) = ctx.handle_process_exit(&exit) {
                                schedule_relaunch(&internal_tx, exit.session_id, exit.launch_id, delay);
                            }
                        }
                        InternalEvent::RelaunchDue { session_id, launch_id } => {
                            if ctx.should_relaunch(session_id, launch_id) {
                                info!(session = session_id, "Relaunching session process");
                                if !start_session_process_if_not_running(&mut ctx, system, &Session::new(session_id), &internal_tx)
                                    && let Some(delay) = ctx.retry_failed_launch(session_id, launch_id)
                                {
                                    schedule_relaunch(&internal_tx, session_id, launch_id, delay);
                                }
                            }
                        }
                    }
                }
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
                            // The session is registered so that a later upgrade to a remote
                            // session is tracked, but the session process is only ever started for
                            // remote sessions (initiated via RDP), because the DVC handler it hosts
                            // is only reachable from one. `GatewaySession::is_ready_to_start`
                            // enforces that.
                            ctx.register_session(&id, SessionKind::Console, SessionReadiness::WaitingForLogon);
                        }
                        AgentServiceEvent::SessionDisconnect(id) => {
                            info!(%id, "Session disconnected");
                            if let Err(error) = system.terminate(&id) {
                                error!(%id, %error, "Failed to terminate disconnected session process");
                            }
                            ctx.write().await.unregister_session(&id);
                        }
                        AgentServiceEvent::SessionRemoteConnect(id) => {
                            info!(%id, "Remote session connected");
                            let readiness = match system.has_logged_in_user(&id) {
                                Ok(true) => SessionReadiness::WaitingForUnlock,
                                Ok(false) => SessionReadiness::WaitingForLogon,
                                Err(error) => {
                                    error!(
                                        %error,
                                        %id,
                                        "Failed to determine whether the remote session has a logged in user"
                                    );
                                    SessionReadiness::WaitingForLogonOrUnlock
                                }
                            };

                            {
                                let mut ctx = ctx.write().await;
                                ctx.register_session(&id, SessionKind::Remote, readiness);
                                ctx.get_session_mut(&id).expect("session was just registered").termination_pending = true;

                                if !finish_session_termination(&mut ctx, system, &id) {
                                    continue;
                                }

                                // A queued connect may predate the startup snapshot and its user's logon.
                                match system.active_remote_sessions() {
                                    Ok(sessions) if sessions.iter().any(|session| session.id == id.id) => {
                                        start_session_process_if_not_running(&mut ctx, system, &id, &internal_tx);
                                    }
                                    Ok(_) => {}
                                    Err(error) => {
                                        error!(%id, %error, "Failed to check whether the remote session is active");
                                    }
                                }
                            }
                        }
                        AgentServiceEvent::SessionRemoteDisconnect(id) => {
                            info!(%id, "Remote session disconnected");
                            // Terminate session process when remote session is disconnected
                            // (NOTE: depending on the system settings, session could
                            // still be running in the background after RDP disconnect).
                            if let Err(error) = system.terminate(&id) {
                                error!(%id, %error, "Failed to terminate disconnected session process");
                            }
                            ctx.write().await.unregister_session(&id);
                        }
                        AgentServiceEvent::SessionLogon(id) => {
                            info!(%id, "Session logged on");

                            // NOTE: In some cases, SessionRemoteConnect is fired before
                            // an actual user is logged in, therefore we need to try start the
                            // session app on logon, if not yet started.
                            let mut ctx = ctx.write().await;
                            if ctx.should_start_session(&id, SessionReadinessEvent::Logon) {
                                start_session_process_if_not_running(&mut ctx, system, &id, &internal_tx);
                            }
                        }
                        AgentServiceEvent::SessionUnlock(id) => {
                            info!(%id, "Session unlocked");

                            let mut ctx = ctx.write().await;
                            if ctx.should_start_session(&id, SessionReadinessEvent::Unlock) {
                                start_session_process_if_not_running(&mut ctx, system, &id, &internal_tx);
                            }
                        }
                        AgentServiceEvent::SessionLogoff(id) => {
                            info!(%id, "Session logged off");
                            if let Some(session) = ctx.write().await.get_session_mut(&id) {
                                // When a user logs off, session process will be stopped by the system;
                                // Console sessions could be reused for different users, therefore
                                // we should not remove the session from the list, but mark it as
                                // not yet ready (session will be started as soon as new user logs in).
                                session.set_waiting_for_logon();
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
///
/// A process started here is watched, and its exit is reported through `internal_tx`.
/// A process found already running, such as one started by an earlier agent instance, is not watched, so its exit is
/// not relaunched until the next logon or unlock.
fn start_session_process_if_not_running(
    ctx: &mut SessionManagerCtx,
    system: &dyn SessionSystem,
    session: &Session,
    internal_tx: &mpsc::UnboundedSender<InternalEvent>,
) -> bool {
    if !finish_session_termination(ctx, system, session) {
        return false;
    }
    ctx.start_process_if_not_running(
        session,
        |session| system.is_running(session),
        |session, launch_id| system.start_watched(session, launch_id, internal_tx),
    )
}

fn finish_session_termination(ctx: &mut SessionManagerCtx, system: &dyn SessionSystem, session: &Session) -> bool {
    let Some(gw_session) = ctx.get_session_mut(session) else {
        return false;
    };
    if gw_session.termination_pending {
        if let Err(error) = system.terminate(session) {
            error!(%session, %error, "Failed to finish terminating the previous session process");
            return false;
        }
        gw_session.termination_pending = false;
    }
    true
}

/// Reports the exit of `process` to the session manager from a dedicated thread.
///
/// The thread blocks until the process exits, which may outlive the session manager.
fn watch_session_process(
    process: Process,
    session_id: u32,
    launch_id: u64,
    internal_tx: mpsc::UnboundedSender<InternalEvent>,
) {
    let started_at = Instant::now();

    // UNTESTED: the watcher is a detached `std::thread`, never a `tokio::task::spawn_blocking` task, and is never
    // joined, because the runtime waits for blocking tasks at shutdown and a long-lived process would then hang the
    // service stop.
    // When changing this, check that stopping the service with a running session process returns promptly.
    let spawn_result = std::thread::Builder::new()
        .name(format!("session-{session_id}-process-watcher"))
        .spawn(move || {
            let exit_code = match process.wait(None).and_then(|_| process.exit_code()) {
                Ok(exit_code) => exit_code,
                Err(error) => {
                    error!(%error, session = session_id, "Failed to wait for session process exit");
                    return;
                }
            };

            let exit = ProcessExit {
                session_id,
                launch_id,
                exit_code,
                run_time: started_at.elapsed(),
            };

            // The session manager is gone once it shuts down, and then nothing is left to relaunch the process.
            let _ = internal_tx.send(InternalEvent::ProcessExited(exit));
        });

    if let Err(error) = spawn_result {
        error!(%error, session = session_id, "Failed to watch session process");
    }
}

/// Sends a relaunch-due event for the process started with `launch_id` after `delay`.
fn schedule_relaunch(
    internal_tx: &mpsc::UnboundedSender<InternalEvent>,
    session_id: u32,
    launch_id: u64,
    delay: Duration,
) {
    let internal_tx = internal_tx.clone();

    // UNTESTED: the timer is a detached task that nothing awaits, so that shutting down the session manager does not
    // wait for a pending relaunch.
    // When changing this, check that stopping the service during a relaunch delay returns promptly.
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = internal_tx.send(InternalEvent::RelaunchDue { session_id, launch_id });
    });
}

/// Terminates Devolutions Session process in the target session.
fn terminate_session_process(session: &Session) -> anyhow::Result<()> {
    match terminate_process_by_name_in_session_and_wait(SESSION_BINARY, session.id, 1_000)? {
        false => {
            trace!(%session, "Session process is not running");
        }
        true => {
            info!(%session, "Session process terminated");
        }
    }
    Ok(())
}

fn is_session_running_in_session(session: &Session) -> anyhow::Result<bool> {
    let is_running = is_process_running_in_session(SESSION_BINARY, session.id)?;
    Ok(is_running)
}

fn start_session_process(session: &Session) -> anyhow::Result<Process> {
    if !session_has_logged_in_user(session.id)? {
        anyhow::bail!("Session {} does not have a logged in user", session);
    }

    let session_app_path = session_app_path();
    let command_line = session_command_line(&session_app_path, session);

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
        Ok(process_information) => {
            info!(%session, process_id = process_information.process_id, "{SESSION_BINARY} started");
            Ok(process_information.process)
        }
        Err(error) => {
            error!(%error, %session, "Failed to start {SESSION_BINARY}");
            Err(error)
        }
    }
}

/// Builds the session process command line.
///
/// The process receives the command line unchanged as its whole command line, so it must start with the module name
/// that the process reads as `argv[0]`.
fn session_command_line(session_app_path: &Utf8Path, session: &Session) -> CommandLine {
    CommandLine::new(vec![
        session_app_path.as_str().to_owned(),
        "--session".to_owned(),
        session.to_string(),
    ])
}

fn session_app_path() -> Utf8PathBuf {
    let mut current_dir = Utf8PathBuf::from_path_buf(std::env::current_exe().expect("BUG: can't get current exe path"))
        .expect("BUG: OS should always return valid UTF-8 executable path");

    current_dir.pop();
    current_dir.push(SESSION_BINARY);

    current_dir
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::Mutex;
    use std::time::Duration;

    use camino::Utf8Path;
    use devolutions_gateway_task::{ChildTask, ShutdownHandle};
    use tokio::sync::mpsc;
    use win_api_wrappers::utils::CommandLine;

    use super::{
        AgentServiceEvent, GatewaySession, InternalEvent, ProcessExit, Session, SessionKind, SessionManager,
        SessionManagerCtx, SessionReadiness, SessionReadinessEvent, SessionSystem, relaunch_delay,
        session_command_line,
    };

    #[derive(Debug, PartialEq, Eq)]
    enum HostAction {
        Started(u32),
        Stopped(u32),
        FoundRunning(u32),
    }

    struct TestSessionSystem {
        active_sessions: Vec<u32>,
        events: mpsc::Sender<AgentServiceEvent>,
        events_during_snapshot: Mutex<Vec<AgentServiceEvent>>,
        lookup_failures: Mutex<VecDeque<bool>>,
        termination_failures: Mutex<VecDeque<bool>>,
        running: Mutex<BTreeSet<u32>>,
        exit_on_start: Mutex<Option<u32>>,
        actions: mpsc::UnboundedSender<HostAction>,
    }

    impl SessionSystem for TestSessionSystem {
        fn active_remote_sessions(&self) -> anyhow::Result<Vec<Session>> {
            for event in std::mem::take(&mut *self.events_during_snapshot.lock().expect("snapshot events lock")) {
                assert!(self.events.try_send(event).is_ok(), "session event queue has capacity");
            }
            Ok(self.active_sessions.iter().copied().map(Session::new).collect())
        }

        fn has_logged_in_user(&self, _session: &Session) -> anyhow::Result<bool> {
            Ok(true)
        }

        fn is_running(&self, session: &Session) -> anyhow::Result<bool> {
            if self
                .lookup_failures
                .lock()
                .expect("lookup failure lock")
                .pop_front()
                .unwrap_or(false)
            {
                anyhow::bail!("process lookup failed");
            }
            let running = self
                .running
                .lock()
                .expect("running processes lock")
                .contains(&session.id);
            if running {
                self.actions
                    .send(HostAction::FoundRunning(session.id))
                    .expect("host observer remains open");
            }
            Ok(running)
        }

        fn start_watched(
            &self,
            session: &Session,
            launch_id: u64,
            internal_tx: &mpsc::UnboundedSender<InternalEvent>,
        ) -> anyhow::Result<()> {
            assert!(
                self.running.lock().expect("running processes lock").insert(session.id),
                "duplicate host launch"
            );
            self.actions
                .send(HostAction::Started(session.id))
                .expect("host observer remains open");
            if let Some(exit_code) = self.exit_on_start.lock().expect("process exit lock").take() {
                self.running.lock().expect("running processes lock").remove(&session.id);
                internal_tx
                    .send(InternalEvent::ProcessExited(ProcessExit {
                        session_id: session.id,
                        launch_id,
                        exit_code,
                        run_time: Duration::ZERO,
                    }))
                    .expect("session manager remains open");
            }
            Ok(())
        }

        fn terminate(&self, session: &Session) -> anyhow::Result<()> {
            if self
                .termination_failures
                .lock()
                .expect("termination failure lock")
                .pop_front()
                .unwrap_or(false)
            {
                anyhow::bail!("previous process is still terminating");
            }
            if self.running.lock().expect("running processes lock").remove(&session.id) {
                self.actions
                    .send(HostAction::Stopped(session.id))
                    .expect("host observer remains open");
            }
            Ok(())
        }
    }

    fn start_test_manager(
        active_sessions: Vec<u32>,
        running: BTreeSet<u32>,
        events_during_snapshot: Vec<AgentServiceEvent>,
        lookup_failures: Vec<bool>,
        exit_on_start: Option<u32>,
        termination_failures: Vec<bool>,
    ) -> (
        ShutdownHandle,
        ChildTask<anyhow::Result<()>>,
        mpsc::UnboundedReceiver<HostAction>,
    ) {
        let manager = SessionManager::default();
        let (shutdown, signal) = ShutdownHandle::new();
        let (actions, observations) = mpsc::unbounded_channel();
        let system = TestSessionSystem {
            active_sessions,
            events: manager.service_event_tx(),
            events_during_snapshot: Mutex::new(events_during_snapshot),
            lookup_failures: Mutex::new(lookup_failures.into()),
            termination_failures: Mutex::new(termination_failures.into()),
            running: Mutex::new(running),
            exit_on_start: Mutex::new(exit_on_start),
            actions,
        };
        let task = ChildTask::spawn(async move { manager.run_with(signal, &system).await });
        (shutdown, task, observations)
    }

    async fn next_action(actions: &mut mpsc::UnboundedReceiver<HostAction>) -> HostAction {
        tokio::time::timeout(Duration::from_secs(10), actions.recv())
            .await
            .expect("session manager did not act")
            .expect("session manager stopped")
    }

    // oracle: reference deployed Agent 2BD6884A9E49A9D6FE80F6036907C48BECF180C0DBDD7AD93C3C7B80D571FA45
    // launches a missing host in an already-active RDP session without new logon or unlock events.
    #[tokio::test]
    async fn already_active_remote_session_launches_without_new_events() {
        let (shutdown, task, mut actions) = start_test_manager(vec![42], BTreeSet::new(), vec![], vec![], None, vec![]);

        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
    }

    // oracle: mutant replayed connection events leave an active session waiting for an already-past logon.
    #[tokio::test]
    async fn reconnect_during_snapshot_restores_an_already_active_host() {
        let (shutdown, task, mut actions) = start_test_manager(
            vec![42],
            BTreeSet::new(),
            vec![
                AgentServiceEvent::SessionRemoteDisconnect(Session::new(42)),
                AgentServiceEvent::SessionRemoteConnect(Session::new(42)),
            ],
            vec![],
            None,
            vec![],
        );

        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));
        assert_eq!(next_action(&mut actions).await, HostAction::Stopped(42));
        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
    }

    // oracle: reference deployed Agent 2BD6884A9E49A9D6FE80F6036907C48BECF180C0DBDD7AD93C3C7B80D571FA45
    // adopts an existing host on restart without replacing it.
    #[tokio::test]
    async fn already_running_startup_host_is_adopted() {
        let (shutdown, task, mut actions) =
            start_test_manager(vec![42], BTreeSet::from([42]), vec![], vec![], None, vec![]);

        assert_eq!(next_action(&mut actions).await, HostAction::FoundRunning(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
        assert!(
            actions.try_recv().is_err(),
            "startup must neither stop nor duplicate the host"
        );
    }

    // oracle: mutant discarding notifications during the initial snapshot leaves a disconnected host running.
    #[tokio::test]
    async fn disconnect_during_snapshot_stops_the_host() {
        let (shutdown, task, mut actions) = start_test_manager(
            vec![42],
            BTreeSet::new(),
            vec![AgentServiceEvent::SessionRemoteDisconnect(Session::new(42))],
            vec![],
            None,
            vec![],
        );

        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));
        assert_eq!(next_action(&mut actions).await, HostAction::Stopped(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
    }

    // oracle: mutant a session absent from the snapshot loses its queued connection or logon event.
    #[tokio::test]
    async fn connection_during_snapshot_launches_after_logon() {
        let (shutdown, task, mut actions) = start_test_manager(
            vec![],
            BTreeSet::new(),
            vec![
                AgentServiceEvent::SessionRemoteConnect(Session::new(42)),
                AgentServiceEvent::SessionLogon(Session::new(42)),
            ],
            vec![],
            None,
            vec![],
        );

        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
    }

    // oracle: mutant a transient lookup error kills the manager instead of allowing a readiness retry.
    #[tokio::test]
    async fn process_lookup_failure_does_not_stop_later_readiness_events() {
        let (shutdown, task, mut actions) = start_test_manager(
            vec![],
            BTreeSet::new(),
            vec![
                AgentServiceEvent::SessionRemoteConnect(Session::new(42)),
                AgentServiceEvent::SessionLogon(Session::new(42)),
                AgentServiceEvent::SessionUnlock(Session::new(42)),
            ],
            vec![true],
            None,
            vec![],
        );

        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
    }

    // oracle: mutant startup launches bypass the process-exit notification and relaunch path.
    #[tokio::test]
    async fn failed_startup_host_is_relaunched_through_the_watched_path() {
        let (shutdown, task, mut actions) =
            start_test_manager(vec![42], BTreeSet::new(), vec![], vec![], Some(1), vec![]);

        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));
        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
    }

    // oracle: mutant a transient lookup failure during relaunch leaves the session Ready without another retry.
    #[tokio::test]
    async fn relaunch_lookup_failure_is_retried_without_another_service_event() {
        let (shutdown, task, mut actions) =
            start_test_manager(vec![42], BTreeSet::new(), vec![], vec![false, true], Some(1), vec![]);

        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));
        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
    }

    // oracle: mutant reconnect adopts the old host before its asynchronous termination completes.
    #[tokio::test]
    async fn reconnect_does_not_adopt_a_host_still_terminating() {
        let (shutdown, task, mut actions) = start_test_manager(
            vec![42],
            BTreeSet::from([42]),
            vec![
                AgentServiceEvent::SessionRemoteConnect(Session::new(42)),
                AgentServiceEvent::SessionUnlock(Session::new(42)),
            ],
            vec![],
            None,
            vec![true],
        );

        assert_eq!(next_action(&mut actions).await, HostAction::FoundRunning(42));
        assert_eq!(next_action(&mut actions).await, HostAction::Stopped(42));
        assert_eq!(next_action(&mut actions).await, HostAction::Started(42));

        shutdown.signal();
        task.join()
            .await
            .expect("session manager task")
            .expect("session manager result");
    }

    fn make_session(kind: SessionKind, readiness: SessionReadiness) -> GatewaySession {
        GatewaySession::new(Session::new(1), kind, readiness)
    }

    /// The session process reads its arguments after `argv[0]`, so a command line without the module name loses the
    /// first one.
    #[test]
    fn session_command_line_starts_with_the_module_name() {
        let session_app_path = Utf8Path::new(r"C:\Program Files\Devolutions\Agent\DevolutionsSession.exe");

        let command_line = session_command_line(session_app_path, &Session::new(3)).to_command_line();

        let argv = CommandLine::from_command_line(&command_line).0;
        // oracle: spec CreateProcessAsUserW §Parameters
        assert_eq!(argv[0], session_app_path.as_str());
        // oracle: scaffold
        assert_eq!(argv[1..], ["--session", "3"]);
    }

    /// A failure to look up the session process must neither end the session manager nor mark the session ready, so
    /// that the next readiness event retries.
    // oracle: scaffold
    #[test]
    fn process_lookup_failure_leaves_the_session_waiting() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        ctx.register_session(&session, SessionKind::Remote, SessionReadiness::WaitingForLogon);

        ctx.start_process_if_not_running(
            &session,
            |_| Err(anyhow::anyhow!("process lookup failed")),
            |_, _| panic!("the process was started although the lookup failed"),
        );

        assert!(ctx.should_start_session(&session, SessionReadinessEvent::Logon));
    }

    #[test]
    fn new_user_session_waits_for_logon() {
        assert!(SessionReadiness::WaitingForLogon.is_satisfied_by(SessionReadinessEvent::Logon));
        assert!(!SessionReadiness::WaitingForLogon.is_satisfied_by(SessionReadinessEvent::Unlock));
    }

    #[test]
    fn existing_user_session_waits_for_unlock() {
        assert!(SessionReadiness::WaitingForUnlock.is_satisfied_by(SessionReadinessEvent::Unlock));
        assert!(SessionReadiness::WaitingForUnlock.is_satisfied_by(SessionReadinessEvent::Logon));
    }

    #[test]
    fn ready_session_ignores_later_readiness_events() {
        assert!(!SessionReadiness::Ready.is_satisfied_by(SessionReadinessEvent::Logon));
        assert!(!SessionReadiness::Ready.is_satisfied_by(SessionReadinessEvent::Unlock));
    }

    #[test]
    fn unknown_session_user_state_accepts_logon_or_unlock() {
        assert!(SessionReadiness::WaitingForLogonOrUnlock.is_satisfied_by(SessionReadinessEvent::Logon));
        assert!(SessionReadiness::WaitingForLogonOrUnlock.is_satisfied_by(SessionReadinessEvent::Unlock));
    }

    #[test]
    fn console_session_never_starts_the_session_process() {
        for readiness in [
            SessionReadiness::WaitingForLogon,
            SessionReadiness::WaitingForUnlock,
            SessionReadiness::WaitingForLogonOrUnlock,
        ] {
            let session = make_session(SessionKind::Console, readiness);

            assert!(!session.is_ready_to_start(SessionReadinessEvent::Logon));
            assert!(!session.is_ready_to_start(SessionReadinessEvent::Unlock));
        }
    }

    #[test]
    fn remote_session_starts_on_its_readiness_event() {
        let session = make_session(SessionKind::Remote, SessionReadiness::WaitingForLogon);
        assert!(session.is_ready_to_start(SessionReadinessEvent::Logon));

        let session = make_session(SessionKind::Remote, SessionReadiness::WaitingForUnlock);
        assert!(session.is_ready_to_start(SessionReadinessEvent::Unlock));
    }

    /// Registers a remote session and starts its process through the production path, returning its launch id.
    fn start_ready_remote_session(ctx: &mut SessionManagerCtx, session: &Session) -> u64 {
        ctx.register_session(session, SessionKind::Remote, SessionReadiness::WaitingForLogon);
        start_again(ctx, session)
    }

    /// Starts the process of an already registered session as a relaunch would, returning its launch id.
    fn start_again(ctx: &mut SessionManagerCtx, session: &Session) -> u64 {
        let mut launched = None;
        ctx.start_process_if_not_running(
            session,
            |_| Ok(false),
            |_, launch_id| {
                launched = Some(launch_id);
                Ok(())
            },
        );
        launched.expect("the process was not started")
    }

    fn failed_exit(session: &Session, launch_id: u64, run_time: Duration) -> ProcessExit {
        ProcessExit {
            session_id: session.id,
            launch_id,
            exit_code: 0xC000_0005,
            run_time,
        }
    }

    const QUICK_RUN: Duration = Duration::from_secs(1);

    /// A process that crashes while its session still wants it must come back, or the channel it hosts stays unserved.
    // oracle: scaffold
    #[test]
    fn failed_exit_of_ready_remote_session_schedules_relaunch_after_the_floor_delay() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);

        let delay = ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN));

        assert_eq!(delay, Some(Duration::from_secs(2)));
        assert!(ctx.should_relaunch(session.id, launch_id));
    }

    /// Back-off keeps a process that fails on start from being relaunched in a tight loop.
    // oracle: scaffold
    #[test]
    fn relaunch_delay_doubles_per_consecutive_failure_and_is_capped() {
        assert_eq!(relaunch_delay(1), Duration::from_secs(2));
        assert_eq!(relaunch_delay(2), Duration::from_secs(4));
        assert_eq!(relaunch_delay(3), Duration::from_secs(8));
        assert_eq!(relaunch_delay(6), Duration::from_secs(60));
        assert_eq!(relaunch_delay(u32::MAX), Duration::from_secs(60));
    }

    /// Consecutive quick failures of relaunched processes grow the delay.
    // oracle: scaffold
    #[test]
    fn second_quick_failure_doubles_the_delay() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN));
        let launch_id = start_again(&mut ctx, &session);

        let delay = ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN));

        assert_eq!(delay, Some(Duration::from_secs(4)));
    }

    /// A process that ran for a while before failing is not failing on start, so it is relaunched promptly.
    // oracle: scaffold
    #[test]
    fn long_run_before_failure_resets_the_delay() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN));
        let launch_id = start_again(&mut ctx, &session);
        ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN));
        let launch_id = start_again(&mut ctx, &session);

        let delay = ctx.handle_process_exit(&failed_exit(&session, launch_id, Duration::from_secs(60)));

        assert_eq!(delay, Some(Duration::from_secs(2)));
    }

    /// A process that keeps failing on start is given up on, and the next logon or unlock tries again.
    // oracle: scaffold
    #[test]
    fn repeated_quick_failures_give_up_until_the_next_logon_or_unlock() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let mut launch_id = start_ready_remote_session(&mut ctx, &session);
        for _ in 0..4 {
            assert!(
                ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN))
                    .is_some()
            );
            launch_id = start_again(&mut ctx, &session);
        }

        let delay = ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN));

        assert_eq!(delay, None);
        assert!(ctx.should_start_session(&session, SessionReadinessEvent::Logon));
        assert!(ctx.should_start_session(&session, SessionReadinessEvent::Unlock));
    }

    /// Exit code 0 means the process ended on purpose, such as when the client has no listener for the channel.
    // oracle: scaffold
    #[test]
    fn clean_exit_is_not_relaunched() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        let exit = ProcessExit {
            exit_code: 0,
            ..failed_exit(&session, launch_id, QUICK_RUN)
        };

        assert_eq!(ctx.handle_process_exit(&exit), None);
        assert!(!ctx.should_start_session(&session, SessionReadinessEvent::Logon));
    }

    /// The exit of a process replaced by a later launch says nothing about the current one.
    // oracle: scaffold
    #[test]
    fn exit_of_a_replaced_launch_is_ignored() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let old_launch_id = start_ready_remote_session(&mut ctx, &session);
        start_again(&mut ctx, &session);

        assert_eq!(
            ctx.handle_process_exit(&failed_exit(&session, old_launch_id, QUICK_RUN)),
            None
        );
    }

    /// A reconnected session terminates the old process, whose exit must not start a second one.
    // oracle: scaffold
    #[test]
    fn exit_after_remote_reconnect_is_ignored() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        ctx.register_session(&session, SessionKind::Remote, SessionReadiness::WaitingForUnlock);

        assert_eq!(
            ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN)),
            None
        );
    }

    /// A disconnected session terminates its process and wants none.
    // oracle: scaffold
    #[test]
    fn exit_after_disconnect_is_ignored() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        ctx.unregister_session(&session);

        assert_eq!(
            ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN)),
            None
        );
    }

    /// The system stops the process at logoff, and the next logon starts it.
    // oracle: scaffold
    #[test]
    fn exit_after_logoff_is_ignored() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        ctx.get_session_mut(&session)
            .expect("the session is registered")
            .set_waiting_for_logon();

        assert_eq!(
            ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN)),
            None
        );
    }

    /// A console session never hosts the process, so a stray report for one must not start it.
    // oracle: scaffold
    #[test]
    fn exit_in_console_session_is_ignored() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        ctx.register_session(&session, SessionKind::Console, SessionReadiness::Ready);
        ctx.get_session_mut(&session)
            .expect("the session is registered")
            .launch_id = Some(launch_id);

        assert_eq!(
            ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN)),
            None
        );
    }

    /// A session that logged off during the delay must not have the process started when the delay ends.
    // oracle: scaffold
    #[test]
    fn relaunch_due_after_logoff_is_ignored() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN));
        ctx.get_session_mut(&session)
            .expect("the session is registered")
            .set_waiting_for_logon();

        assert!(!ctx.should_relaunch(session.id, launch_id));
    }

    /// A relaunch scheduled for a launch that was since replaced must not start another process.
    // oracle: scaffold
    #[test]
    fn relaunch_due_for_a_replaced_launch_is_ignored() {
        let session = Session::new(1);
        let mut ctx = SessionManagerCtx::default();
        let launch_id = start_ready_remote_session(&mut ctx, &session);
        ctx.handle_process_exit(&failed_exit(&session, launch_id, QUICK_RUN));
        start_again(&mut ctx, &session);

        assert!(!ctx.should_relaunch(session.id, launch_id));
    }

    #[test]
    fn ready_remote_session_is_not_started_twice() {
        let session = make_session(SessionKind::Remote, SessionReadiness::Ready);

        assert!(!session.is_ready_to_start(SessionReadinessEvent::Logon));
        assert!(!session.is_ready_to_start(SessionReadinessEvent::Unlock));
    }
}
