use std::io::{Read as _, Write as _};
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use devolutions_agent_shared::windows::RDM_UPDATE_CODE;
use devolutions_agent_shared::windows::registry::{
    ProductVersionEncoding, get_install_location, get_installed_product_version,
};
use now_proto_pdu::ironrdp_core::{Encode, WriteCursor};
use now_proto_pdu::{
    NowChannelCapsetMsg, NowMessage, NowProtoVersion, NowRdmAppNotifyMsg, NowRdmAppStartMsg, NowRdmAppState,
    NowRdmCapabilitiesMsg, NowRdmMessage, NowRdmReason,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tracing::{error, info, trace, warn};
use win_api_wrappers::event::Event;
use win_api_wrappers::handle::Handle;
use win_api_wrappers::process::{Process, ProcessEntry32Iterator, get_current_session_id};
use win_api_wrappers::utils::WideString;
use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, CreateProcessW, NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, STARTUPINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::{SW_MAXIMIZE, SW_RESTORE};
use windows::core::{PCWSTR, PWSTR};

use crate::dvc::channel::WinapiSignaledSender;
use crate::dvc::now_message_dissector::NowMessageDissector;

const PIPE_READ_BUFFER_SIZE: usize = 4096;

/// Generate session-specific RDM agent pipe name with process ID.
///
/// Format: `\\.\pipe\devolutions-session-rdm-{session_id}-{pid}`
fn get_rdm_pipe_name(pid: u32) -> anyhow::Result<String> {
    let session_id = get_current_session_id().context("Failed to get current session ID")?;
    Ok(format!(r"\\.\pipe\devolutions-session-rdm-{}-{}", session_id, pid))
}

/// Generate session-specific RDM ready event name with process ID.
///
/// Format: `Global\devolutions-session-rdm-{session_id}-{pid}-ready`
/// This event is created by devolutions-session and signaled by RDM when ready.
fn get_rdm_ready_event_name(pid: u32) -> anyhow::Result<String> {
    let session_id = get_current_session_id().context("Failed to get current session ID")?;
    Ok(format!(r"Global\devolutions-session-rdm-{}-{}-ready", session_id, pid))
}

/// Create or open the RDM ready event for a specific process
///
/// Creates a named event that RDM will signal when its pipe server is ready.
/// If RDM already created the event (it was launched before us), we open it instead.
fn create_or_open_rdm_ready_event(pid: u32) -> anyhow::Result<Event> {
    let event_name = get_rdm_ready_event_name(pid)?;

    info!(event_name, pid, "Creating or opening RDM ready event");

    // Check if event already existed after creation
    // Use auto-reset event (false) so it automatically resets after one waiter is released
    let event = Event::new_named(&event_name, false, false)?;
    #[allow(clippy::cast_possible_wrap)]
    let already_exists = win_api_wrappers::Error::last_error().code() == ERROR_ALREADY_EXISTS.0 as i32;

    if already_exists {
        info!(
            event_name,
            pid, "RDM ready event already exists (RDM was launched first)"
        );
    } else {
        info!(event_name, pid, "Created new RDM ready event");
    }

    Ok(event)
}

/// RDM named pipe connection for message passthrough
pub struct RdmPipeConnection {
    pipe: NamedPipeClient,
    pipe_name: String,
    dissector: NowMessageDissector,
}

impl RdmPipeConnection {
    /// Connect to RDM named pipe after waiting for ready event
    ///
    /// Waits for RDM ready event to be signaled, then connects to the pipe.
    /// The ready event is dropped after connection, allowing RDM to own it.
    async fn connect(timeout_secs: u32, ready_event: Event, pid: u32) -> anyhow::Result<Self> {
        let pipe_name = get_rdm_pipe_name(pid)?;
        let timeout_ms = timeout_secs.saturating_mul(1000);

        info!(pipe_name, timeout_secs, "Waiting for RDM and connecting to pipe");

        // Wait for RDM to signal it's ready (pipe server is listening)
        // Transfer ownership to spawn_blocking - event dropped after wait completes
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            ready_event.wait(Some(timeout_ms))?;
            info!("RDM ready event signaled successfully");
            Ok(())
        })
        .await
        .context("Task join error")?
        .context("Failed to wait for RDM ready event")?;

        trace!("RDM ready event signaled, attempting to connect to pipe");

        // Retry connection with exponential backoff
        // RDM event was signaled, but pipe server might need a moment to accept connections
        const MAX_ATTEMPTS: usize = 10;
        const INITIAL_DELAY_MS: u64 = 50;

        let mut delay_ms = INITIAL_DELAY_MS;
        let mut attempt = 0;

        let pipe_error = loop {
            match ClientOptions::new().open(&pipe_name) {
                Ok(pipe_client) => {
                    info!(pipe_name, attempt, "Successfully connected to RDM pipe");
                    return Ok(Self {
                        pipe: pipe_client,
                        pipe_name,
                        dissector: NowMessageDissector::default(),
                    });
                }
                Err(error) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(500); // Cap at 500ms
                    attempt += 1;
                    if attempt >= MAX_ATTEMPTS {
                        break error;
                    }
                }
            }
        };
        Err(pipe_error).context("RDM host pipe is unresponsive")
    }

    async fn send_message(&mut self, message: &NowMessage<'_>) -> anyhow::Result<()> {
        let size = message.size();
        let mut buffer = vec![0u8; size];

        {
            let mut cursor = WriteCursor::new(&mut buffer);
            message.encode(&mut cursor).context("Failed to encode message")?;
        }

        self.pipe
            .write_all(&buffer)
            .await
            .context("Failed to send message to RDM pipe")?;

        Ok(())
    }

    async fn read_messages(&mut self) -> anyhow::Result<Vec<NowMessage<'static>>> {
        let mut buffer = vec![0u8; PIPE_READ_BUFFER_SIZE];

        loop {
            let bytes_read = self
                .pipe
                .read(&mut buffer)
                .await
                .context("Failed to read from RDM pipe")?;

            if bytes_read == 0 {
                bail!("RDM pipe closed");
            }

            let messages = self
                .dissector
                .dissect(&buffer[..bytes_read])
                .context("Failed to dissect message from RDM")?;

            if !messages.is_empty() {
                trace!(count = messages.len(), "Read messages from RDM pipe");
                return Ok(messages);
            }

            // Need more data, continue reading
        }
    }

    fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}

fn validate_capset_response(message: NowMessage<'_>) -> anyhow::Result<NowChannelCapsetMsg> {
    match message {
        NowMessage::Channel(now_proto_pdu::NowChannelMessage::Capset(caps)) => {
            if caps.version().major != NowProtoVersion::CURRENT.major {
                bail!(
                    "Incompatible protocol version: expected major version {}, got {}.{}",
                    NowProtoVersion::CURRENT.major,
                    caps.version().major,
                    caps.version().minor
                );
            }

            Ok(caps)
        }
        _ => {
            bail!("Expected capset message, got: {:?}", message);
        }
    }
}

/// Perform NOW protocol negotiation with RDM
///
/// Sends the agent's proposed capabilities to RDM and receives RDM's negotiated
/// capabilities for the connection (a final set that may be a downgraded subset
/// of the agent's proposal and that both sides will use).
/// This establishes the protocol version and capabilities for the connection.
async fn negotiate_with_rdm(
    pipe: &mut RdmPipeConnection,
    agent_caps: &NowChannelCapsetMsg,
) -> anyhow::Result<NowChannelCapsetMsg> {
    info!(pipe_name = %pipe.pipe_name(), "Starting NOW protocol negotiation with RDM");

    let caps_msg: NowMessage<'_> = agent_caps.clone().into();
    pipe.send_message(&caps_msg)
        .await
        .context("Failed to send capabilities to RDM")?;

    info!("Sent agent capabilities to RDM, waiting for response");

    let messages = pipe
        .read_messages()
        .await
        .context("Failed to read RDM capabilities response")?;

    let rdm_caps_msg = messages
        .into_iter()
        .next()
        .context("No capset response received from RDM")?;

    let rdm_caps = validate_capset_response(rdm_caps_msg).context("Invalid capset response from RDM")?;

    info!(
        rdm_version = ?rdm_caps.version(),
        "Negotiation successful with RDM"
    );

    Ok(rdm_caps)
}

/// Bidirectional message passthrough between RDM pipe and DVC channel
/// for RDM messages.
///
/// Handles both directions:
/// - RDM→DVC: Reads from RDM pipe, forwards to NowAgent DVC channel
/// - DVC→RDM: Receives from NowAgent DVC channel, writes to RDM pipe.
///
/// Uses tokio::select! to multiplex between reading from pipe and receiving from channel.
/// Intercepts AppNotify messages to track connection state.
async fn run_rdm_to_dvc_passthrough(
    mut pipe: RdmPipeConnection,
    mut dvc_rx: tokio::sync::mpsc::Receiver<NowMessage<'static>>,
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
    connection_state: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    let pipe_name = pipe.pipe_name().to_owned();
    info!(pipe_name, "Starting bidirectional RDM pipe passthrough");

    loop {
        tokio::select! {
            // Read messages from RDM pipe and forward to DVC
            result = pipe.read_messages() => {
                let messages = match result {
                    Ok(msgs) => msgs,
                    Err(error) => {
                        error!(%error, pipe_name, "Failed to read message from RDM");
                        connection_state.store(RdmConnectionState::Disconnected.as_u8(), Ordering::Release);
                        break;
                    }
                };
                // Process all messages from this read
                for message in messages {
                    info!(pipe_name, "Received message from RDM: {:?}", message);

                    // Intercept AppNotify to track state
                    if let NowMessage::Rdm(NowRdmMessage::AppNotify(ref notify)) = message {
                        let app_state = notify.app_state();
                        info!(?app_state, "Intercepted AppNotify from RDM");

                        let new_state = match app_state {
                            NowRdmAppState::READY => Some(RdmConnectionState::Ready),
                            NowRdmAppState::FAILED => Some(RdmConnectionState::Disconnected),
                            _ => None,
                        };

                        if let Some(new_state) = new_state {
                            // Update state atomically
                            connection_state.store(new_state.as_u8(), Ordering::Release);
                            info!(pipe_name, ?new_state, "Updated RDM connection state");
                        }
                    }

                    // Forward message to DVC
                    if let Err(error) = dvc_tx.send(message).await {
                        error!(%error, pipe_name, "Failed to send message to DVC");
                        return Ok(());
                    }
                }
            }

            // Receive messages from channel and write to RDM pipe
            message_opt = dvc_rx.recv() => {
                match message_opt {
                    Some(message) => {
                        info!(pipe_name, "Forwarding message to RDM: {:?}", message);
                        if let Err(error) = pipe.send_message(&message).await {
                            error!(%error, pipe_name, "Failed to send message to RDM pipe");
                            connection_state.store(RdmConnectionState::Disconnected.as_u8(), Ordering::Release);
                            break;
                        }
                    }
                    None => {
                        info!(pipe_name, "DVC receiver channel closed; terminating RDM passthrough task");
                        break;
                    }
                }
            }
        }
    }

    info!(pipe_name, "Bidirectional RDM passthrough task terminated");

    Ok(())
}

/// RDM connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RdmConnectionState {
    /// Not connected to RDM
    Disconnected = 0,
    /// Connection in progress
    Connecting = 1,
    /// Connected and ready (received READY notification from RDM)
    Ready = 2,
}

impl RdmConnectionState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Disconnected,
            1 => Self::Connecting,
            2 => Self::Ready,
            _ => Self::Disconnected, // Default to disconnected for invalid values
        }
    }

    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Manages DVC <-> RDM pipe communication/state and message routing.
pub struct RdmMessageProcessor {
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
    rdm_tx: Option<tokio::sync::mpsc::Sender<NowMessage<'static>>>,
    connection_state: Arc<AtomicU8>,
}

impl RdmMessageProcessor {
    /// Create a new RDM handler
    pub fn new(dvc_tx: WinapiSignaledSender<NowMessage<'static>>) -> Self {
        Self {
            dvc_tx,
            rdm_tx: None,
            connection_state: Arc::new(AtomicU8::new(RdmConnectionState::Disconnected.as_u8())),
        }
    }

    /// Process RDM capabilities message
    ///
    /// This is the only RDM message handled by the agent and not passed to DVC.
    /// It checks if RDM is installed and returns version information along with
    /// timestamp synchronization.
    pub async fn process_capabilities(
        &self,
        rdm_caps_msg: NowRdmCapabilitiesMsg<'_>,
    ) -> anyhow::Result<NowMessage<'static>> {
        let client_timestamp = rdm_caps_msg.timestamp();
        let server_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Failed to get current timestamp")?
            .as_secs();

        info!(
            client_timestamp,
            server_timestamp, "Processing RDM capabilities message"
        );

        let (is_rdm_available, rdm_version) = {
            match get_installed_product_version(RDM_UPDATE_CODE, ProductVersionEncoding::Rdm) {
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

    /// Process RDM app start message:
    /// - If RDM is already connected and ready, send immediate READY notification.
    /// - If RDM connection is in progress, ignore duplicate app start.
    /// - If RDM is not started, launch RDM and start connection process.
    ///     - Spawns a background task to handle the connection process.
    pub fn process_app_start(&mut self, rdm_app_start_msg: NowRdmAppStartMsg, agent_caps: NowChannelCapsetMsg) {
        let mut current_state = RdmConnectionState::from_u8(self.connection_state.load(Ordering::Acquire));

        // Ensure that the transition from Disconnected to Connecting is done atomically
        // so that only one task is spawned to handle app_start.
        loop {
            match current_state {
                RdmConnectionState::Ready => {
                    info!("RDM already connected and ready, sending immediate READY notification");
                    let dvc_tx = self.dvc_tx.clone();
                    tokio::spawn(async move {
                        if let Err(error) =
                            send_rdm_app_notify(&dvc_tx, NowRdmAppState::READY, NowRdmReason::NOT_SPECIFIED).await
                        {
                            error!(%error, "Failed to send immediate RDM READY notification");
                        }
                    });
                    return;
                }
                RdmConnectionState::Connecting => {
                    info!("RDM connection already in progress, ignoring duplicate app_start");
                    return;
                }
                RdmConnectionState::Disconnected => {
                    info!("Starting RDM connection process");
                    let disconnected = RdmConnectionState::Disconnected.as_u8();
                    let connecting = RdmConnectionState::Connecting.as_u8();

                    match self.connection_state.compare_exchange(
                        disconnected,
                        connecting,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // Successfully claimed responsibility for starting the connection.
                            break;
                        }
                        Err(actual) => {
                            // State changed concurrently; re-evaluate the new state.
                            current_state = RdmConnectionState::from_u8(actual);
                            continue;
                        }
                    }
                }
            }
        }

        let dvc_tx = self.dvc_tx.clone();
        let connection_state = Arc::clone(&self.connection_state);

        // Use bounded channel to prevent unbounded memory growth (capacity: 100 messages)
        let (rdm_tx, rdm_rx) = tokio::sync::mpsc::channel(100);
        self.rdm_tx = Some(rdm_tx);

        tokio::spawn(async move {
            if let Err(error) = process_app_start_impl(
                rdm_app_start_msg,
                agent_caps,
                dvc_tx,
                Arc::clone(&connection_state),
                rdm_rx,
            )
            .await
            {
                error!(%error, "RDM app start failed");
                // Ensure connection_state is reset so future app_start attempts are possible
                connection_state.store(RdmConnectionState::Disconnected.as_u8(), Ordering::Release);
            }
        });
    }

    /// Forward RDM message to RDM via pipe
    pub async fn forward_message(&mut self, message: NowRdmMessage<'static>) -> anyhow::Result<()> {
        let current_state = RdmConnectionState::from_u8(self.connection_state.load(Ordering::Acquire));

        match current_state {
            RdmConnectionState::Ready => {
                if let Some(rdm_tx) = &self.rdm_tx {
                    let now_msg: NowMessage<'static> = NowMessage::Rdm(message);
                    rdm_tx
                        .send(now_msg)
                        .await
                        .context("Failed to send message to RDM channel")?;
                    Ok(())
                } else {
                    warn!("RDM state is Ready but channel is not available");
                    bail!("RDM channel not available");
                }
            }
            RdmConnectionState::Connecting => {
                warn!("Cannot forward message: RDM connection is still in progress");
                bail!("RDM connection in progress");
            }
            RdmConnectionState::Disconnected => {
                warn!("Cannot forward message: RDM is not connected");
                bail!("RDM not connected");
            }
        }
    }
}

/// Implementation of RDM app start logic (runs in background task)
async fn process_app_start_impl(
    rdm_app_start_msg: NowRdmAppStartMsg,
    agent_caps: NowChannelCapsetMsg,
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
    connection_state: Arc<AtomicU8>,
    rdm_rx: tokio::sync::mpsc::Receiver<NowMessage<'static>>,
) -> anyhow::Result<()> {
    info!("Processing RDM app start message");

    // Re-use already running RDM instance if available or launch new one.
    let rdm_pid = if let Some(pid) = find_rdm_pid().await {
        info!(pid, "RDM is already running, using existing instance");
        pid
    } else {
        info!("RDM is not running, launching...");
        match launch_rdm_process(&rdm_app_start_msg).await {
            Ok(process_id) => {
                info!(
                    "RDM application started successfully with PID: {} (detached)",
                    process_id
                );
                process_id
            }
            Err(error) => {
                error!(%error, "Failed to launch RDM application");
                send_rdm_app_notify(&dvc_tx, NowRdmAppState::FAILED, NowRdmReason::STARTUP_FAILURE).await?;
                return Err(error);
            }
        }
    };

    // Update PID hint for future connections.
    set_rdm_pid_hint(rdm_pid);

    // Create or open the ready event that RDM will signal.
    let ready_event = create_or_open_rdm_ready_event(rdm_pid).context("Failed to create/open RDM ready event")?;

    // Connect to RDM pipe with timeout.
    let mut pipe = match RdmPipeConnection::connect(rdm_app_start_msg.timeout(), ready_event, rdm_pid).await {
        Ok(pipe) => {
            info!("Connected to RDM pipe successfully");
            pipe
        }
        Err(error) => {
            error!(%error, "Failed to connect to RDM pipe");
            send_rdm_app_notify(&dvc_tx, NowRdmAppState::FAILED, NowRdmReason::LAUNCH_TIMEOUT).await?;
            return Err(error).context("Failed to connect to RDM pipe");
        }
    };

    // Perform negotiation
    match negotiate_with_rdm(&mut pipe, &agent_caps).await {
        Ok(_rdm_caps) => {
            info!("Negotiation with RDM successful");

            // Passthrough original app start message to RDM.
            let app_start_msg: NowMessage<'_> = NowMessage::Rdm(NowRdmMessage::AppStart(rdm_app_start_msg));
            pipe.send_message(&app_start_msg)
                .await
                .context("Failed to send app start message to RDM")?;

            trace!("Sent app start message to RDM");

            // Start passthrough task with pipe and channel receiver
            // RDM will send READY notification after negotiation completes
            start_passthrough_task(pipe, rdm_rx, dvc_tx, connection_state).await?;

            Ok(())
        }
        Err(error) => {
            error!(%error, "Failed to negotiate with RDM");
            send_rdm_app_notify(&dvc_tx, NowRdmAppState::FAILED, NowRdmReason::STARTUP_FAILURE).await?;
            Err(error).context("Failed to negotiate with RDM")
        }
    }
}

/// Start the passthrough task to forward messages bidirectionally
async fn start_passthrough_task(
    pipe: RdmPipeConnection,
    rdm_rx: tokio::sync::mpsc::Receiver<NowMessage<'static>>,
    dvc_tx: WinapiSignaledSender<NowMessage<'static>>,
    connection_state: Arc<AtomicU8>,
) -> anyhow::Result<()> {
    tokio::spawn(async move {
        if let Err(error) = run_rdm_to_dvc_passthrough(pipe, rdm_rx, dvc_tx, connection_state).await {
            error!(%error, "RDM passthrough task failed");
        }
    });

    Ok(())
}

/// Launch RDM process with specified options (detached)
async fn launch_rdm_process(rdm_app_start_msg: &NowRdmAppStartMsg) -> anyhow::Result<u32> {
    let rdm_exe_path = get_rdm_executable_path().context("RDM is not installed")?;

    let install_location = rdm_exe_path
        .parent()
        .context("Failed to get RDM installation directory")?
        .to_string_lossy()
        .to_string();

    // Convert command line to wide string
    let current_dir = WideString::from(&install_location);

    info!(
        exe_path = %rdm_exe_path.display(),
        fullscreen = rdm_app_start_msg.is_fullscreen(),
        maximized = rdm_app_start_msg.is_maximized(),
        jump_mode = rdm_app_start_msg.is_jump_mode(),
        "Starting RDM application with CreateProcess"
    );

    // Create process using CreateProcessW
    #[allow(clippy::cast_possible_truncation)] // STARTUPINFOW.cb is u32 by design
    let startup_info = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        #[allow(clippy::cast_possible_truncation)] // wShowWindow is u16 by design
        wShowWindow: if rdm_app_start_msg.is_maximized() {
            SW_MAXIMIZE.0 as u16
        } else {
            SW_RESTORE.0 as u16
        },
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
            None,
            Some(PWSTR(command_line_buffer.as_mut_ptr())),
            None,
            None,
            false,
            NORMAL_PRIORITY_CLASS | CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE,
            None,
            PCWSTR(current_dir.as_pcwstr().as_ptr()),
            &startup_info,
            &mut process_info,
        )
    };

    if success.is_err() || process_info.hProcess.is_invalid() {
        return Err(win_api_wrappers::Error::last_error().into());
    }

    // Close handles as we're launching detached (no need to wait)
    // SAFETY: It is safe to create owned handle wrapper from created process thread handle
    let _ = unsafe { Handle::new(process_info.hThread, true) };
    // SAFETY: It is safe to create owned handle wrapper from created process handle
    let _ = unsafe { Handle::new(process_info.hProcess, true) };

    Ok(process_info.dwProcessId)
}

fn rdm_pid_hint_file_path() -> anyhow::Result<tempfile::NamedTempFile> {
    let file = tempfile::Builder::new()
        .prefix("devolutions-session-rdm")
        .suffix(".pid")
        .rand_bytes(0)
        // Keep file after drop, while still removing on reboot on Windows.
        .disable_cleanup(true)
        .make(|path| std::fs::File::create(path))
        .context("Failed to create temporary file for RDM PID hint")?;

    info!(
        path = %file.path().display(),
        "Using temporary file for RDM PID hint"
    );

    Ok(file)
}

fn try_get_read_rdm_pid_hint() -> anyhow::Result<u32> {
    let mut file = rdm_pid_hint_file_path().context("Failed to get RDM PID hint file path")?;

    let mut text = String::new();
    file.read_to_string(&mut text)
        .context("Failed to read RDM PID hint from temporary file")?;

    text.trim()
        .parse::<u32>()
        .context("Failed to parse RDM PID hint as u32")
}

fn get_rdm_pid_hint() -> Option<u32> {
    match try_get_read_rdm_pid_hint() {
        Ok(pid) => Some(pid),
        Err(error) => {
            warn!(%error, "Failed to get RDM PID hint");
            None
        }
    }
}

fn try_set_rdm_pid_hint(pid: u32) -> anyhow::Result<()> {
    let mut file = rdm_pid_hint_file_path().context("Failed to get RDM PID hint file path")?;

    file.write_all(pid.to_string().as_bytes())
        .context("Failed to write RDM PID hint to temporary file")
}

fn set_rdm_pid_hint(pid: u32) {
    if let Err(error) = try_set_rdm_pid_hint(pid) {
        warn!(%error, "Failed to set RDM PID hint");
    }
}

/// Get RDM process pid:
/// - First tries to read PID hint from temporary file to use the same instance each time
///   client connects (devolutions-session.exe is restarted each time user connects). This improves
///   user experience by reusing the same RDM instance as much as possible instead of using random
///   running instance.
/// - If PID hint is not available or invalid, enumerates processes to find first matching RDM
///   executable PID.
async fn find_rdm_pid() -> Option<u32> {
    let pid_hint = get_rdm_pid_hint();

    let rdm_exe_path = get_rdm_executable_path()?;

    let process_iterator = match ProcessEntry32Iterator::new() {
        Ok(iter) => iter,
        Err(error) => {
            warn!(%error, "Failed to create process iterator for RDM detection");
            return None;
        }
    };

    let mut found_pid: Option<u32> = None;

    for process_entry in process_iterator {
        let pid = process_entry.process_id();

        let process = match Process::get_by_pid(pid, PROCESS_QUERY_INFORMATION) {
            Ok(proc) => proc,
            Err(_) => continue,
        };

        let exe_path = match process.exe_path() {
            Ok(path) => path,
            Err(_) => continue,
        };

        // Compare the full paths case-insensitively
        if exe_path
            .to_string_lossy()
            .eq_ignore_ascii_case(&rdm_exe_path.to_string_lossy())
        {
            match pid_hint {
                None => {
                    found_pid = Some(pid);
                    break;
                }
                Some(hint) if pid == hint => {
                    info!(
                        rdm_path = %rdm_exe_path.display(),
                        pid,
                        "Found RDM instance matching PID hint"
                    );

                    found_pid = Some(pid);
                    break;
                }
                Some(_) => {
                    if found_pid.is_none() {
                        found_pid = Some(pid);
                    }
                }
            }
        }
    }

    if let Some(pid) = found_pid {
        info!(
            rdm_path = %rdm_exe_path.display(),
            pid,
            "Found RDM instance"
        );
    }

    found_pid
}

/// Get the RDM executable path from installation location
fn get_rdm_executable_path() -> Option<std::path::PathBuf> {
    match get_install_location(RDM_UPDATE_CODE) {
        Ok(Some(install_location)) => {
            let rdm_exe_path = std::path::Path::new(&install_location).join("RemoteDesktopManager.exe");
            Some(rdm_exe_path)
        }
        Ok(None) => None,
        Err(_) => None,
    }
}

/// Send RDM app notification message
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
