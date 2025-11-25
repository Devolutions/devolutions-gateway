//! Window monitoring functionality for tracking active window changes.
//!
//! This module provides functionality to monitor the currently focused/active window
//! on the system, capturing information such as window title, process executable path,
//! and timestamp (UTC).
//!
//! Uses Windows Event Hooks (SetWinEventHook) to receive EVENT_SYSTEM_FOREGROUND
//! notifications whenever the foreground window changes. Additionally supports optional
//! polling for detecting title changes within the same window.
//!
//! The module provides a channel-based interface for integrating with other systems
//! (e.g., DVC protocol for transmitting window change events).

use std::cell::RefCell;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context as _, bail};
use now_proto_pdu::NowSessionWindowRecEventMsg;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use win_api_wrappers::process::Process;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, EVENT_SYSTEM_FOREGROUND, GetForegroundWindow, GetMessageW, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, MSG, PostThreadMessageW, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WINEVENT_OUTOFCONTEXT,
    WM_GETTEXT, WM_QUIT,
};

use crate::dvc::process::ServerChannelEvent;

/// Minimum allowed polling interval in milliseconds.
const MIN_POLL_INTERVAL_MS: u64 = 100;

/// Default polling interval in milliseconds.
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;

/// Default timeout for SendMessageTimeoutW in milliseconds.
const DEFAULT_SEND_MESSAGE_TIMEOUT_MS: u32 = 1000;

/// Size of the channel buffer for window snapshots.
const SNAPSHOT_CHANNEL_SIZE: usize = 100;

/// Configuration for window monitoring.
pub struct WindowMonitorConfig {
    /// Channel to send window change events to the main task.
    pub event_tx: mpsc::Sender<ServerChannelEvent>,
    /// Interval for polling title changes (in milliseconds).
    /// Minimum value is 100ms. Values below this will be clamped to the minimum with a warning.
    pub poll_interval_ms: NonZeroU64,
    pub track_title_changes: bool,
    pub shutdown: tokio::sync::oneshot::Receiver<()>,
}

impl WindowMonitorConfig {
    /// Creates a new configuration with the given event sender and shutdown receiver.
    pub fn new(
        event_tx: mpsc::Sender<ServerChannelEvent>,
        track_title_changes: bool,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Self {
        Self {
            event_tx,
            poll_interval_ms: NonZeroU64::new(DEFAULT_POLL_INTERVAL_MS).expect("default poll interval is non-zero"),
            track_title_changes,
            shutdown,
        }
    }

    /// Sets the polling interval in milliseconds.
    ///
    /// Values below the minimum (100ms) will be clamped to the minimum with a warning.
    #[must_use]
    pub fn with_poll_interval_ms(mut self, milliseconds: u64) -> Self {
        if milliseconds < MIN_POLL_INTERVAL_MS {
            tracing::warn!(
                requested_ms = milliseconds,
                min_ms = MIN_POLL_INTERVAL_MS,
                "Requested poll interval is below minimum, clamping to minimum value"
            );
            self.poll_interval_ms = NonZeroU64::new(MIN_POLL_INTERVAL_MS).expect("min poll interval is non-zero");
        } else {
            self.poll_interval_ms = NonZeroU64::new(milliseconds).expect("validated milliseconds is non-zero");
        }
        self
    }
}

/// Internal window information for tracking changes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowSnapshot {
    process_id: u32,
    title: String,
    exe_path: PathBuf,
}

/// Gets the title of a window using multiple strategies.
///
/// First tries the standard `GetWindowTextW` API, then falls back to
/// `SendMessageTimeoutW` with `WM_GETTEXT` for Windows 11 UWP/WinUI apps.
fn get_window_title(hwnd: HWND) -> anyhow::Result<String> {
    if hwnd.is_invalid() {
        bail!("invalid window handle");
    }

    // Try GetWindowTextW first (standard approach).
    // Returns 0 if the window handle is invalid or the window has no title.

    // SAFETY: FFI call with no outstanding preconditions.
    let title_length = unsafe { GetWindowTextLengthW(hwnd) };

    if title_length > 0 {
        // Allocate buffer for window title (including null terminator).
        #[expect(clippy::cast_sign_loss, reason = "title_length is positive")]
        let buffer_size = (title_length + 1) as usize;
        let mut title_buffer: Vec<u16> = vec![0; buffer_size];

        // SAFETY: Title buffer is valid and large enough to hold the title.
        let chars_copied = unsafe { GetWindowTextW(hwnd, &mut title_buffer) };

        if chars_copied > 0 {
            // Convert UTF-16 to String, removing null terminator.
            #[expect(clippy::cast_sign_loss, reason = "chars_copied is positive")]
            let title = String::from_utf16_lossy(&title_buffer[..chars_copied as usize]);

            if !title.is_empty() {
                return Ok(title);
            }
        }
    }

    // Fallback: Use SendMessageTimeoutW with WM_GETTEXT for Windows 11 apps.
    // This works better for modern UWP/WinUI apps like File Explorer.
    const MAX_TITLE_LENGTH: usize = 512;
    let mut title_buffer: Vec<u16> = vec![0; MAX_TITLE_LENGTH];
    let mut result: usize = 0;

    // SAFETY: lParam is valid pointer in heap with sufficient size defined by wParam.
    let send_result = unsafe {
        SendMessageTimeoutW(
            hwnd,
            WM_GETTEXT,
            WPARAM(MAX_TITLE_LENGTH),
            LPARAM(title_buffer.as_mut_ptr() as isize),
            SMTO_ABORTIFHUNG,
            DEFAULT_SEND_MESSAGE_TIMEOUT_MS,
            Some(&mut result),
        )
    };

    if send_result.0 != 0 && result > 0 {
        // Convert UTF-16 to String, removing null terminator.
        let title = String::from_utf16_lossy(&title_buffer[..result]);
        return Ok(title);
    }

    // No title available.
    Ok(String::new())
}

/// Gets the process ID for a given window.
fn get_window_process_id(hwnd: HWND) -> anyhow::Result<u32> {
    if hwnd.is_invalid() {
        bail!("invalid window handle");
    }

    let mut process_id: u32 = 0;

    // SAFETY: FFI call with no outstanding preconditions.
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut process_id));
    }

    if process_id == 0 {
        bail!("failed to get process ID for window");
    }

    Ok(process_id)
}

/// Captures a snapshot of window information for a given window handle.
fn capture_window_snapshot(hwnd: HWND) -> anyhow::Result<WindowSnapshot> {
    if hwnd.is_invalid() {
        bail!("invalid window handle");
    }

    let title = get_window_title(hwnd).context("failed to get window title")?;
    let process_id = get_window_process_id(hwnd).context("failed to get process ID")?;

    // Open process to query information.
    // This may fail for protected/system processes, which is expected.
    let process = Process::get_by_pid(process_id, PROCESS_QUERY_INFORMATION)
        .context("failed to open process (may be protected/system process)")?;

    let exe_path = process.exe_path().context("failed to get executable path")?;

    Ok(WindowSnapshot {
        process_id,
        title,
        exe_path,
    })
}

/// Captures information about the currently active window.
fn capture_foreground_window() -> anyhow::Result<WindowSnapshot> {
    // SAFETY: FFI call with no outstanding preconditions.
    let foreground_window = unsafe { GetForegroundWindow() };

    if foreground_window.is_invalid() {
        bail!("no foreground window");
    }

    capture_window_snapshot(foreground_window)
}

/// Gets the current timestamp as seconds since Unix epoch.
fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Thread-local context for the event hook callback.
///
/// Windows event hook callbacks must be plain C functions, so we use thread-local
/// storage to communicate with the async runtime. This is safe because WINEVENT_OUTOFCONTEXT
/// ensures the callback runs on the same thread that installed the hook.
struct HookContext {
    sender: mpsc::Sender<WindowSnapshot>,
}

std::thread_local! {
    /// Thread-local storage for hook context.
    ///
    /// This is only accessed from the hook thread.
    static HOOK_CONTEXT: RefCell<Option<HookContext>> = const { RefCell::new(None) };
}

/// Win event callback function called by Windows when foreground window changes.
///
/// This function is called by Windows as a callback and must match the expected
/// extern "system" signature. With WINEVENT_OUTOFCONTEXT, the callback runs on the
/// same thread that installed the hook, making thread-local access safe.
extern "system" fn win_event_proc(
    _h_win_event_hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _id_event_thread: u32,
    _dwms_event_time: u32,
) {
    // Access thread-local context.
    HOOK_CONTEXT.with(|context| {
        let context_ref = context.borrow();
        let Some(ctx) = context_ref.as_ref() else {
            return;
        };

        // Capture window snapshot and send to async task.
        match capture_window_snapshot(hwnd) {
            Ok(snapshot) => {
                // Ignore errors if receiver has been dropped (shutdown in progress).
                let _ = ctx.sender.blocking_send(snapshot);
            }
            Err(error) => {
                debug!(%error, "Failed to capture window snapshot in event callback");
            }
        }
    });
}

/// RAII guard for an active window event hook.
///
/// Ensures the hook is properly unhooked and thread-local context is cleaned up
/// when dropped, preventing resource leaks even in case of panics or early returns.
struct ActiveWindowHook {
    hook: HWINEVENTHOOK,
}

impl ActiveWindowHook {
    /// Creates a new window event hook for monitoring foreground window changes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A hook is already active on this thread (context is not None)
    /// - Windows fails to install the event hook
    fn new(sender: mpsc::Sender<WindowSnapshot>) -> anyhow::Result<Self> {
        // Check if hook is already active on this thread.
        let is_active = HOOK_CONTEXT.with(|context| context.borrow().is_some());

        if is_active {
            bail!("window hook is already active on this thread");
        }

        // Initialize thread-local context for the callback.
        HOOK_CONTEXT.with(|context| {
            *context.borrow_mut() = Some(HookContext { sender });
        });

        // SAFETY: win_event_proc is a valid function pointer matching the expected signature.
        // WINEVENT_OUTOFCONTEXT should be specified to ensure the callback runs on this thread.
        // (win_event_proc uses thread-local storage for context).
        let hook = unsafe {
            SetWinEventHook(
                EVENT_SYSTEM_FOREGROUND, // Iterested only in foreground window changes
                EVENT_SYSTEM_FOREGROUND,
                None,                 // No module handle (not in a DLL)
                Some(win_event_proc), // Hook callback function
                0,
                0,
                WINEVENT_OUTOFCONTEXT, // Callback runs on this thread
            )
        };

        if hook.is_invalid() {
            // Clean up context on failure.
            HOOK_CONTEXT.with(|context| {
                *context.borrow_mut() = None;
            });
            bail!("failed to install Windows event hook");
        }

        info!("Windows event hook installed successfully");

        Ok(Self { hook })
    }
}

impl Drop for ActiveWindowHook {
    fn drop(&mut self) {
        info!("Unhooking Windows event hook");

        // SAFETY: self.hook validity ensured by constructor.
        unsafe {
            let _ = UnhookWinEvent(self.hook);
        }

        // Clear thread-local context.
        HOOK_CONTEXT.with(|context| {
            *context.borrow_mut() = None;
        });
    }
}

/// Helper function to send window recording events through the channel.
///
/// Returns `true` if the message was sent successfully, `false` if the channel is closed.
async fn send_window_event(
    event_tx: &mpsc::Sender<ServerChannelEvent>,
    message: NowSessionWindowRecEventMsg<'static>,
) -> bool {
    event_tx
        .send(ServerChannelEvent::WindowRecordingEvent { message })
        .await
        .is_ok()
}

/// Runs the window monitoring loop.
///
/// This function spawns a dedicated thread for the Windows message loop required
/// by event hooks, and processes window change events asynchronously using the
/// provided callback.
///
/// The monitoring loop continues until the shutdown signal is received. To stop
/// monitoring, send a value through the shutdown sender or drop the sender.
///
/// # Arguments
///
/// * `config` - Configuration including the event channel, polling interval, and shutdown signal.
///
/// # Errors
///
/// Returns an error if the hook thread fails to initialize.
pub async fn run_window_monitor(config: WindowMonitorConfig) -> anyhow::Result<()> {
    info!("Starting window monitor");

    // Create channel for receiving window events from the hook callback.
    let (tx, mut rx) = mpsc::channel(SNAPSHOT_CHANNEL_SIZE);

    // Create oneshot channel to receive hook thread ID for shutdown.
    let (thread_id_tx, thread_id_rx) = tokio::sync::oneshot::channel();

    // Spawn dedicated thread for Windows message loop.
    // Windows hooks require a message loop to function properly.
    let hook_thread = std::thread::spawn(move || {
        // SAFETY: GetCurrentThreadId has no preconditions and always returns a valid thread ID.
        let hook_thread_id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };

        // Send thread ID back to main task for shutdown coordination.
        let _ = thread_id_tx.send(hook_thread_id);

        // Install event hook with RAII guard for automatic cleanup.
        let _hook_guard = match ActiveWindowHook::new(tx) {
            Ok(guard) => guard,
            Err(error) => {
                error!(%error, "Failed to install Windows event hook");
                return hook_thread_id;
            }
        };

        // Run message loop to keep hook active.
        // The hook guard will automatically unhook when this function returns.
        let mut msg = MSG::default();

        // SAFETY: MSG structure is in valid stack memory and initialized to zero, therefore
        // GetMessageW is safe to call.
        while let Some(result) = std::num::NonZero::new(unsafe { GetMessageW(&mut msg, None, 0, 0) }.0) {
            // GetMessageW returns -1 on error, 0 when WM_QUIT is received, or non-zero for messages.
            if result.get() == -1 {
                error!("GetMessageW failed in hook thread");
                break;
            }

            // SAFETY: msg is a valid MSG structure obtained from GetMessageW.
            unsafe {
                DispatchMessageW(&msg);
            }
        }

        // Hook guard is automatically dropped here, cleaning up the hook and context.
        hook_thread_id
    });

    // Wait for hook thread to send its thread ID.
    let hook_thread_id = match thread_id_rx.await {
        Ok(id) => id,
        Err(_) => {
            anyhow::bail!("hook thread panicked or exited unexpectedly during initialization");
        }
    };

    // Track last known window state to detect changes.
    let mut last_snapshot: Option<WindowSnapshot> = None;

    // Capture and notify about initial foreground window.
    match capture_foreground_window() {
        Ok(snapshot) => {
            let timestamp = get_current_timestamp();

            debug!(
                process_id = snapshot.process_id,
                title = %snapshot.title,
                exe_path = %snapshot.exe_path.display(),
                "Initial active window"
            );

            // Send initial window event.
            match NowSessionWindowRecEventMsg::active_window(
                timestamp,
                snapshot.process_id,
                snapshot.title.clone(),
                snapshot.exe_path.to_string_lossy().to_string(),
            ) {
                Ok(message) => {
                    if !send_window_event(&config.event_tx, message).await {
                        // Channel closed, stop monitoring.
                        return Ok(());
                    }
                    last_snapshot = Some(snapshot);
                }
                Err(error) => {
                    error!(%error, "Failed to create window recording message");
                }
            }
        }
        Err(error) => {
            debug!(%error, "No active window");

            let timestamp = get_current_timestamp();

            // Send "no active window" event.
            let message = NowSessionWindowRecEventMsg::no_active_window(timestamp);
            if !send_window_event(&config.event_tx, message).await {
                // Channel closed, stop monitoring.
                return Ok(());
            }
        }
    }

    // Set up polling interval.
    let mut poll_interval = tokio::time::interval(std::time::Duration::from_millis(config.poll_interval_ms.get()));

    let mut shutdown = config.shutdown;

    // Process window events.
    loop {
        tokio::select! {
            // Handle shutdown signal.
            _ = &mut shutdown => {
                info!("Window monitor received shutdown signal");
                break;
            }

            // Handle window focus change events from hook.
            snapshot = rx.recv() => {
                let Some(snapshot) = snapshot else {
                    break;
                };

                // Check if this is actually a change.
                if last_snapshot.as_ref() != Some(&snapshot) {
                    let timestamp = get_current_timestamp();

                    debug!(
                        process_id = snapshot.process_id,
                        title = %snapshot.title,
                        exe_path = %snapshot.exe_path.display(),
                        "Active window changed"
                    );

                    // Send window change event.
                    match NowSessionWindowRecEventMsg::active_window(
                        timestamp,
                        snapshot.process_id,
                        snapshot.title.clone(),
                        snapshot.exe_path.to_string_lossy().to_string(),
                    ) {
                        Ok(message) => {
                            if !send_window_event(&config.event_tx, message).await {
                                // Channel closed, stop monitoring.
                                break;
                            }
                            last_snapshot = Some(snapshot);
                        }
                        Err(error) => {
                            error!(%error, "Failed to create window recording message");
                        }
                    }
                }
            }

            // Poll for title changes on the current foreground window.
            _ = poll_interval.tick() => {
                match capture_foreground_window() {
                    Ok(snapshot) => {
                        // Check if title or window changed.
                        if last_snapshot.as_ref() != Some(&snapshot) {
                            let timestamp = get_current_timestamp();

                            // Determine if only the title changed for the same process.
                            let is_title_change = last_snapshot.as_ref()
                                .map(|s| s.process_id == snapshot.process_id && s.exe_path == snapshot.exe_path)
                                .unwrap_or(false);

                            // Skip title changes if tracking is disabled.
                            if is_title_change && !config.track_title_changes {
                                // Only update process_id and exe_path, keep the previous title
                                // to avoid missing process/exe_path changes.
                                let prev_title = last_snapshot
                                    .as_ref()
                                    .map_or_else(String::new, |s| s.title.clone());
                                last_snapshot = Some(WindowSnapshot {
                                    process_id: snapshot.process_id,
                                    exe_path: snapshot.exe_path.clone(),
                                    title: prev_title,
                                });
                            } else {
                                let message_result = if is_title_change {
                                    debug!(
                                        process_id = snapshot.process_id,
                                        title = %snapshot.title,
                                        exe_path = %snapshot.exe_path.display(),
                                        "Active window title changed"
                                    );
                                    NowSessionWindowRecEventMsg::title_changed(timestamp, snapshot.title.clone())
                                } else {
                                    debug!(
                                        process_id = snapshot.process_id,
                                        title = %snapshot.title,
                                        exe_path = %snapshot.exe_path.display(),
                                        "Active window changed (detected via poll)"
                                    );
                                    NowSessionWindowRecEventMsg::active_window(
                                        timestamp,
                                        snapshot.process_id,
                                        snapshot.title.clone(),
                                        snapshot.exe_path.to_string_lossy().to_string(),
                                    )
                                };

                                // Send window change event.
                                match message_result {
                                    Ok(message) => {
                                        if !send_window_event(&config.event_tx, message).await {
                                            // Channel closed, stop monitoring.
                                            break;
                                        }
                                        last_snapshot = Some(snapshot);
                                    }
                                    Err(error) => {
                                        error!(%error, "Failed to create window recording message");
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        debug!(%error, "No foreground window");

                        // If we previously had an active window, send "no active window" event.
                        if last_snapshot.is_some() {
                            let timestamp = get_current_timestamp();

                            let message = NowSessionWindowRecEventMsg::no_active_window(timestamp);
                            if !send_window_event(&config.event_tx, message).await {
                                // Channel closed, stop monitoring.
                                break;
                            }
                            last_snapshot = None;
                        }
                    }
                }
            }
        }
    }

    info!("Window monitor shutting down");

    // Signal hook thread to stop by posting WM_QUIT message.

    // SAFETY: FFI call with no outstanding preconditions.
    unsafe {
        let _ = PostThreadMessageW(hook_thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
    }

    if tokio::task::spawn_blocking(move || hook_thread.join()).await.is_err() {
        error!("Hook thread panicked during shutdown");
    }

    Ok(())
}
