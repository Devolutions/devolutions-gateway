//! This module contains the DVC server implementation.
//!
//! ## Architecture
//!
//! ### DVC IO thread
//! Current implementation heavily relies on WinAPI overlapped IO for DVC communication. To handle
//! two-way communication with the client, we use a separate IO thread which waits on multiple
//! handles (DVC channel read, DVC channel write (mpsc channel wrapper), stop event). This thread
//! separates WinAPI IO logic from the less platform-specific DVC logic and makes it possible to
//! mix async tokio runtime with WinAPI IO.
//!
//! ### Exec session IO redirection
//! Exec session IO redirection is running in a separate worker thread for each session. Those
//! worker threads are implemented in a similar way to DVC IO thread, running a loop with
//! overlapped IO for stdin/stdout/stderr redirection and exec session processing.
//!
//! ### Operations
//! - When a fire-and-forget operation fails (e.g. Logoff), we should log the error and continue
//!   DVC execution.
//! - Long-running operations with expected response (e.g. MessageBox) should NOT block the main
//!   DVC IO thread and potentially could be executed in their own separate async task or thread.
//!
//! ### Error handling
//! - If internal server error happens before Exec session start (e.g. MSPC channel error,
//!   WinAPI error unrelated to process start etc.), we should close channel gracefully with
//!   error reporting and send session result with error to the client. Without starting
//!   IO thread.
//! - If some error happens after session has started (e.g. during data transmission, graceful
//!   exit etc.), we should terminate the IO thread gracefully and send session result with error
//!   to the client.
//! - If session fails due to MPSC channels failure (e.g. channel closed, overflow etc.) or other
//!   internal DVC logic not related to specific DVC request, we should treat this as
//!   critical error and act on the best-effort basis to close the DVC channel gracefully and send
//!   session result with error to the client (if possible).

pub mod channel;
pub mod fs;
pub mod io;
pub mod now_message_dissector;
pub mod process;
pub mod task;
pub mod window_monitor;

mod env;
