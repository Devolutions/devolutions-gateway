//! Protocol-neutral Windows process execution engine.
//!
//! This crate contains the battle-tested WinAPI process launcher extracted from
//! `devolutions-session`: `CreateProcessW`-based spawning with a hidden dedicated console,
//! overlapped-IO stdout/stderr/stdin redirection, OEM-codepage transcoding, graceful cancel
//! vs. hard abort, kill-on-drop, and detached (fire-and-forget) execution with temp-file
//! lifetime management.
//!
//! The engine is protocol-neutral: it emits [`ProcessEvent`]s and surfaces [`ExecError`]s that
//! carry only engine-level failures. Mapping those to any wire protocol is the responsibility
//! of the consumer.

#![cfg(windows)]

pub mod channel;
pub mod encoding;
pub mod env;
pub mod fs;
pub mod pipes;
pub mod process;

pub use channel::{WinapiSignaledReceiver, WinapiSignaledSender, bounded_mpsc_channel, winapi_signaled_mpsc_channel};
pub use encoding::{DataEncoding, InputEncoder, OutputDecoder};
pub use env::make_environment_block;
pub use fs::TmpFileGuard;
pub use pipes::{IoRedirectionPipes, ensure_overlapped_io_result};
pub use process::{ExecError, ProcessEvent, StdioStream, WinApiProcess, WinApiProcessBuilder};
