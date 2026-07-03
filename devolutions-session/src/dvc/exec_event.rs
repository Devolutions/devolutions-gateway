//! Session-local wrapper for events flowing to the DVC task loop.
//!
//! The process execution engine (`crate::dvc::process`) emits protocol-neutral
//! [`ProcessEvent`]s. This module wraps them together with the `session_id` the DVC task
//! keys on, and multiplexes them with window recording events onto a single channel.

use now_proto_pdu::OwnedNowSessionWindowRecEventMsg;

use crate::dvc::process::ProcessEvent;

/// Event delivered to the DVC task loop.
#[derive(Debug)]
pub enum ServerChannelEvent {
    /// A process execution event, tagged with the session it belongs to.
    Process {
        session_id: u32,
        event: ProcessEvent,
    },
    /// A window recording event produced by the window monitor.
    WindowRecordingEvent {
        message: OwnedNowSessionWindowRecEventMsg,
    },
}
