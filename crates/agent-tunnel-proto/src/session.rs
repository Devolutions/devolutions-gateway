//! Session-stream message types.
//!
//! Encoding and decoding live in [`crate::session_codec`].

use uuid::Uuid;

use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded session message size (64 KiB).
pub const MAX_SESSION_MESSAGE_SIZE: u32 = 64 * 1024;

/// Request from Gateway to Agent, sent as the first message on a newly opened
/// QUIC bidirectional session stream.
///
/// Modeled as an enum (with a single variant for now) so future session-opening
/// semantics — SOCKS5, UDP, multi-target, etc. — can be added without breaking
/// the wire format: a v1 decoder sees an unknown tag and returns
/// [`crate::ProtoError::UnknownTag`] cleanly, same as `ControlMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectRequest {
    /// Open a plain TCP connection to the given target.
    ///
    /// Wire layout: `[1B tag=0x01][2B version][16B uuid][4B target_len][target bytes]`.
    Tcp {
        protocol_version: u16,
        /// Association/session ID from the Gateway.
        session_id: Uuid,
        /// Target address in `host:port` form (e.g., `"192.168.1.100:3389"`).
        target: String,
    },
}

/// Agent's response to a [`ConnectRequest`].
///
/// Wire layout:
/// - Success: `[1B tag=0x00][2B version]`
/// - Error:   `[1B tag=0x01][2B version][4B reason_len][reason bytes]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectResponse {
    Success { protocol_version: u16 },
    Error { protocol_version: u16, reason: String },
}

impl ConnectRequest {
    /// Convenience constructor for the common "connect to TCP target" case.
    pub fn tcp(session_id: Uuid, target: String) -> Self {
        Self::Tcp {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            session_id,
            target,
        }
    }

    /// Extract the protocol version from any variant.
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Tcp { protocol_version, .. } => *protocol_version,
        }
    }

    /// Extract the session ID from any variant that carries one.
    pub fn session_id(&self) -> Uuid {
        match self {
            Self::Tcp { session_id, .. } => *session_id,
        }
    }

    /// Extract the target string from any variant that carries one.
    pub fn target(&self) -> &str {
        match self {
            Self::Tcp { target, .. } => target,
        }
    }
}

impl ConnectResponse {
    pub fn success() -> Self {
        Self::Success {
            protocol_version: CURRENT_PROTOCOL_VERSION,
        }
    }

    pub fn error(reason: impl Into<String>) -> Self {
        Self::Error {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            reason: reason.into(),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Extract the protocol version from any variant.
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Success { protocol_version } | Self::Error { protocol_version, .. } => *protocol_version,
        }
    }
}
