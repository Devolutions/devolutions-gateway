use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded session message size (64 KiB).
pub const MAX_SESSION_MESSAGE_SIZE: u32 = 64 * 1024;

/// Request from Gateway to Agent to open a TCP connection to a target.
///
/// Sent as the first message on a newly opened QUIC bidirectional stream.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConnectRequest {
    pub protocol_version: u16,
    /// Association/session ID from the Gateway.
    pub session_id: Uuid,
    /// Target address in `host:port` form (e.g., `"192.168.1.100:3389"`).
    pub target: String,
}

/// Agent's response to a ConnectRequest.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum ConnectResponse {
    Success { protocol_version: u16 },
    Error { protocol_version: u16, reason: String },
}

impl ConnectRequest {
    pub fn new(session_id: Uuid, target: String) -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            session_id,
            target,
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
