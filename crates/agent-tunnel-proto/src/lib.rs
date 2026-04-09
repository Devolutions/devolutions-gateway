//! Protocol definitions for the QUIC-based agent tunnel.
//!
//! This crate defines the binary protocol exchanged between Gateway and Agent
//! over QUIC streams. All messages use length-prefixed bincode encoding and
//! carry a `protocol_version` field for forward compatibility.
//!
//! ## Stream model
//!
//! - **Control stream** (QUIC stream 0): carries [`ControlMessage`] variants
//!   (route advertisements, heartbeats).
//! - **Session streams** (QUIC streams 1..N): each stream proxies one TCP
//!   connection. The first message is a [`ConnectRequest`] from Gateway,
//!   followed by a [`ConnectResponse`] from Agent. After a successful
//!   response, raw TCP bytes flow bidirectionally.

pub mod control;
pub mod error;
pub mod session;
pub mod stream;
pub mod version;

pub use control::{ControlMessage, DomainAdvertisement, MAX_CONTROL_MESSAGE_SIZE};
pub use error::ProtoError;
pub use session::{ConnectRequest, ConnectResponse, MAX_SESSION_MESSAGE_SIZE};
pub use stream::{ControlRecvStream, ControlSendStream, ControlStream, SessionStream};
pub use version::{CURRENT_PROTOCOL_VERSION, MIN_SUPPORTED_VERSION, validate_protocol_version};

/// Current wall-clock time in milliseconds since UNIX epoch.
pub fn current_time_millis() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_millis(),
    )
    .expect("millisecond timestamp should fit in u64")
}
