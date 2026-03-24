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
//!   connection. The first message is a [`ConnectMessage`] from Gateway,
//!   followed by a [`ConnectResponse`] from Agent. After a successful
//!   response, raw TCP bytes flow bidirectionally.

pub mod control;
pub mod error;
pub mod session;
pub mod version;

pub use control::ControlMessage;
pub use error::ProtoError;
pub use session::{ConnectMessage, ConnectResponse};
pub use version::{CURRENT_PROTOCOL_VERSION, MIN_SUPPORTED_VERSION, validate_protocol_version};
