//! Tunnel protocol for WireGuard agent tunneling
//!
//! This crate defines the relay protocol used inside WireGuard tunnels
//! to multiplex multiple TCP streams over a single encrypted connection.
//!
//! # Protocol Overview
//!
//! The relay protocol uses a simple message framing format:
//! - Each message has a 7-byte header (stream_id + msg_type + length)
//! - Payload follows the header (up to 65528 bytes)
//!
//! Message types:
//! - `CONNECT`: Request to establish a new TCP connection to a target
//! - `CONNECTED`: Confirmation that the connection was established
//! - `DATA`: Transfer data over an established stream
//! - `CLOSE`: Close a stream
//! - `ERROR`: Report an error condition
//! - `ROUTE_ADVERTISE`: Replace the peer's current routable subnets
//!
//! # Example
//!
//! ```rust
//! use tunnel_proto::{RelayMessage, RelayMsgType};
//! use bytes::{Bytes, BytesMut};
//!
//! // Create a CONNECT message
//! let msg = RelayMessage::connect(123, "tcp://192.168.1.100:3389").unwrap();
//!
//! // Encode to wire format
//! let mut buf = BytesMut::new();
//! msg.encode(&mut buf).unwrap();
//!
//! // Decode from wire format
//! let decoded = RelayMessage::decode(&buf[..]).unwrap();
//! assert_eq!(msg.stream_id, decoded.stream_id);
//! ```

pub mod error;
pub mod message;
pub mod stream_id;

// Re-export main types
// Re-export bytes types for convenience
pub use bytes::{Bytes, BytesMut};
pub use error::{Error, Result};
pub use message::{RelayMessage, RelayMsgType, RouteAdvertisement};
pub use stream_id::StreamIdAllocator;
