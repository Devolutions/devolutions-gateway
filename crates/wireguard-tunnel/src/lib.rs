//! WireGuard tunnel utilities for agent tunneling
//!
//! This crate provides utilities for working with WireGuard tunnels (via boringtun)
//! to transport relay protocol messages over encrypted connections.
//!
//! # Overview
//!
//! The agent tunneling system uses WireGuard as a secure transport layer:
//! 1. Relay protocol messages are wrapped in simplified IPv4 packets (protocol 253)
//! 2. IPv4 packets are encrypted using WireGuard (boringtun implementation)
//! 3. Encrypted packets are sent over UDP between gateway and agents
//!
//! # Example
//!
//! ```rust,no_run
//! use wireguard_tunnel::{ip_packet, tunn_manager};
//! use boringtun::noise::Tunn;
//! use std::net::Ipv4Addr;
//!
//! // Build an IP packet containing relay payload
//! let src_ip = Ipv4Addr::new(10, 10, 0, 2);
//! let dst_ip = Ipv4Addr::new(10, 10, 0, 1);
//! let payload = b"relay protocol message";
//!
//! let ip_packet = ip_packet::build_ip_packet(src_ip, dst_ip, payload).unwrap();
//!
//! // Extract payload from received packet
//! let extracted = ip_packet::extract_payload(&ip_packet).unwrap();
//! assert_eq!(&extracted[..], payload);
//! ```

pub mod error;
pub mod ip_packet;
pub mod tunn_manager;

// Re-export main types
// Re-export boringtun types for convenience
pub use boringtun::noise::{Tunn, TunnResult};
pub use boringtun::x25519::{PublicKey, StaticSecret};
pub use error::{Error, Result};
