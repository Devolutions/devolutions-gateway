//! Wire-format helpers for the protocols the network scanner speaks.
//!
//! - [`icmp_v4`] / [`icmp_v6`] — ICMP echo and friends used by ping.
//! - [`netbios`] — NetBIOS-over-UDP name service queries.
//!
//! All modules are pure byte-level: they neither own sockets nor perform
//! I/O. The companion `network-scanner` crate composes them with raw
//! sockets to send and receive packets.

pub mod icmp_v4;
pub mod icmp_v6;
pub mod netbios;
