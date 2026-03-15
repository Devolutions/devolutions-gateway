//! WireGuard-based agent tunneling
//!
//! This module implements WireGuard tunneling for agent-based connections,
//! allowing Gateway to route sessions through agents deployed in private networks.

pub mod listener;
pub mod peer;
pub mod stream;

pub use listener::{AgentInfo, AgentStatus, WireGuardHandle, WireGuardListener};
pub use peer::AgentPeer;
pub use stream::VirtualTcpStream;
