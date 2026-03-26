//! QUIC-based agent tunnel.
//!
//! Provides a reliable, multiplexed tunnel between the gateway and remote agents
//! using QUIC with mutual TLS authentication. Replaces the WireGuard-based POC.

pub mod cert;
pub mod enrollment_store;
pub mod listener;
pub mod registry;
pub mod stream;

pub use enrollment_store::EnrollmentTokenStore;
pub use listener::{AgentTunnelHandle, AgentTunnelListener};
pub use registry::AgentRegistry;
pub use stream::QuicStream;

#[cfg(test)]
mod integration_test;
