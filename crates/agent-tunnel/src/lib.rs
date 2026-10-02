//! QUIC-based agent tunnel (Quinn).
//!
//! Provides a reliable, multiplexed tunnel between the gateway and remote agents
//! using QUIC with mutual TLS authentication.

#[macro_use]
extern crate tracing;

pub mod authorization;
#[cfg(feature = "standard")]
pub mod cert;
#[cfg(feature = "standard")]
pub mod listener;
pub mod registry;
pub mod routing;
#[cfg(feature = "standard")]
pub mod stream;
#[cfg(feature = "fips")]
pub mod stream {
    pub use crate::unavailable::TunnelStream;
}

#[cfg(feature = "standard")]
pub use listener::{AgentTunnelHandle, AgentTunnelListener};
#[cfg(feature = "fips")]
mod unavailable;
pub use registry::AgentRegistry;
#[cfg(feature = "standard")]
pub use stream::TunnelStream;
#[cfg(feature = "fips")]
pub use unavailable::{AgentTunnelHandle, TunnelStream};
