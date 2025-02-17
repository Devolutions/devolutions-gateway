// Used by devolutions-agent binary.
use {ceviche as _, ctrlc as _};

#[macro_use]
extern crate tracing;

pub mod config;
pub mod log;
pub mod remote_desktop;

#[cfg(windows)]
pub mod session_manager;

#[cfg(windows)]
pub mod updater;

pub enum CustomAgentServiceEvent {}

pub type AgentServiceEvent = ceviche::ServiceEvent<CustomAgentServiceEvent>;
