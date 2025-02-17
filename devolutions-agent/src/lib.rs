// Used by devolutions-agent binary.
use {ceviche as _, ctrlc as _};

#[macro_use]
extern crate tracing;

pub mod config;
mod log;
mod remote_desktop;

#[cfg(windows)]
mod session_manager;

#[cfg(windows)]
mod updater;

pub enum CustomAgentServiceEvent {}
pub type AgentServiceEvent = ceviche::ServiceEvent<CustomAgentServiceEvent>;
