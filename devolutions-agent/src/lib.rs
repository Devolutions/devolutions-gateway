// Used by devolutions-agent binary.
use ceviche as _;
use ctrlc as _;

#[macro_use]
extern crate tracing;

pub mod config;
pub mod domain_detect;
pub mod enrollment;
pub mod log;
pub mod remote_desktop;
pub mod tunnel;

#[cfg(windows)]
pub mod session_manager;

#[cfg(windows)]
pub mod updater;

pub enum CustomAgentServiceEvent {}

pub type AgentServiceEvent = ceviche::ServiceEvent<CustomAgentServiceEvent>;
