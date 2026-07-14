// Used by devolutions-agent binary.
use ceviche as _;
use ctrlc as _;

#[macro_use]
extern crate tracing;

#[cfg(windows)]
pub mod broker;
#[cfg(windows)]
pub(crate) mod code_signing;
pub mod config;
pub mod domain_detect;
pub mod enrollment;
pub mod log;
pub mod psu_agent;
pub mod remote_desktop;
pub mod tunnel;
mod tunnel_helpers;

#[cfg(windows)]
pub mod session_manager;

#[cfg(windows)]
pub mod updater;

pub enum CustomAgentServiceEvent {}

pub type AgentServiceEvent = ceviche::ServiceEvent<CustomAgentServiceEvent>;
