// Used by devolutions-agent binary.
use ceviche as _;
use ctrlc as _;

#[macro_use]
extern crate tracing;

use std::sync::{Arc, LazyLock};

use sysevent::SystemEventSink;

pub mod config;
pub mod domain_detect;
pub mod enrollment;
pub mod identity;
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

/// The agent's system event sink, created on first use and shared by every feature.
pub static SYSTEM_LOGGER: LazyLock<Arc<dyn SystemEventSink>> = LazyLock::new(init_system_logger);

fn init_system_logger() -> Arc<dyn SystemEventSink> {
    // UNTESTED: the agent emits system events in every build, debug builds included, unlike the Gateway.
    // Neither the Event Log nor syslog is portably observable from tests.
    // When changing this, keep the Event Log source `Devolutions Agent`, the syslog ident `devolutions-agent` with
    // facility daemon and the no-op fallback, and check that the identity key-backend event reaches the system log.
    #[cfg(windows)]
    let sink =
        sysevent_winevent::WinEvent::new("Devolutions Agent").map(|sink| Arc::new(sink) as Arc<dyn SystemEventSink>);
    #[cfg(unix)]
    let sink = sysevent_syslog::Syslog::new(
        c"devolutions-agent",
        sysevent_syslog::SyslogOptions::default()
            .log_pid(true)
            .facility(sysevent::Facility::Daemon),
    )
    .map(|sink| Arc::new(sink) as Arc<dyn SystemEventSink>);
    sink.unwrap_or_else(|_| Arc::new(sysevent::NoopSink))
}
