use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use network_scanner::ping;
use network_scanner_net::runtime::Socket2Runtime;
use thiserror::Error;
use time::UtcDateTime;
use tokio_util::sync::CancellationToken;
use tracing::warn;

mod log_queue;
mod state;

#[rustfmt::skip]
pub use crate::state::{ConfigCache, State};

#[derive(Error, Debug)]
pub enum SetConfigError {
    #[error("failed to store the new config in cache")]
    CacheStore { source: anyhow::Error },
}

pub async fn set_config(new_config: MonitorsConfig, state: Arc<State>) -> Result<(), SetConfigError> {
    // Ensure set_config is never run concurrently using a 1-permit semaphore.
    let _guard = state
        .set_config_permit
        .acquire()
        .await
        .expect("as per invariant, semaphore is never closed");

    // Update the config in the cache.
    state
        .config_cache
        .store(&new_config)
        .map_err(|source| SetConfigError::CacheStore { source })?;

    let new_config_set: HashSet<MonitorDefinition> = new_config.monitors.iter().cloned().collect();

    // Update the config in the state.
    let old_config = {
        let mut config = state.config.write().expect("poisoned");
        std::mem::replace(&mut *config, new_config)
    };

    let old_config_set: HashSet<MonitorDefinition> = old_config.monitors.into_iter().collect();

    let added = new_config_set.difference(&old_config_set).cloned();
    let deleted = old_config_set.difference(&new_config_set);

    // Spawn added monitors, and cancel deleted monitors.
    {
        let mut cancellation_tokens = state.cancellation_tokens.lock().expect("poisoned");

        for definition in added {
            let monitor_id = definition.id.clone();
            let cancellation_token = spawn_monitor(Arc::clone(&state), definition);
            cancellation_tokens.insert(monitor_id, cancellation_token);
        }

        for definition in deleted {
            match cancellation_tokens.get(&definition.id) {
                Some(token) => token.cancel(),
                None => warn!("cancellation token for monitor {} not found", definition.id),
            }

            cancellation_tokens.remove(&definition.id);
        }
    }

    return Ok(());

    fn spawn_monitor(state: Arc<State>, definition: MonitorDefinition) -> CancellationToken {
        let cancellation_token = CancellationToken::new();

        let monitor_task = {
            let cancellation_token = cancellation_token.clone();

            async move {
                let mut interval = tokio::time::interval(definition.interval);

                loop {
                    tokio::select! {
                        // The first time, it ticks immediately.
                        _ = interval.tick() => {}

                        _ = cancellation_token.cancelled() => {
                            break;
                        }
                    };

                    let monitor_result = match &definition.probe {
                        ProbeType::Ping => do_ping_monitor(&definition, Arc::clone(&state.scanner_runtime)).await,
                        ProbeType::TcpOpen => do_tcpopen_monitor(&definition).await,
                    };

                    state.log.write(monitor_result);
                }
            }
        };

        tokio::spawn(monitor_task);

        cancellation_token
    }
}

async fn do_ping_monitor(definition: &MonitorDefinition, scanner_runtime: Arc<Socket2Runtime>) -> MonitorResult {
    let request_start_time = UtcDateTime::now();
    let start_instant = Instant::now();

    let ping_result = ping::ping_addr(
        scanner_runtime,
        format!("{hostname}:0", hostname = definition.address),
        definition.timeout,
    )
    .await;

    // TODO: send more than 1 ping packet

    match ping_result {
        Ok(()) => MonitorResult {
            monitor_id: definition.id.clone(),
            request_start_time,
            response_success: true,
            response_message: None,
            response_time: Some(start_instant.elapsed()),
        },
        Err(error) => MonitorResult {
            monitor_id: definition.id.clone(),
            request_start_time,
            response_success: false,
            response_message: Some(format!("{error:#}")),
            response_time: None,
        },
    }
}

async fn do_tcpopen_monitor(definition: &MonitorDefinition) -> MonitorResult {
    MonitorResult {
        monitor_id: definition.id.clone(),
        request_start_time: UtcDateTime::now(),
        response_success: false,
        response_message: Some("not implemented".to_owned()),
        response_time: None,
    }
}

pub fn drain_log(state: Arc<State>) -> VecDeque<MonitorResult> {
    state.log.drain()
}

#[derive(Debug)]
pub struct MonitorsConfig {
    pub monitors: Vec<MonitorDefinition>,
}

impl MonitorsConfig {
    fn empty() -> MonitorsConfig {
        MonitorsConfig { monitors: Vec::new() }
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub enum ProbeType {
    Ping,
    TcpOpen,
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct MonitorDefinition {
    pub id: MonitorId,
    pub probe: ProbeType,
    pub address: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub port: Option<u16>,
}

#[derive(PartialEq, Clone, Debug)]
pub struct MonitorResult {
    pub monitor_id: MonitorId,
    pub request_start_time: UtcDateTime,
    pub response_success: bool,
    pub response_message: Option<String>,
    pub response_time: Option<Duration>,
}

#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct MonitorId(String);

impl MonitorId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for MonitorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
