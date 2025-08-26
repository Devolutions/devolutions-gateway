use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io, mem};

use anyhow::anyhow;
use camino::Utf8PathBuf;
use network_scanner_net::runtime::Socket2Runtime;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::UtcDateTime;
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use network_scanner::ping;

mod log_queue;
mod state;

pub use crate::state::State;

#[derive(Error, Debug)]
#[error(transparent)]
pub enum SetConfigError {
    Io(#[from] io::Error),
    Serde(#[from] serde_json::Error),
    Other(#[from] anyhow::Error),
}

pub async fn set_config(config: MonitorsConfig, state: Arc<State>) -> Result<(), SetConfigError> {
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&state.cache_path)?;

    let mut config_write = state.config.write().map_err(|_| anyhow!("config lock poisoned"))?;

    serde_json::to_writer_pretty(&file, &config)?;

    let old_config = mem::replace(&mut *config_write, config);

    let new_config_set: HashSet<MonitorDefinition> = config_write.monitors.clone().into_iter().collect();
    let old_config_set: HashSet<MonitorDefinition> = old_config.monitors.into_iter().collect();

    drop(config_write);

    let added = new_config_set.difference(&old_config_set).cloned();
    let deleted = old_config_set.difference(&new_config_set);

    let (new_cancellation_tokens, new_monitors): (
        Vec<(String, CancellationToken)>,
        Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
    ) = added
        .map(|definition| {
            let cancellation_token = CancellationToken::new();
            let cancellation_monitor = cancellation_token.clone();

            let state = Arc::clone(&state);
            let definition_id = definition.id.clone();

            let monitor = async move {
                loop {
                    let start_time = UtcDateTime::now();

                    let monitor_result = match &definition.probe {
                        ProbeType::Ping => {
                            let scanner_runtime = match &*state.scanner_runtime {
                                Ok(scanner_runtime) => Arc::clone(scanner_runtime),
                                Err(error) => {
                                    warn!(error = %error, monitor_id = definition.id, "scanning runtime failed to start, aborting monitor");
                                    break;
                                },
                            };
                            do_ping_monitor(&definition, scanner_runtime).await
                        },
                        ProbeType::TcpOpen => do_tcpopen_monitor(&definition).await,
                    };

                    state.log.write(monitor_result);

                    let elapsed = UtcDateTime::now() - start_time;
                    let next_run_in =
                        (definition.interval as f64 - elapsed.as_seconds_f64()).clamp(1.0, f64::INFINITY);
                    select! {
                        _ = cancellation_monitor.cancelled() => { return }
                        _ = tokio::time::sleep(Duration::from_secs_f64(next_run_in)) => { }
                    };
                }
            };

            (
                (definition_id, cancellation_token),
                Box::pin(monitor) as Pin<Box<dyn Future<Output = ()> + Send>>,
            )
        })
        .unzip();

    let mut cancellation_tokens_write = state
        .cancellation_tokens
        .lock()
        .map_err(|_| anyhow!("cancellation token lock poisoned"))?;

    for definition in deleted {
        cancellation_tokens_write[&definition.id].cancel();
        cancellation_tokens_write.remove(&definition.id);
    }

    for (monitor_id, cancellation_token) in new_cancellation_tokens {
        cancellation_tokens_write.insert(monitor_id, cancellation_token);
    }

    for monitoring_task in new_monitors {
        tokio::spawn(monitoring_task);
    }

    Ok(())
}

async fn do_ping_monitor(definition: &MonitorDefinition, scanner_runtime: Arc<Socket2Runtime>) -> MonitorResult {
    let start_time = UtcDateTime::now();

    let ping_result = async || -> anyhow::Result<time::Duration> {
        ping::ping_addr(
            scanner_runtime,
            format!("{hostname}:0", hostname = definition.address),
            Duration::from_secs(definition.timeout),
        )
        .await?;
        // TODO: send more than 1 ping packet

        Ok(UtcDateTime::now() - start_time)
    }()
    .await;

    match ping_result {
        Ok(time) => MonitorResult {
            monitor_id: definition.id.clone(),
            request_start_time: start_time,
            response_success: true,
            response_messages: None,
            response_time: time.as_seconds_f64(),
        },
        Err(error) => MonitorResult {
            monitor_id: definition.id.clone(),
            request_start_time: start_time,
            response_success: false,
            response_messages: Some(format!("{error:#}")),
            response_time: f64::INFINITY,
        },
    }
}

async fn do_tcpopen_monitor(definition: &MonitorDefinition) -> MonitorResult {
    MonitorResult {
        monitor_id: definition.id.clone(),
        request_start_time: UtcDateTime::now(),
        response_success: false,
        response_messages: Some("not implemented".into()),
        response_time: f64::INFINITY,
    }
}

pub fn drain_log(state: Arc<State>) -> VecDeque<MonitorResult> {
    state.log.drain()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitorsConfig {
    pub monitors: Vec<MonitorDefinition>,
}

impl MonitorsConfig {
    fn empty() -> MonitorsConfig {
        MonitorsConfig { monitors: Vec::new() }
    }

    fn mock() -> MonitorsConfig {
        MonitorsConfig {
            monitors: vec![MonitorDefinition {
                id: "a".to_owned(),
                probe: ProbeType::Ping,
                address: "c".to_owned(),
                interval: 1,
                timeout: 2,
                port: Some(3),
            }],
        }
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ProbeType {
    Ping,
    TcpOpen,
}

#[derive(Eq, PartialEq, Hash, Clone, Serialize, Deserialize, Debug)]
pub struct MonitorDefinition {
    pub id: String,
    pub probe: ProbeType,
    pub address: String,
    pub interval: u64,
    pub timeout: u64,
    pub port: Option<i16>,
}

#[derive(PartialEq, Clone, Debug)]
pub struct MonitorResult {
    pub monitor_id: String,
    pub request_start_time: UtcDateTime,
    pub response_success: bool,
    pub response_messages: Option<String>,
    pub response_time: f64,
}
