//! UniGetUI Broker entry point

use std::sync::{Arc, RwLock};

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::sync::Notify;
use tracing::info;

use crate::executor::{self, CommandExecutor};
use crate::pipe::DEFAULT_PIPE_NAME;
use crate::policy_loader;
use crate::policy_watcher::{PolicyState, PolicyWatcher};
use crate::server::BrokerState;

/// Configuration for the broker task.
#[derive(Debug, Clone)]
pub struct BrokerTaskConfig {
    /// Named pipe name to listen on.
    pub pipe_name: String,
    /// Path to the policy file. If `None`, uses the default location.
    /// Supports `.json`, `.yaml`, and `.yml` extensions.
    pub policy_path: Option<String>,
}

impl Default for BrokerTaskConfig {
    fn default() -> Self {
        Self {
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
            policy_path: None,
        }
    }
}


pub struct BrokerTask {
    config: BrokerTaskConfig,
}

impl BrokerTask {
    pub fn new(config: BrokerTaskConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Task for BrokerTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "unigetui-broker";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> Self::Output {

        // Resolve policy file path.

        let policy_path = match &self.config.policy_path {
            Some(path) => std::path::PathBuf::from(path),
            None => policy_loader::find_default_policy().context("failed to find default broker policy")?,
        };

        // Create policy watcher with initial load attempt.
        let (watcher, mut state_rx) = PolicyWatcher::new(policy_path.clone());

        // Log initial state.
        match &*state_rx.borrow() {
            PolicyState::Active(policy) => {
                info!(
                    policy_id = %policy.metadata.id,
                    policy_revision = %policy.metadata.revision,
                    path = %policy_path.display(),
                    "Loaded UniGetUI broker policy"
                );
            }
            PolicyState::Unavailable { reason } => {
                tracing::warn!(
                    %reason,
                    path = %policy_path.display(),
                    "Policy unavailable at startup; broker will pause until a valid policy is provided"
                );
            }
        }

        let executor: Box<dyn CommandExecutor> = executor::create_platform_executor();

        // Initialize BrokerState with current policy (or None if unavailable).
        let initial_policy = match &*state_rx.borrow() {
            PolicyState::Active(policy) => Some(Arc::clone(policy)),
            PolicyState::Unavailable { .. } => None,
        };

        let state = Arc::new(BrokerState {
            policy: RwLock::new(initial_policy),
            executor,
            pipe_name: self.config.pipe_name.clone(),
        });

        // Bridge the agent's ShutdownSignal to the Notify used by subsystems.
        let shutdown_notify = Arc::new(Notify::new());

        // Spawn policy watcher task.
        let watcher_shutdown = Arc::clone(&shutdown_notify);
        tokio::spawn(async move {
            watcher.watch(watcher_shutdown).await;
        });

        // Spawn policy state relay: updates BrokerState when policy watcher reports changes.
        let relay_state = Arc::clone(&state);
        let relay_shutdown = Arc::clone(&shutdown_notify);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = relay_shutdown.notified() => break,
                    result = state_rx.changed() => {
                        if result.is_err() {
                            // Sender dropped (watcher exited).
                            break;
                        }
                        let new_policy = match &*state_rx.borrow_and_update() {
                            PolicyState::Active(policy) => {
                                info!(
                                    policy_id = %policy.metadata.id,
                                    revision = policy.metadata.revision,
                                    "Policy hot-reloaded; broker resumed"
                                );
                                Some(Arc::clone(policy))
                            }
                            PolicyState::Unavailable { reason } => {
                                tracing::warn!(%reason, "Policy became unavailable; broker paused");
                                None
                            }
                        };
                        *relay_state.policy.write().expect("policy lock poisoned") = new_policy;
                    }
                }
            }
        });

        // Spawn pipe server.
        let server_shutdown = Arc::clone(&shutdown_notify);
        let server_handle = tokio::spawn({
            let state = Arc::clone(&state);
            async move { crate::pipe::run_pipe_server(state, server_shutdown).await }
        });

        // Wait for agent shutdown signal.
        shutdown_signal.wait().await;
        tracing::info!("UniGetUI broker received shutdown signal");
        shutdown_notify.notify_waiters();

        // Wait for the server task to finish.
        match server_handle.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error).context("broker pipe server error"),
            Err(error) => Err(error).context("broker server task panicked"),
        }
    }
}
