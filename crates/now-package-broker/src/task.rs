//! Package broker entry point

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::executor::{self, CommandExecutor};
use crate::pipe::DEFAULT_PIPE_NAME;
use crate::policy_store::PolicyStore;
use crate::server::BrokerState;

/// Configuration for the broker task.
#[derive(Debug, Clone)]
pub struct BrokerTaskConfig {
    /// Named pipe name to listen on.
    pub pipe_name: String,
    /// Path to the policy JSON file. If `None`, uses the default location
    /// (`%PROGRAMDATA%\Devolutions\PackageBroker\package-broker-policy.json`).
    pub policy_path: Option<String>,
    /// Skip Authenticode signature validation for the broker client executable.
    pub skip_signature_validation: bool,
}

impl Default for BrokerTaskConfig {
    fn default() -> Self {
        Self {
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
            policy_path: None,
            skip_signature_validation: false,
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

    const NAME: &'static str = "package-broker";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> Self::Output {
        let policy_store = PolicyStore::load(self.config.policy_path.clone().map(std::path::PathBuf::from));

        let executor: Arc<dyn CommandExecutor> = executor::create_platform_executor().into();

        let state = Arc::new(BrokerState {
            policy_store: Arc::clone(&policy_store),
            executor,
            pipe_name: self.config.pipe_name.clone(),
            tracker: crate::operation_tracker::OperationTracker::new(),
            skip_signature_validation: self.config.skip_signature_validation,
            manager_probe_cache: Default::default(),
        });

        // Bridge the agent's ShutdownSignal to the cancellation token used by subsystems.
        let shutdown = CancellationToken::new();
        state.tracker.clone().spawn_eviction_task(shutdown.clone());

        // Spawn the policy store's file watcher, coordinating external edits with the
        // management API through the store's own write lock.
        let watcher_shutdown = shutdown.clone();
        tokio::spawn(async move {
            policy_store.watch(watcher_shutdown).await;
        });

        // Spawn pipe server.
        let server_shutdown = shutdown.clone();
        let server_handle = tokio::spawn({
            let state = Arc::clone(&state);
            async move { crate::pipe::run_pipe_server(state, server_shutdown).await }
        });

        // Wait for agent shutdown signal.
        shutdown_signal.wait().await;
        info!("package broker received shutdown signal");
        shutdown.cancel();

        // Wait for the server task to finish.
        match server_handle.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error).context("broker pipe server error"),
            Err(error) => Err(error).context("broker server task panicked"),
        }
    }
}
