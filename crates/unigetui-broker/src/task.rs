//! Agent task integration for the UniGetUI package broker.
//!
//! Provides a `BrokerTask` struct that implements
//! `devolutions_gateway_task::Task`, allowing the broker to run as a
//! managed subtask inside Devolutions Agent.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::sync::Notify;

use crate::executor::{self, CommandExecutor};
use crate::pipe::DEFAULT_PIPE_NAME;
use crate::policy_loader;
use crate::schema::SchemaValidators;
use crate::server::BrokerState;

/// Configuration for the broker task.
#[derive(Debug, Clone)]
pub struct BrokerTaskConfig {
    /// Named pipe name to listen on.
    pub pipe_name: String,
    /// Path to the policy JSON file. If `None`, uses the default location.
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

/// Broker task for integration with devolutions-agent.
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
        let validators = SchemaValidators::new();

        let policy_path = match &self.config.policy_path {
            Some(path) => std::path::PathBuf::from(path),
            None => policy_loader::find_default_policy().context("failed to find default broker policy")?,
        };

        let policy = policy_loader::load_policy(&policy_path, &validators).context("failed to load broker policy")?;

        tracing::info!(
            policy_id = %policy.metadata.id,
            policy_revision = %policy.metadata.revision,
            "Loaded UniGetUI broker policy"
        );

        let executor: Box<dyn CommandExecutor> = executor::create_platform_executor();

        let state = Arc::new(BrokerState {
            policy,
            executor,
            pipe_name: self.config.pipe_name.clone(),
            validators,
        });

        // Bridge the agent's ShutdownSignal to the Notify used by the pipe server.
        let shutdown_notify = Arc::new(Notify::new());
        let shutdown_notify_clone = Arc::clone(&shutdown_notify);

        let server_handle = tokio::spawn({
            let state = Arc::clone(&state);
            async move { crate::pipe::run_pipe_server(state, shutdown_notify_clone).await }
        });

        // Wait for agent shutdown signal.
        shutdown_signal.wait().await;
        tracing::info!("UniGetUI broker received shutdown signal");
        shutdown_notify.notify_one();

        // Wait for the server task to finish.
        match server_handle.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error).context("broker pipe server error"),
            Err(error) => Err(error).context("broker server task panicked"),
        }
    }
}
