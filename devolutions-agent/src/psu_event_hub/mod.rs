pub(crate) mod compat;
mod executor;
mod result_store;
mod signalr;

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::task::JoinSet;

use crate::config::{ConfHandle, dto};
use crate::psu_event_hub::executor::EventHubExecutor;
use crate::psu_powershell::PowerShellWorker;

pub struct PsuEventHubTask {
    conf_handle: ConfHandle,
}

impl PsuEventHubTask {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[async_trait]
impl Task for PsuEventHubTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "psu event hub";

    async fn run(self, shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        let conf = self.conf_handle.get_conf();
        let psu_conf = conf.psu_event_hub.clone();

        if psu_conf.connections.is_empty() {
            warn!("PSU Event Hub feature is enabled, but no connections are configured");
            return Ok(());
        }

        info!(
            connection_count = psu_conf.connections.len(),
            "Starting PSU Event Hub compatibility feature"
        );

        let mut join_set = JoinSet::new();

        let worker = Arc::new(
            PowerShellWorker::new(psu_conf.powershell.clone()).context("failed to initialize PSU PowerShell worker")?,
        );

        for mut connection in psu_conf.connections {
            if connection.hub.trim().is_empty() {
                warn!(url = %connection.url, "Skipping PSU Event Hub connection without a hub name");
                continue;
            }

            if let Err(error) = validate_connection(&connection) {
                error!(
                    hub = %connection.hub,
                    error = format!("{error:#}"),
                    "Skipping PSU Event Hub connection because configuration is invalid"
                );
                continue;
            }

            if let Some(app_token) = connection.app_token.as_deref() {
                match worker.resolve_app_token(app_token).await {
                    Ok(resolved) => connection.app_token = Some(resolved),
                    Err(error) => {
                        error!(
                            hub = %connection.hub,
                            error = format!("{error:#}"),
                            "Skipping PSU Event Hub connection because AppToken secret resolution failed"
                        );
                        continue;
                    }
                }
            }

            let executor = EventHubExecutor::new(&connection, Arc::clone(&worker));
            let connection_shutdown_signal = shutdown_signal.clone();

            join_set
                .spawn(async move { signalr::run_connection(connection, executor, connection_shutdown_signal).await });
        }

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok(())) => trace!("PSU Event Hub connection task terminated gracefully"),
                Ok(Err(error)) => error!(error = format!("{error:#}"), "PSU Event Hub connection task failed"),
                Err(error) => error!(%error, "PSU Event Hub connection task panicked"),
            }
        }

        Ok(())
    }
}

fn validate_connection(connection: &dto::PsuEventHubConnectionConf) -> anyhow::Result<()> {
    if connection.use_default_credentials && connection.app_token.is_none() {
        anyhow::bail!(
            "PSU Event Hub use_default_credentials is configured for hub {} but Windows default credentials are not implemented",
            connection.hub
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    // THOUGHT(CBenoit): The contract should probably be encoded at the type level instead of providing a separate validate_connection function.
    // We need to verify if the type can be made stronger without breaking something else though.
    #[test]
    fn default_credentials_without_app_token_are_rejected() {
        let connection = dto::PsuEventHubConnectionConf {
            hub: "Hub".to_owned(),
            url: Url::parse("http://localhost:5000").expect("parse URL"),
            app_token: None,
            use_default_credentials: true,
            script_path: None,
            description: None,
        };

        assert!(validate_connection(&connection).is_err());
    }
}
