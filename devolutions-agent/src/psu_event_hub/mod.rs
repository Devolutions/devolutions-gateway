pub(crate) mod compat;
mod executor;
mod models;
mod powershell_worker;
mod result_store;
mod signalr;

use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::task::JoinSet;

use crate::config::ConfHandle;
use crate::psu_event_hub::executor::EventHubExecutor;
use crate::psu_event_hub::powershell_worker::PowerShellWorker;

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

        let secret_resolver = PowerShellWorker::new(psu_conf.powershell.clone());

        for mut connection in psu_conf.connections {
            if connection.hub.trim().is_empty() {
                warn!(url = %connection.url, "Skipping PSU Event Hub connection without a hub name");
                continue;
            }

            if let Some(app_token) = connection.app_token.as_deref() {
                match secret_resolver.resolve_app_token(app_token).await {
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

            let executor = EventHubExecutor::new(&connection, psu_conf.powershell.clone());
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
