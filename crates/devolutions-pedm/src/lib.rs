use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};

cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        pub mod api;
        mod config;
        mod elevations;
        mod elevator;
        mod error;
        mod log;
        mod policy;
        mod utils;
        use tokio::select;

        use tracing::error;
    }
}

pub struct PedmTask {}

impl PedmTask {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for PedmTask {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Task for PedmTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "devolutions-pedm";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "windows")] {
                select! {
                    res = api::serve(config::PIPE_NAME) => {
                        if let Err(error) = &res {
                            error!(%error, "Devolutions PEDM named pipe server got error");
                        }

                        res
                    }
                    _ = shutdown_signal.wait() => {
                        Ok(())
                    }
                }
            } else {
                shutdown_signal.wait().await;

                Ok(())
            }
        }
    }
}
