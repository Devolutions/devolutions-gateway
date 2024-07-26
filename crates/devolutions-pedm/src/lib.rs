mod config;
mod desktop;
mod elevations;
mod elevator;
mod policy;
mod utils;
mod log;
mod error;
pub mod api;

use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use tokio::select;

use tracing::error;

pub struct PedmTask {}

impl PedmTask {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Task for PedmTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "devolutions-pedm";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
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
    }
}
