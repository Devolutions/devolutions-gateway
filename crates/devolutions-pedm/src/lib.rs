use async_trait::async_trait;
use camino::Utf8PathBuf;

use devolutions_gateway_task::{ShutdownSignal, Task};

cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        pub mod api;
        mod db;
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

#[derive(Default)]
pub struct PedmTask;

impl PedmTask {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Task for PedmTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "devolutions-pedm";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> anyhow::Result<()> {
        select! {
            res = api::serve(r"\\.\pipe\DevolutionsPEDM", None) => {
                if let Err(e) = &res {
                    error!(%e, "Named pipe server got error");
                }
                res.map_err(Into::into)
            }
            _ = shutdown_signal.wait() => {
                Ok(())
            }
        }
    }
}

pub(crate) fn data_dir() -> Utf8PathBuf {
    devolutions_agent_shared::get_data_dir().join("pedm")
}
