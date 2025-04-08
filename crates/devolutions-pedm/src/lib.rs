use async_trait::async_trait;
use camino::Utf8PathBuf;

pub mod model;

pub use config::Config;
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

        pub use api::serve;

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
        cfg_if::cfg_if! {
            if #[cfg(target_os = "windows")] {
                select! {
                    res = serve(Config::standard()) => {
                        if let Err(error) = &res {
                            error!(%error, "Named pipe server got error");
                        }
                        res.map_err(Into::into)
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

pub(crate) fn data_dir() -> Utf8PathBuf {
    devolutions_agent_shared::get_data_dir().join("pedm")
}
