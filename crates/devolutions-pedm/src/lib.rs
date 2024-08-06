#[cfg(target_os = "windows")]
#[path = ""]
mod lib_win {
    pub mod api;
    pub(crate) mod config;
    pub(crate) mod desktop;
    pub(crate) mod elevations;
    pub(crate) mod elevator;
    pub(crate) mod error;
    pub(crate) mod log;
    pub(crate) mod policy;
    pub(crate) mod utils;

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
}

#[cfg(target_os = "windows")]
pub use lib_win::*;
