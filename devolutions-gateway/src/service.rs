use crate::config::Config;
use crate::http::http_server::configure_http_server;
use crate::jet_client::JetAssociationsMap;
use crate::listener::GatewayListener;
use crate::logger;
use anyhow::Context;
use parking_lot::Mutex;
use slog::Logger;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::runtime::{self, Runtime};

#[allow(clippy::large_enum_variant)] // `Running` variant is bigger than `Stopped` but we don't care
enum GatewayState {
    Stopped,
    Running { runtime: Runtime },
}

pub struct GatewayService {
    config: Arc<Config>,
    logger: Logger,
    state: GatewayState,
    _logger_guard: slog_scope::GlobalLoggerGuard,
}

impl GatewayService {
    pub fn load(config: Config) -> anyhow::Result<Self> {
        let logger =
            logger::init(config.log_file.as_ref().map(|o| o.as_std_path())).context("failed to setup logger")?;
        let logger_guard = slog_scope::set_global_logger(logger.clone());
        slog_stdlog::init().context("Failed to init logger")?;

        config.validate().context("Invalid configuration")?;

        let config = Arc::new(config);

        Ok(GatewayService {
            config,
            logger,
            state: GatewayState::Stopped,
            _logger_guard: logger_guard,
        })
    }

    pub fn get_service_name(&self) -> &str {
        self.config.service_name.as_str()
    }

    pub fn get_display_name(&self) -> &str {
        self.config.display_name.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.config.description.as_str()
    }

    pub fn start(&mut self) {
        let runtime = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create runtime");

        let config = self.config.clone();
        let logger = self.logger.clone();

        // create_futures needs to be run in the runtime in order to bind the sockets.
        let futures = runtime.block_on(async { create_futures(config, logger).expect("failed to initiate gateway") });

        let join_all = futures::future::join_all(futures);

        runtime.spawn(async {
            join_all.await.into_iter().for_each(|result| {
                if let Err(e) = result {
                    error!("Listeners failed: {}", e)
                }
            });
        });

        self.state = GatewayState::Running { runtime };
    }

    pub fn stop(&mut self) {
        match std::mem::replace(&mut self.state, GatewayState::Stopped) {
            GatewayState::Stopped => {
                info!("Attempted to stop gateway service, but it's already stopped");
            }
            GatewayState::Running { runtime } => {
                info!("Stopping gateway service");

                // stop runtime now
                runtime.shutdown_background();

                self.state = GatewayState::Stopped;
            }
        }
    }
}

// TODO: when benchmarking facility is ready, use Handle instead of pinned futures
type VecOfFuturesType = Vec<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'static>>>;

fn create_futures(config: Arc<Config>, logger: slog::Logger) -> anyhow::Result<VecOfFuturesType> {
    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));

    // Configure http server
    configure_http_server(config.clone(), jet_associations.clone()).context("failed to configure http server")?;

    let mut futures: VecOfFuturesType = Vec::with_capacity(config.listeners.len());

    let listeners = config
        .listeners
        .iter()
        .map(|listener| {
            GatewayListener::init_and_bind(
                listener.internal_url.clone(),
                config.clone(),
                jet_associations.clone(),
                logger.clone(),
            )
            .with_context(|| format!("Failed to initialize {}", listener.internal_url))
        })
        .collect::<anyhow::Result<Vec<GatewayListener>>>()
        .context("Failed to bind a listener")?;

    for listener in listeners {
        futures.push(Box::pin(listener.run()))
    }

    futures.push(Box::pin(async {
        crate::token::cleanup_task().await;
        Ok(())
    }));

    Ok(futures)
}
