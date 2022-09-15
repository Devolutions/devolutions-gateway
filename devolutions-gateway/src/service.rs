use crate::config::{Conf, ConfHandle};
use crate::http::http_server::configure_http_server;
use crate::jet_client::JetAssociationsMap;
use crate::listener::GatewayListener;
use crate::log::{self, LoggerGuard};
use crate::session::{session_manager_channel, SessionManagerTask};
use crate::subscriber::subscriber_channel;
use crate::token::{CurrentJrl, JrlTokenClaims};
use anyhow::Context;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tap::prelude::*;
use tokio::runtime::{self, Runtime};

pub const SERVICE_NAME: &str = "devolutions-gateway";
pub const DISPLAY_NAME: &str = "Devolutions Gateway";
pub const DESCRIPTION: &str = "Devolutions Gateway service";

#[allow(clippy::large_enum_variant)] // `Running` variant is bigger than `Stopped` but we don't care
enum GatewayState {
    Stopped,
    Running { runtime: Runtime },
}

pub struct GatewayService {
    conf_handle: ConfHandle,
    state: GatewayState,
    _logger_guard: LoggerGuard,
}

impl GatewayService {
    pub fn load(conf_handle: ConfHandle) -> anyhow::Result<Self> {
        let conf = conf_handle.get_conf();

        let logger_guard =
            log::init(&conf.log_file, conf.log_directive.as_deref()).context("failed to setup logger")?;

        let conf_file = conf_handle.get_conf_file();
        trace!(?conf_file);

        crate::plugin_manager::load_plugins(&conf).context("failed to load plugins")?;

        if !conf.debug.is_default() {
            warn!(
                ?conf.debug,
                "**DEBUG OPTIONS ARE ENABLED, PLEASE DO NOT USE IN PRODUCTION**",
            );
        }

        if let Err(e) = crate::tls_sanity::check_default_configuration() {
            warn!("Anomality detected with TLS configuration: {e:#}");
        }

        Ok(GatewayService {
            conf_handle,
            state: GatewayState::Stopped,
            _logger_guard: logger_guard,
        })
    }

    pub fn get_service_name(&self) -> &str {
        SERVICE_NAME
    }

    pub fn get_display_name(&self) -> &str {
        DISPLAY_NAME
    }

    pub fn get_description(&self) -> &str {
        DESCRIPTION
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let runtime = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create runtime");

        let config = self.conf_handle.clone();

        // create_futures needs to be run in the runtime in order to bind the sockets.
        let futures = runtime.block_on(async { create_futures(config) })?;

        let join_all = futures::future::join_all(futures);

        runtime.spawn(async {
            join_all.await.into_iter().for_each(|result| {
                if let Err(e) = result {
                    error!("Listeners failed: {}", e)
                }
            });
        });

        self.state = GatewayState::Running { runtime };

        Ok(())
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

fn create_futures(conf_handle: ConfHandle) -> anyhow::Result<VecOfFuturesType> {
    let conf = conf_handle.get_conf();

    let associations: Arc<JetAssociationsMap> = Arc::new(Mutex::new(HashMap::new()));
    let token_cache = crate::token::new_token_cache().pipe(Arc::new);
    let jrl = load_jrl_from_disk(&conf)?;
    let (session_manager_handle, session_manager_rx) = session_manager_channel();

    // Configure http server
    configure_http_server(
        conf_handle.clone(),
        associations.clone(),
        token_cache.clone(),
        jrl.clone(),
        session_manager_handle.clone(),
    )
    .context("failed to configure http server")?;

    let mut futures: VecOfFuturesType = Vec::with_capacity(conf.listeners.len());

    let (subscriber_tx, subscriber_rx) = subscriber_channel();

    let listeners = conf
        .listeners
        .iter()
        .map(|listener| {
            GatewayListener::init_and_bind(
                listener.internal_url.clone(),
                conf_handle.clone(),
                associations.clone(),
                token_cache.clone(),
                jrl.clone(),
                session_manager_handle.clone(),
                subscriber_tx.clone(),
            )
            .with_context(|| format!("Failed to initialize {}", listener.internal_url))
        })
        .collect::<anyhow::Result<Vec<GatewayListener>>>()
        .context("Failed to bind a listener")?;

    for listener in listeners {
        futures.push(Box::pin(listener.run()))
    }

    futures.push(Box::pin(async {
        crate::token::cleanup_task(token_cache).await;
        Ok(())
    }));

    {
        let log_path = conf.log_file.clone();
        futures.push(Box::pin(async move { crate::log::log_deleter_task(&log_path).await }));
    }

    futures.push(Box::pin(async move {
        crate::subscriber::subscriber_polling_task(session_manager_handle, subscriber_tx).await
    }));

    futures.push(Box::pin(async move {
        crate::subscriber::subscriber_task(conf_handle.clone(), subscriber_rx).await
    }));

    futures.push(Box::pin(async move {
        crate::session::session_manager_task(SessionManagerTask::new(session_manager_rx)).await
    }));

    Ok(futures)
}

fn load_jrl_from_disk(config: &Conf) -> anyhow::Result<Arc<CurrentJrl>> {
    let jrl_file = config.jrl_file.as_path();

    let claims: JrlTokenClaims = if jrl_file.exists() {
        info!("Reading JRL file from disk (path: {jrl_file})");
        std::fs::read_to_string(jrl_file)
            .context("Couldn't read JRL file")?
            .pipe_deref(serde_json::from_str)
            .context("Invalid JRL")?
    } else {
        info!("JRL file doesn't exist (path: {jrl_file}). Starting with an empty JRL (JWT Revocation List).");
        JrlTokenClaims::default()
    };

    Ok(Arc::new(Mutex::new(claims)))
}
