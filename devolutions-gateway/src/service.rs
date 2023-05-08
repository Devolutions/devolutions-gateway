use anyhow::Context as _;
use devolutions_gateway::config::{Conf, ConfHandle};
use devolutions_gateway::listener::GatewayListener;
use devolutions_gateway::log::{self, LoggerGuard};
use devolutions_gateway::session::{session_manager_channel, SessionManagerTask};
use devolutions_gateway::subscriber::subscriber_channel;
use devolutions_gateway::token::{CurrentJrl, JrlTokenClaims};
use devolutions_gateway::DgwState;
use parking_lot::Mutex;
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

        info!(version = env!("CARGO_PKG_VERSION"));

        let conf_file = conf_handle.get_conf_file();
        trace!(?conf_file);

        devolutions_gateway::plugin_manager::load_plugins(&conf).context("failed to load plugins")?;

        if !conf.debug.is_default() {
            warn!(
                ?conf.debug,
                "**DEBUG OPTIONS ARE ENABLED, PLEASE DO NOT USE IN PRODUCTION**",
            );
        }

        if let Err(e) = devolutions_gateway::tls::sanity::check_default_configuration() {
            warn!("Anomality detected with TLS configuration: {e:#}");
        }

        Ok(GatewayService {
            conf_handle,
            state: GatewayState::Stopped,
            _logger_guard: logger_guard,
        })
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let runtime = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create runtime");

        let config = self.conf_handle.clone();

        // create_futures needs to be run in the runtime in order to bind the sockets.
        let futures = runtime.block_on(create_futures(config))?;

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

async fn create_futures(conf_handle: ConfHandle) -> anyhow::Result<VecOfFuturesType> {
    let conf = conf_handle.get_conf();

    let token_cache = devolutions_gateway::token::new_token_cache().pipe(Arc::new);
    let jrl = load_jrl_from_disk(&conf)?;
    let (session_manager_handle, session_manager_rx) = session_manager_channel();
    let (subscriber_tx, subscriber_rx) = subscriber_channel();

    let state = DgwState {
        conf_handle: conf_handle.clone(),
        token_cache: token_cache.clone(),
        jrl,
        sessions: session_manager_handle.clone(),
        subscriber_tx: subscriber_tx.clone(),
    };

    let mut futures: VecOfFuturesType = Vec::with_capacity(conf.listeners.len());

    let listeners = conf
        .listeners
        .iter()
        .map(|listener| {
            GatewayListener::init_and_bind(listener.internal_url.clone(), state.clone())
                .with_context(|| format!("Failed to initialize {}", listener.internal_url))
        })
        .collect::<anyhow::Result<Vec<GatewayListener>>>()
        .context("failed to bind listener")?;

    for listener in listeners {
        futures.push(Box::pin(listener.run()))
    }

    if conf.debug.enable_ngrok && std::env::var("NGROK_AUTHTOKEN").is_ok() {
        let session = devolutions_gateway::ngrok::NgrokSession::connect(state)
            .await
            .context("couldn’t create ngrok session")?;

        let tcp_fut = {
            let session = session.clone();
            async move { session.run_tcp_endpoint().await }
        };
        futures.push(Box::pin(tcp_fut));

        let http_fut = async move { session.run_http_endpoint().await };
        futures.push(Box::pin(http_fut));
    }

    futures.push(Box::pin(async {
        devolutions_gateway::token::cleanup_task(token_cache).await;
        Ok(())
    }));

    {
        let log_path = conf.log_file.clone();
        futures.push(Box::pin(async move {
            devolutions_gateway::log::log_deleter_task(&log_path).await
        }));
    }

    futures.push(Box::pin(async move {
        devolutions_gateway::subscriber::subscriber_polling_task(session_manager_handle, subscriber_tx).await
    }));

    futures.push(Box::pin(async move {
        devolutions_gateway::subscriber::subscriber_task(conf_handle, subscriber_rx).await
    }));

    futures.push(Box::pin(async move {
        devolutions_gateway::session::session_manager_task(SessionManagerTask::new(session_manager_rx)).await
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
