use crate::config::Config;
use crate::http::http_server::configure_http_server;
use crate::jet_client::JetAssociationsMap;
use crate::listener::GatewayListener;
use crate::log::{self, log_deleter_task, LoggerGuard};
use crate::token::{CurrentJrl, JrlTokenClaims};
use anyhow::Context;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tap::Pipe as _;
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
    config: Arc<Config>,
    state: GatewayState,
    _logger_guard: LoggerGuard,
}

impl GatewayService {
    pub fn load(config: Config) -> anyhow::Result<Self> {
        let logger_guard =
            log::init(&config.log_file, config.log_directive.as_deref()).context("failed to setup logger")?;

        debug!(?config, "config loaded");

        crate::plugin_manager::load_plugins(&config).context("failed to load plugins")?;

        if !config.debug.is_default() {
            warn!(
                ?config.debug,
                "**DEBUG OPTIONS ARE ENABLED, PLEASE DO NOT USE IN PRODUCTION**",
            );
        }

        let config = Arc::new(config);

        if let Err(e) = crate::tls_sanity::check_default_configuration() {
            warn!("Anomality detected with TLS configuration: {e:#}");
        }

        Ok(GatewayService {
            config,
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

    pub fn start(&mut self) {
        let runtime = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create runtime");

        let config = self.config.clone();

        // create_futures needs to be run in the runtime in order to bind the sockets.
        let futures = runtime.block_on(async { create_futures(config).expect("failed to initiate gateway") });

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

fn create_futures(config: Arc<Config>) -> anyhow::Result<VecOfFuturesType> {
    let associations: Arc<JetAssociationsMap> = Arc::new(Mutex::new(HashMap::new()));
    let token_cache = crate::token::new_token_cache().pipe(Arc::new);
    let jrl = load_jrl_from_disk(&config)?;

    // Configure http server
    configure_http_server(config.clone(), associations.clone(), token_cache.clone(), jrl.clone())
        .context("failed to configure http server")?;

    let mut futures: VecOfFuturesType = Vec::with_capacity(config.listeners.len());

    let listeners = config
        .listeners
        .iter()
        .map(|listener| {
            GatewayListener::init_and_bind(
                listener.internal_url.clone(),
                config.clone(),
                associations.clone(),
                token_cache.clone(),
                jrl.clone(),
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
        let log_path = config.log_file.clone();
        futures.push(Box::pin(async move { log_deleter_task(&log_path).await }));
    }

    Ok(futures)
}

fn load_jrl_from_disk(config: &Config) -> anyhow::Result<Arc<CurrentJrl>> {
    use picky::jose::{jws, jwt};

    let jrl_file = config.jrl_file.as_path();

    let claims: JrlTokenClaims = if jrl_file.exists() {
        info!("Reading JRL file from disk (path: {jrl_file})");
        let token = std::fs::read_to_string(jrl_file).context("Couldn't read JRL file")?;

        let jwt = if config.debug.disable_token_validation {
            warn!("**DEBUG OPTION** ignoring JRL token signature");
            jws::RawJws::decode(&token)
                .map(jws::RawJws::discard_signature)
                .map(jwt::JwtSig::from)
                .map_err(jwt::JwtError::from)
        } else {
            jwt::JwtSig::decode(&token, &config.provisioner_public_key)
        }
        .context("Failed to decode JRL token")?;

        let jwt = jwt
            .validate::<JrlTokenClaims>(&jwt::NO_CHECK_VALIDATOR) // we don't expect any expiration for JRL tokens
            .context("JRL token validation failed")?;

        jwt.state.claims
    } else {
        info!("JRL file doesn't exist (path: {jrl_file}). Starting with an empty JRL (JWT Revocation List).");
        JrlTokenClaims::default()
    };

    Ok(Arc::new(Mutex::new(claims)))
}
