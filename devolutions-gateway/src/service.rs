use anyhow::Context as _;
use devolutions_gateway::config::{Conf, ConfHandle};
use devolutions_gateway::listener::GatewayListener;
use devolutions_gateway::log::{self, LoggerGuard};
use devolutions_gateway::session::session_manager_channel;
use devolutions_gateway::subscriber::subscriber_channel;
use devolutions_gateway::token::{CurrentJrl, JrlTokenClaims};
use devolutions_gateway::DgwState;
use devolutions_gateway_task::{ChildTask, ShutdownHandle, ShutdownSignal};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tap::prelude::*;
use tokio::runtime::{self, Runtime};

pub const SERVICE_NAME: &str = "devolutions-gateway";
pub const DISPLAY_NAME: &str = "Devolutions Gateway";
pub const DESCRIPTION: &str = "Devolutions Gateway service";

#[allow(clippy::large_enum_variant)] // `Running` variant is bigger than `Stopped` but we don't care
enum GatewayState {
    Stopped,
    Running {
        shutdown_handle: ShutdownHandle,
        runtime: Runtime,
    },
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
        let tasks = runtime.block_on(spawn_tasks(config))?;

        trace!("Tasks created");

        let mut join_all = futures::future::select_all(tasks.inner.into_iter().map(|child| Box::pin(child.join())));

        runtime.spawn(async {
            loop {
                let (result, _, rest) = join_all.await;

                match result {
                    Ok(Ok(())) => trace!("A task terminated gracefully"),
                    Ok(Err(error)) => error!(error = format!("{error:#}"), "A task failed"),
                    Err(error) => error!(%error, "Something went very wrong with a task"),
                }

                if rest.is_empty() {
                    break;
                } else {
                    join_all = futures::future::select_all(rest);
                }
            }
        });

        self.state = GatewayState::Running {
            shutdown_handle: tasks.shutdown_handle,
            runtime,
        };

        Ok(())
    }

    pub fn stop(&mut self) {
        match std::mem::replace(&mut self.state, GatewayState::Stopped) {
            GatewayState::Stopped => {
                info!("Attempted to stop gateway service, but it's already stopped");
            }
            GatewayState::Running {
                shutdown_handle,
                runtime,
            } => {
                info!("Stopping gateway service");

                // Send shutdown signals to all tasks
                shutdown_handle.signal();

                runtime.block_on(async move {
                    tokio::select! {
                        _ = shutdown_handle.all_closed() => {
                            debug!("All tasks closed gracefully");
                        }
                        _ = tokio::time::sleep(Duration::from_secs(10)) => {
                            warn!("Some tasks didn’t terminate at all");
                        }
                    }
                });

                runtime.shutdown_timeout(Duration::from_secs(3));

                self.state = GatewayState::Stopped;
            }
        }
    }
}

struct Tasks {
    inner: Vec<ChildTask<anyhow::Result<()>>>,
    shutdown_handle: ShutdownHandle,
    shutdown_signal: ShutdownSignal,
}

impl Tasks {
    fn new() -> Self {
        let (shutdown_handle, shutdown_signal) = devolutions_gateway_task::ShutdownHandle::new();

        Self {
            inner: Vec::new(),
            shutdown_handle,
            shutdown_signal,
        }
    }

    fn register<T>(&mut self, task: T)
    where
        T: devolutions_gateway_task::Task<Output = anyhow::Result<()>> + 'static,
    {
        let child = devolutions_gateway_task::spawn_task(task, self.shutdown_signal.clone());
        self.inner.push(child);
    }
}

async fn spawn_tasks(conf_handle: ConfHandle) -> anyhow::Result<Tasks> {
    let conf = conf_handle.get_conf();

    let token_cache = devolutions_gateway::token::new_token_cache().pipe(Arc::new);
    let jrl = load_jrl_from_disk(&conf)?;
    let (session_manager_handle, session_manager_rx) = session_manager_channel();
    let (subscriber_tx, subscriber_rx) = subscriber_channel();
    let mut tasks = Tasks::new();

    let state = DgwState {
        conf_handle: conf_handle.clone(),
        token_cache: token_cache.clone(),
        jrl,
        sessions: session_manager_handle.clone(),
        subscriber_tx: subscriber_tx.clone(),
        shutdown_signal: tasks.shutdown_signal.clone(),
    };

    conf.listeners
        .iter()
        .map(|listener| {
            GatewayListener::init_and_bind(listener.internal_url.clone(), state.clone())
                .with_context(|| format!("Failed to initialize {}", listener.internal_url))
        })
        .collect::<anyhow::Result<Vec<GatewayListener>>>()
        .context("failed to bind listener")?
        .into_iter()
        .for_each(|listener| tasks.register(listener));

    if let Some(ngrok_conf) = &conf.ngrok {
        let session = devolutions_gateway::ngrok::NgrokSession::connect(ngrok_conf)
            .await
            .context("couldn’t create ngrok session")?;

        for (name, conf) in &ngrok_conf.tunnels {
            let tunnel = session.configure_endpoint(name, conf);
            tasks.register(devolutions_gateway::ngrok::NgrokTunnelTask {
                tunnel,
                state: state.clone(),
            });
        }
    }

    tasks.register(devolutions_gateway::token::CleanupTask { token_cache });

    tasks.register(devolutions_gateway::log::LogDeleterTask {
        prefix: conf.log_file.clone(),
    });

    tasks.register(devolutions_gateway::subscriber::SubscriberPollingTask {
        sessions: session_manager_handle,
        subscriber: subscriber_tx,
    });

    tasks.register(devolutions_gateway::subscriber::SubscriberTask {
        conf_handle,
        rx: subscriber_rx,
    });

    tasks.register(devolutions_gateway::session::SessionManagerTask::new(
        session_manager_rx,
    ));

    Ok(tasks)
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
