use std::time::Duration;

use anyhow::Context;
use devolutions_agent::AgentServiceEvent;
use devolutions_agent::config::ConfHandle;
use devolutions_agent::log::AgentLog;
use devolutions_agent::remote_desktop::RemoteDesktopTask;
#[cfg(windows)]
use devolutions_agent::session_manager::SessionManager;
#[cfg(windows)]
use devolutions_agent::updater::UpdaterTask;
use devolutions_gateway_task::{ChildTask, ShutdownHandle, ShutdownSignal};
use devolutions_log::{self, LogDeleterTask, LoggerGuard};
#[cfg(windows)]
use devolutions_pedm::PedmTask;
use tokio::runtime::{self, Runtime};
use tokio::sync::mpsc;

pub(crate) const SERVICE_NAME: &str = "devolutions-agent";
pub(crate) const DISPLAY_NAME: &str = "Devolutions Agent";
pub(crate) const DESCRIPTION: &str = "Devolutions Agent service";

struct TasksCtx {
    /// Spawned service tasks
    tasks: Tasks,
    /// Sender side of the service event channel (Used for session manager module)
    service_event_tx: Option<mpsc::Sender<AgentServiceEvent>>,
}

#[allow(clippy::large_enum_variant)] // `Running` variant is bigger than `Stopped` but we don't care
enum AgentState {
    Stopped,
    Running {
        shutdown_handle: ShutdownHandle,
        runtime: Runtime,
    },
}

pub(crate) struct AgentService {
    conf_handle: ConfHandle,
    state: AgentState,
    _logger_guard: LoggerGuard,
    service_event_tx: Option<mpsc::Sender<AgentServiceEvent>>,
}

impl AgentService {
    pub(crate) fn load(conf_handle: ConfHandle) -> anyhow::Result<Self> {
        let conf = conf_handle.get_conf();

        let logger_guard = devolutions_log::init::<AgentLog>(
            &conf.log_file,
            conf.verbosity_profile.to_log_filter(),
            conf.debug.log_directives.as_deref(),
        )
        .context("failed to setup logger")?;

        info!(version = env!("CARGO_PKG_VERSION"));

        let conf_file = conf_handle.get_conf_file();
        trace!(?conf_file);

        if !conf.debug.is_default() {
            warn!(
                ?conf.debug,
                "**DEBUG OPTIONS ARE ENABLED, PLEASE DO NOT USE IN PRODUCTION**",
            );
        }

        Ok(AgentService {
            conf_handle,
            state: AgentState::Stopped,
            service_event_tx: None,
            _logger_guard: logger_guard,
        })
    }

    pub(crate) fn start(&mut self) -> anyhow::Result<()> {
        let runtime = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create runtime");

        let config = self.conf_handle.clone();

        // create_futures needs to be run in the runtime in order to bind the sockets.
        let TasksCtx {
            tasks,
            service_event_tx,
        } = runtime.block_on(spawn_tasks(config))?;

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

        self.service_event_tx = service_event_tx;
        self.state = AgentState::Running {
            shutdown_handle: tasks.shutdown_handle,
            runtime,
        };

        Ok(())
    }

    pub(crate) fn stop(&mut self) {
        match std::mem::replace(&mut self.state, AgentState::Stopped) {
            AgentState::Stopped => {
                info!("Attempted to stop agent service, but it's already stopped");
            }
            AgentState::Running {
                shutdown_handle,
                runtime,
            } => {
                info!("Stopping agent service");

                // Send shutdown signals to all tasks
                shutdown_handle.signal();

                runtime.block_on(async move {
                    const MAX_COUNT: usize = 3;
                    let mut count = 0;

                    loop {
                        tokio::select! {
                            _ = shutdown_handle.all_closed() => {
                                debug!("All tasks are terminated");
                                break;
                            }
                            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                                count += 1;

                                if count >= MAX_COUNT {
                                    warn!("Terminate forcefully the lingering tasks");
                                    break;
                                } else {
                                    warn!("Termination of certain tasks is experiencing significant delays");
                                }
                            }
                        }
                    }
                });

                // Wait for 1 more second before forcefully shutting down the runtime
                runtime.shutdown_timeout(Duration::from_secs(1));

                self.state = AgentState::Stopped;
            }
        }
    }

    pub(crate) fn service_event_tx(&self) -> Option<mpsc::Sender<AgentServiceEvent>> {
        self.service_event_tx.clone()
    }
}

struct Tasks {
    inner: Vec<ChildTask<anyhow::Result<()>>>,
    shutdown_handle: ShutdownHandle,
    shutdown_signal: ShutdownSignal,
}

impl Tasks {
    fn new() -> Self {
        let (shutdown_handle, shutdown_signal) = ShutdownHandle::new();

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

async fn spawn_tasks(conf_handle: ConfHandle) -> anyhow::Result<TasksCtx> {
    let conf = conf_handle.get_conf();

    let mut tasks = Tasks::new();

    tasks.register(LogDeleterTask::<AgentLog>::new(conf.log_file.clone()));

    #[cfg(windows)]
    let service_event_tx = {
        if conf.updater.enabled {
            tasks.register(UpdaterTask::new(conf_handle.clone()));
        }

        if conf.pedm.enabled {
            tasks.register(PedmTask::new())
        }

        if conf.session.enabled {
            let session_manager = SessionManager::default();
            let tx = session_manager.service_event_tx();
            tasks.register(session_manager);
            Some(tx)
        } else {
            None
        }
    };

    #[cfg(not(windows))]
    let service_event_tx = None;

    if conf.debug.enable_unstable && conf.remote_desktop.enabled {
        tasks.register(RemoteDesktopTask::new(conf_handle));
    }

    Ok(TasksCtx {
        tasks,
        service_event_tx,
    })
}
