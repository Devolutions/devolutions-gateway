// Start the program without a console window.
// It has no effect on platforms other than Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(all(windows, feature = "dvc"))]
use ::{async_trait as _, now_proto_pdu as _, tempfile as _, thiserror as _, win_api_wrappers as _, windows as _};
use ::{
    camino as _, cfg_if as _, ctrlc as _, devolutions_log as _, futures as _, parking_lot as _, serde as _,
    serde_json as _, tap as _,
};

#[macro_use]
extern crate tracing;
use anyhow::Context;
use devolutions_gateway_task::{ChildTask, ShutdownHandle, ShutdownSignal};
#[cfg(all(windows, feature = "dvc"))]
use devolutions_session::dvc::task::DvcIoTask;
use devolutions_session::{ConfHandle, get_data_dir, init_log};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

fn main() -> anyhow::Result<()> {
    // Ensure per-user data dir exists.

    std::fs::create_dir_all(get_data_dir()).context("failed to create data directory")?;

    let conf = ConfHandle::init()
        .context("failed to initialize configuration")?
        .get_conf();

    let _logger_guard = init_log(&conf);

    info!("Starting Devolutions Session");

    let (runtime, shutdown_handle, join_handle) = start()?;

    ctrlc::set_handler(move || {
        info!("Ctrl-C received, exiting");

        shutdown_handle.signal();
    })
    .expect("BUG: Failed to set Ctrl-C handler");

    info!("Waiting for shutdown signal");

    runtime.block_on(join_handle)?;

    info!("Exiting Devolutions Session");

    Ok(())
}

pub fn start() -> anyhow::Result<(Runtime, ShutdownHandle, JoinHandle<()>)> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create runtime");

    // NOTE: `spawn_tasks` should be always called from within the tokio runtime.
    let tasks = runtime.block_on(spawn_tasks())?;

    trace!("Devolutions Session tasks created");

    let shutdown_handle = tasks.shutdown_handle;

    let mut join_all = futures::future::select_all(tasks.inner.into_iter().map(|child| Box::pin(child.join())));

    let join_handle = runtime.spawn(async {
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

    Ok((runtime, shutdown_handle, join_handle))
}

#[cfg(all(windows, feature = "dvc"))]
async fn spawn_tasks() -> anyhow::Result<Tasks> {
    let mut tasks = Tasks::new();

    tasks.register(DvcIoTask::default());

    Ok(tasks)
}

#[cfg(not(all(windows, feature = "dvc")))]
async fn spawn_tasks() -> anyhow::Result<Tasks> {
    Ok(Tasks::new())
}

struct Tasks {
    inner: Vec<ChildTask<anyhow::Result<()>>>,
    shutdown_handle: ShutdownHandle,
    // NOTE: Currently unused on non-windows platforms; kept for future use.
    #[allow(dead_code)]
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

    // NOTE: Currently unused on non-windows platforms; kept for future use.
    #[allow(dead_code)]
    fn register<T>(&mut self, task: T)
    where
        T: devolutions_gateway_task::Task<Output = anyhow::Result<()>> + 'static,
    {
        let child = devolutions_gateway_task::spawn_task(task, self.shutdown_signal.clone());
        self.inner.push(child);
    }
}
