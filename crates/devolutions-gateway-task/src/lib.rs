use std::future::Future;

use async_trait::async_trait;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct ShutdownHandle(tokio::sync::watch::Sender<()>);

impl ShutdownHandle {
    pub fn new() -> (Self, ShutdownSignal) {
        let (sender, receiver) = tokio::sync::watch::channel(());
        (Self(sender), ShutdownSignal(receiver))
    }

    pub fn signal(&self) {
        let _ = self.0.send(());
    }

    pub async fn all_closed(&self) {
        self.0.closed().await;
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownSignal(tokio::sync::watch::Receiver<()>);

impl ShutdownSignal {
    pub async fn wait(&mut self) {
        let _ = self.0.changed().await;
    }
}

/// Aborts the running task when dropped.
/// Also see https://github.com/tokio-rs/tokio/issues/1830 for some background.
#[must_use]
pub struct ChildTask<T>(JoinHandle<T>);

impl<T> ChildTask<T> {
    pub fn spawn<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        ChildTask(tokio::task::spawn(future))
    }

    pub async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        (&mut self.0).await
    }

    /// Immediately abort the task
    pub fn abort(&self) {
        self.0.abort()
    }

    /// Drop without aborting the task
    pub fn detach(self) {
        core::mem::forget(self);
    }
}

impl<T> From<JoinHandle<T>> for ChildTask<T> {
    fn from(value: JoinHandle<T>) -> Self {
        Self(value)
    }
}

impl<T> Drop for ChildTask<T> {
    fn drop(&mut self) {
        self.abort();
    }
}

#[async_trait]
pub trait Task {
    type Output: Send;

    const NAME: &'static str;

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output;
}

pub fn spawn_task<T>(task: T, shutdown_signal: ShutdownSignal) -> ChildTask<T::Output>
where
    T: Task + 'static,
{
    let task_fut = task.run(shutdown_signal);
    let handle = spawn_task_impl(task_fut, T::NAME);
    ChildTask(handle)
}

#[cfg(not(all(feature = "named_tasks", tokio_unstable)))]
#[track_caller]
fn spawn_task_impl<T>(future: T, _name: &str) -> JoinHandle<T::Output>
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    tokio::task::spawn(future)
}

#[cfg(all(feature = "named_tasks", tokio_unstable))]
#[track_caller]
fn spawn_task_impl<T>(future: T, name: &str) -> JoinHandle<T::Output>
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    // NOTE: To enable this code, this crate must be built using a command similar to:
    // > RUSTFLAGS="--cfg tokio_unstable" cargo check --features named_tasks

    // NOTE: unwrap because as of now (tokio 1.28), this never returns an error,
    // and production build never enable tokio-console instrumentation anyway (unstable).
    tokio::task::Builder::new().name(name).spawn(future).unwrap()
}
