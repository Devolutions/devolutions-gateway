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

/// Aborts the running task when dropped, unless it was detached.
/// Also see https://github.com/tokio-rs/tokio/issues/1830 for some background.
#[must_use]
pub struct ChildTask<T> {
    handle: JoinHandle<T>,
    detached: bool,
}

impl<T> ChildTask<T> {
    pub fn spawn<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        ChildTask::from(tokio::task::spawn(future))
    }

    pub async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        (&mut self.handle).await
    }

    /// Immediately abort the task
    pub fn abort(&self) {
        self.handle.abort()
    }

    /// Drop without aborting the task
    pub fn detach(mut self) {
        // The handle is still dropped, because a forgotten `JoinHandle` keeps the finished task allocated.
        self.detached = true;
    }
}

impl<T> From<JoinHandle<T>> for ChildTask<T> {
    fn from(value: JoinHandle<T>) -> Self {
        Self {
            handle: value,
            detached: false,
        }
    }
}

impl<T> Drop for ChildTask<T> {
    fn drop(&mut self) {
        if !self.detached {
            self.abort();
        }
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
    ChildTask::from(handle)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    // oracle: regression #1973
    #[tokio::test]
    async fn detached_task_releases_its_output_once_finished() {
        let output = Arc::new(());
        let task_output = Arc::clone(&output);
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();

        ChildTask::spawn(async move {
            let _ = finished_tx.send(());
            task_output
        })
        .detach();

        finished_rx.await.expect("detached task was aborted");

        // The current-thread runtime completes the task before this test resumes.
        assert_eq!(Arc::strong_count(&output), 1, "detached task kept its output alive");
    }
}
