//! Policy file watcher with live reload.
//!
//! Watches the policy file for changes and reloads it when modified.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::policy_store::{PolicyStore, ReloadCause};

fn affects_policy(event: &notify::Event, path: &Path) -> bool {
    (event.kind.is_create() || event.kind.is_modify() || event.kind.is_remove())
        && event
            .paths
            .iter()
            .any(|event_path| crate::policy_security::windows_paths_equal(event_path, path))
}

async fn debounce_change(
    changes: &mut tokio::sync::mpsc::Receiver<tokio::time::Instant>,
    failures: &mut tokio::sync::mpsc::UnboundedReceiver<WatcherFailure>,
    shutdown: &CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<bool, WatcherFailure> {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(false),
            failure = failures.recv() => return Err(failure.unwrap_or(WatcherFailure::ChannelClosed)),
            _ = tokio::time::sleep_until(deadline) => {
                while changes.try_recv().is_ok() {}
                return Ok(true);
            }
            Some(_) = changes.recv() => {}
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum WatcherFailure {
    Creation,
    Registration,
    Notification,
    ChannelClosed,
    TaskTerminated,
}

/// Watches a JSON policy file and reloads the shared policy store on change.
pub struct PolicyWatcher(Arc<PolicyStore>);

impl PolicyWatcher {
    pub fn new(store: Arc<PolicyStore>) -> Self {
        Self(store)
    }

    /// Start watching the policy file for changes.
    ///
    /// This spawns a background task that watches the policy file's parent directory
    /// and reloads the policy when the file is modified, created, or removed.
    /// The task runs until the shutdown notify is triggered.
    pub(crate) async fn watch(
        self,
        shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<(), WatcherFailure>>,
    ) {
        let store = self.0;
        let path = store.configured_path();
        let dir = path.parent().unwrap_or_else(|| Path::new(".")).to_owned();

        let (change_tx, mut changes) = tokio::sync::mpsc::channel(1);
        let (failure_tx, mut failures) = tokio::sync::mpsc::unbounded_channel();
        let (watcher_stop_tx, watcher_stop_rx) = std::sync::mpsc::channel::<()>();

        let _watcher_handle = tokio::task::spawn_blocking(move || {
            let mut watcher: RecommendedWatcher =
                match notify::recommended_watcher(move |result: notify::Result<notify::Event>| match result {
                    Ok(event) if affects_policy(&event, &path) => _ = change_tx.try_send(tokio::time::Instant::now()),
                    Ok(_) => {}
                    Err(_) => _ = failure_tx.send(WatcherFailure::Notification),
                }) {
                    Ok(watcher) => watcher,
                    Err(error) => {
                        error!(%error, "Failed to create policy file watcher");
                        let _ = ready.send(Err(WatcherFailure::Creation));
                        return;
                    }
                };

            if let Err(error) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
                error!(%error, path = %dir.display(), "Failed to watch policy directory");
                let _ = ready.send(Err(WatcherFailure::Registration));
                return;
            }

            let _ = ready.send(Ok(()));
            let _ = watcher_stop_rx.recv();
        });

        let debounce = Duration::from_millis(500);

        let failure = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break None,
                failure = failures.recv() => break Some(failure.unwrap_or(WatcherFailure::ChannelClosed)),
                Some(changed_at) = changes.recv() => {
                    match debounce_change(&mut changes, &mut failures, &shutdown, changed_at + debounce).await {
                        Ok(true) => _ = store.reload_from_disk(ReloadCause::ExternalChange).await,
                        Ok(false) => break None,
                        Err(failure) => break Some(failure),
                    }
                }
            }
        };
        match failure {
            Some(failure) => fail_closed(&store, failure).await,
            None => info!("Policy watcher shutting down"),
        }
        let _ = watcher_stop_tx.send(());
    }
}

pub(crate) async fn fail_closed(store: &PolicyStore, failure: WatcherFailure) {
    error!(?failure, "Policy watcher failed; broker paused");
    store.mark_watcher_unavailable().await;
}

pub(crate) async fn monitor_watcher_task(
    store: Arc<PolicyStore>,
    shutdown: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
) {
    let _ = handle.await;
    if !shutdown.is_cancelled() {
        fail_closed(&store, WatcherFailure::TaskTerminated).await;
    }
}

#[cfg(test)]
mod tests {
    use notify::EventKind;
    use notify::event::{CreateKind, ModifyKind, RemoveKind, RenameMode};

    use super::*;

    #[tokio::test]
    async fn fatal_error_preempts_expired_deadline_which_preempts_queued_change() {
        let (tx, mut changes) = tokio::sync::mpsc::channel(2);
        let (failure_tx, mut failures) = tokio::sync::mpsc::unbounded_channel();
        tx.send(tokio::time::Instant::now()).await.expect("send change");
        let stop = CancellationToken::new();
        let result = debounce_change(&mut changes, &mut failures, &stop, tokio::time::Instant::now()).await;
        assert!(matches!(result, Ok(true)));
        failure_tx.send(WatcherFailure::Notification).expect("send failure");
        let result = debounce_change(&mut changes, &mut failures, &stop, tokio::time::Instant::now()).await;
        assert!(matches!(result, Err(WatcherFailure::Notification)));
    }

    #[test]
    fn event_filter_ignores_siblings_and_accepts_relevant_kinds() {
        let policy = Path::new(r"C:\POLICY.json");
        let event = |name| notify::Event::new(EventKind::Modify(ModifyKind::Any)).add_path(policy.with_file_name(name));
        assert!(!affects_policy(&event("sibling.json"), policy));
        let relevant = |kind| {
            affects_policy(
                &notify::Event::new(kind).add_path(policy.with_file_name("policy.json")),
                policy,
            )
        };
        assert!(relevant(EventKind::Create(CreateKind::Any)));
        assert!(relevant(EventKind::Modify(ModifyKind::Any)));
        assert!(relevant(EventKind::Remove(RemoveKind::Any)));
        assert!(relevant(EventKind::Modify(ModifyKind::Name(RenameMode::From))));
        assert!(relevant(EventKind::Modify(ModifyKind::Name(RenameMode::To))));
        assert!(relevant(EventKind::Modify(ModifyKind::Name(RenameMode::Both))));
        assert!(affects_policy(
            &notify::Event::new(EventKind::Modify(ModifyKind::Any)).add_path(Path::new(r"C:\pölicy.json").to_owned()),
            Path::new(r"C:\PÖLICY.json"),
        ));
    }

    #[tokio::test]
    async fn watcher_task_exit_fails_closed_but_shutdown_does_not() {
        let store = PolicyStore::for_tests(None);
        let initial = store.management_snapshot().state;
        monitor_watcher_task(Arc::clone(&store), CancellationToken::new(), tokio::spawn(async {})).await;
        assert_ne!(store.management_snapshot().state, initial);
        let store = PolicyStore::for_tests(None);
        let initial = store.management_snapshot().state;
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        monitor_watcher_task(Arc::clone(&store), shutdown, tokio::spawn(async {})).await;
        assert_eq!(store.management_snapshot().state, initial);
    }
}
