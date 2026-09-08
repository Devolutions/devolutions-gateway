//! Policy file watcher with live reload.
//!
//! Watches the policy file for changes and reloads it when modified.

use std::path::{Path, PathBuf};
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

fn affects_watched_paths(event: &notify::Event, paths: &[PathBuf]) -> bool {
    if paths.len() == 1 {
        return affects_policy(event, &paths[0]);
    }
    if !(event.kind.is_create() || event.kind.is_modify() || event.kind.is_remove()) {
        return false;
    }

    let managed = &paths[0];
    let legacy = &paths[1];
    let managed_dir = managed.parent().expect("managed default policy has a parent");
    event.paths.iter().any(|event_path| {
        crate::policy_security::windows_paths_equal(event_path, managed)
            || crate::policy_security::windows_paths_equal(event_path, legacy)
            || crate::policy_security::windows_paths_equal(event_path, managed_dir)
            || event_path
                .parent()
                .is_some_and(|parent| crate::policy_security::windows_paths_equal(parent, managed_dir))
            || managed_dir
                .ancestors()
                .any(|ancestor| crate::policy_security::windows_paths_equal(event_path, ancestor))
    })
}

fn nearest_existing_ancestor(path: &Path) -> PathBuf {
    path.ancestors()
        .find(|candidate| candidate.is_dir())
        .unwrap_or(path)
        .to_owned()
}

fn watch_directories(paths: &[PathBuf]) -> Vec<PathBuf> {
    if paths.len() == 1 {
        return vec![paths[0].parent().unwrap_or_else(|| Path::new(".")).to_owned()];
    }

    let managed_parent = paths[0].parent().expect("managed default policy has a parent");
    let common_parent = managed_parent.parent().unwrap_or_else(|| Path::new("."));
    let mut directories = vec![nearest_existing_ancestor(common_parent)];
    for path in paths {
        let parent = path.parent().expect("default policy path has a parent");
        if parent.is_dir()
            && !directories
                .iter()
                .any(|existing| crate::policy_security::windows_paths_equal(existing, parent))
        {
            directories.push(parent.to_owned());
        }
    }
    directories
}

enum WatcherCommand {
    Refresh,
    Stop,
}

fn create_watcher(
    dir: &Path,
    paths: Arc<[PathBuf]>,
    changes: tokio::sync::mpsc::Sender<tokio::time::Instant>,
    failures: tokio::sync::mpsc::UnboundedSender<WatcherFailure>,
) -> Result<RecommendedWatcher, (WatcherFailure, notify::Error)> {
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<notify::Event>| match result {
        Ok(event) if affects_watched_paths(&event, &paths) => {
            _ = changes.try_send(tokio::time::Instant::now());
        }
        Ok(_) => {}
        Err(_) => _ = failures.send(WatcherFailure::Notification),
    })
    .map_err(|error| (WatcherFailure::Creation, error))?;
    watcher
        .watch(dir, RecursiveMode::NonRecursive)
        .map_err(|error| (WatcherFailure::Registration, error))?;
    Ok(watcher)
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
    /// Configured paths watch their parent directory non-recursively.
    /// Default-path transition uses separate non-recursive watches and dynamically registers directories as they appear.
    /// Relevant modifications, creations, and removals reload the policy.
    /// The task runs until the shutdown notify is triggered.
    pub(crate) async fn watch(
        self,
        shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<(), WatcherFailure>>,
    ) {
        let store = self.0;
        let paths: Arc<[PathBuf]> = store.watched_paths().into();

        let (change_tx, mut changes) = tokio::sync::mpsc::channel(1);
        let (failure_tx, mut failures) = tokio::sync::mpsc::unbounded_channel();
        let (watcher_command_tx, watcher_command_rx) = std::sync::mpsc::channel();

        let _watcher_handle = tokio::task::spawn_blocking(move || {
            let mut watchers = Vec::new();
            let mut watched_directories = Vec::<PathBuf>::new();
            let register = |watchers: &mut Vec<RecommendedWatcher>, watched_directories: &mut Vec<PathBuf>| {
                for dir in watch_directories(&paths) {
                    if watched_directories
                        .iter()
                        .any(|watched| crate::policy_security::windows_paths_equal(watched, &dir))
                    {
                        continue;
                    }
                    let watcher = create_watcher(&dir, Arc::clone(&paths), change_tx.clone(), failure_tx.clone())
                        .map_err(|(failure, error)| (failure, dir.clone(), error))?;
                    watched_directories.push(dir);
                    watchers.push(watcher);
                }
                Ok::<(), (WatcherFailure, PathBuf, notify::Error)>(())
            };

            if let Err((failure, dir, error)) = register(&mut watchers, &mut watched_directories) {
                error!(%error, path = %dir.display(), "Failed to watch policy directory");
                let _ = ready.send(Err(failure));
                return;
            }

            let _ = ready.send(Ok(()));
            while let Ok(command) = watcher_command_rx.recv() {
                match command {
                    WatcherCommand::Refresh => {
                        watchers.clear();
                        watched_directories.clear();
                        if let Err((failure, dir, error)) = register(&mut watchers, &mut watched_directories) {
                            error!(%error, path = %dir.display(), "Failed to extend policy directory monitoring");
                            let _ = failure_tx.send(failure);
                            return;
                        }
                    }
                    WatcherCommand::Stop => return,
                }
            }
        });

        let debounce = Duration::from_millis(500);
        let mut fallback_poll = tokio::time::interval(Duration::from_secs(30));
        fallback_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        fallback_poll.tick().await;

        let failure = loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break None,
                failure = failures.recv() => break Some(failure.unwrap_or(WatcherFailure::ChannelClosed)),
                _ = fallback_poll.tick() => {
                    _ = store.reload_from_disk(ReloadCause::ExternalChange).await;
                    let _ = watcher_command_tx.send(WatcherCommand::Refresh);
                }
                Some(changed_at) = changes.recv() => {
                    match debounce_change(&mut changes, &mut failures, &shutdown, changed_at + debounce).await {
                        Ok(true) => {
                            _ = store.reload_from_disk(ReloadCause::ExternalChange).await;
                            let _ = watcher_command_tx.send(WatcherCommand::Refresh);
                        }
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
        let _ = watcher_command_tx.send(WatcherCommand::Stop);
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

    #[test]
    fn default_transition_filter_tracks_both_policies_and_managed_state() {
        let managed = PathBuf::from(r"C:\ProgramData\Devolutions\PackageBroker\package-broker-policy.json");
        let legacy = PathBuf::from(r"C:\ProgramData\Devolutions\Agent\package-broker-policy.json");
        let paths = vec![managed.clone(), legacy.clone()];
        let event = |path| notify::Event::new(EventKind::Modify(ModifyKind::Any)).add_path(path);

        assert!(affects_watched_paths(&event(managed.clone()), &paths));
        assert!(affects_watched_paths(&event(legacy), &paths));
        assert!(affects_watched_paths(
            &event(managed.with_file_name(".package-broker-policy.json.txn-id.marker")),
            &paths
        ));
        assert!(affects_watched_paths(
            &event(PathBuf::from(r"C:\ProgramData\Devolutions\PackageBroker")),
            &paths
        ));
        assert!(!affects_watched_paths(
            &event(PathBuf::from(r"C:\ProgramData\Devolutions\Agent\unrelated.json")),
            &paths
        ));
    }

    #[test]
    fn default_transition_watch_root_uses_the_nearest_existing_ancestor() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let missing = dir.path().join("Devolutions").join("PackageBroker");

        assert_eq!(nearest_existing_ancestor(&missing), dir.path());
    }

    #[test]
    fn default_transition_uses_independent_non_recursive_directories() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let common = dir.path().join("Devolutions");
        let managed_dir = common.join("PackageBroker");
        let legacy_dir = common.join("Agent");
        std::fs::create_dir_all(&managed_dir).expect("create managed directory");
        std::fs::create_dir(&legacy_dir).expect("create legacy directory");
        let paths = vec![
            managed_dir.join("package-broker-policy.json"),
            legacy_dir.join("package-broker-policy.json"),
        ];

        let directories = watch_directories(&paths);

        assert_eq!(directories.len(), 3);
        assert!(directories.iter().any(|path| path == &common));
        assert!(directories.iter().any(|path| path == &managed_dir));
        assert!(directories.iter().any(|path| path == &legacy_dir));
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
