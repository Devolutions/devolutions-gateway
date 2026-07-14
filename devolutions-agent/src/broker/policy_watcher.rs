//! Policy file watcher with live reload.
//!
//! Watches the policy file for changes and reloads it when modified.
//! If the file becomes unavailable or corrupted, the broker pauses
//! (denies all requests) until a valid policy is available again.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use now_policy::PolicyDocument;
use tokio::sync::{Notify, watch};
use tracing::{error, info, warn};

use crate::broker::policy_loader;

/// State of the policy: either loaded and active, or unavailable.
#[derive(Debug, Clone)]
pub enum PolicyState {
    /// A valid policy is loaded and active.
    Active(Arc<PolicyDocument>),
    /// The policy file is missing or corrupted; broker should deny all requests.
    Unavailable { reason: String },
}

/// Watches a policy file (JSON or YAML) and sends updates via a channel.
///
/// On startup, attempts to load the policy. If it fails, starts in `Unavailable` state.
/// When the file is modified, reloads it. If reload fails, transitions to `Unavailable`.
/// When a valid file becomes available again, transitions back to `Active`.
pub struct PolicyWatcher {
    path: PathBuf,
    state_tx: watch::Sender<PolicyState>,
}

impl PolicyWatcher {
    /// Create a new watcher for the given policy file path.
    ///
    /// Returns the watcher and a receiver for policy state changes.
    pub fn new(path: PathBuf) -> (Self, watch::Receiver<PolicyState>) {
        let initial_state = match policy_loader::load_policy(&path) {
            Ok(policy) => PolicyState::Active(Arc::new(policy)),
            Err(e) => PolicyState::Unavailable { reason: e.to_string() },
        };

        let (state_tx, state_rx) = watch::channel(initial_state);

        let watcher = Self { path, state_tx };

        (watcher, state_rx)
    }

    /// Start watching the policy file for changes.
    ///
    /// This spawns a background task that watches the policy file's parent directory
    /// and reloads the policy when the file is modified, created, or removed.
    /// The task runs until the shutdown notify is triggered.
    pub async fn watch(self, shutdown: Arc<Notify>) {
        let path = self.path.clone();
        let state_tx = self.state_tx;
        let dir = path.parent().unwrap_or_else(|| Path::new(".")).to_owned();

        let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel::<()>(16);
        let (watcher_stop_tx, watcher_stop_rx) = std::sync::mpsc::channel::<()>();

        // Set up file watcher in a blocking context.
        let watch_path = dir.clone();
        let _watcher_handle = tokio::task::spawn_blocking(move || {
            let rt_tx = fs_tx;
            let mut watcher: RecommendedWatcher =
                match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                    if let Ok(event) = res {
                        // Only react to modify/create/remove events.
                        use notify::EventKind;
                        match event.kind {
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) => {
                                let _ = rt_tx.blocking_send(());
                            }
                            _ => {}
                        }
                    }
                }) {
                    Ok(watcher) => watcher,
                    Err(error) => {
                        error!(%error, "Failed to create policy file watcher");
                        return;
                    }
                };

            if let Err(error) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
                error!(%error, path = %watch_path.display(), "Failed to watch policy directory");
                return;
            }

            let _ = watcher_stop_rx.recv();
        });

        // Debounce interval to avoid rapid reloads.
        let debounce = Duration::from_millis(500);

        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    info!("Policy watcher shutting down");
                    let _ = watcher_stop_tx.send(());
                    break;
                }
                Some(()) = fs_rx.recv() => {
                    // Debounce: drain any additional events that arrived.
                    tokio::time::sleep(debounce).await;
                    while fs_rx.try_recv().is_ok() {}

                    // Attempt reload.
                    match policy_loader::load_policy(&path) {
                        Ok(policy) => {
                            info!(
                                policy_id = %policy.metadata.id,
                                revision = policy.metadata.revision,
                                "Policy reloaded successfully"
                            );
                            let _ = state_tx.send(PolicyState::Active(Arc::new(policy)));
                        }
                        Err(e) => {
                            warn!(error = %e, "Policy reload failed; broker paused");
                            let _ = state_tx.send(PolicyState::Unavailable {
                                reason: e.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}
