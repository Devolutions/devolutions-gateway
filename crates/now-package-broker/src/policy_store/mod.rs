//! Agent-owned, serialized policy store.
//!
//! Owns the configured/resolved policy path, the observed Active/Missing/Invalid state,
//! sanitized diagnostics for an Invalid configuration, the immutable active policy
//! snapshot, opaque store tokens bound to the exact observed disk state (see
//! [`windows::DiskFingerprint`] and [`PolicyStore::token_for`]), keyed validation receipts
//! (see [`receipt::ReceiptKey`]), atomic persistence, and coordinated reload from both the
//! management API and external (out-of-band) edits.
//!
//! Concurrency model: hot reads ([`PolicyStore::snapshot`] and friends) take a brief
//! read-lock only to clone one `Arc` and never touch disk; every disk-touching operation
//! (an API-driven [`PolicyStore::replace`] or a watcher-driven
//! [`PolicyStore::reload_from_disk`]) is serialized through a single `tokio::sync::Mutex`,
//! so an API write and an external-edit reload can never interleave.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use notify::{RecommendedWatcher, RecursiveMode, Watcher as _};
use now_policy::PolicyDocument;
use now_policy_api::{
    ErrorCode, ErrorResponse, InvalidPolicyDiagnostics, PolicyConfigurationSource, PolicyConflictHandling,
    PolicyManagementSnapshot, PolicyManagementState, PolicyReadOnlyReason, PolicyReplacementOperation,
    PolicyReplacementRequest, PolicyStoreToken, PolicyValidationResult, PolicyWriteCapability,
};
use tokio_util::sync::CancellationToken;
use win_api_wrappers::identity::sid::Sid;

use crate::audit;
use crate::server::responses::{
    error_response, error_response_with_management, policy_read_only_error_code, stale_token_response,
    validation_error_response,
};

mod receipt;
pub mod validation;
mod windows;

/// Storage backend used by [`PolicyStore`] for every disk-touching operation.
///
/// Abstracted so unit tests can inject an in-memory fake and exercise the store's
/// transactional logic (token comparison, revision planning, validation-receipt/warning
/// gating, snapshot swaps, audit calls) deterministically and without requiring the real
/// SYSTEM/Administrators-only ACL enforcement that production storage depends on.
trait PolicyStorage: Send + Sync {
    /// Observe the exact current disk state of the configured policy path, including
    /// the write capability resolved as part of that same observation (see
    /// `windows::DiskObservation`, item 20/26): capability is never derived from a
    /// separately cached snapshot, so it can never silently drift from the state it
    /// describes.
    fn observe(&self, source: PolicyConfigurationSource, path: &Path) -> windows::DiskObservation;
    /// Observe for a replacement transaction, retaining the exact target handle when one exists.
    fn observe_for_write(&self, source: PolicyConfigurationSource, path: &Path) -> windows::DiskObservation {
        self.observe(source, path)
    }
    fn atomic_replace(
        &self,
        hosting_dir: &windows::VerifiedHostingDirectory,
        observed_target: Option<windows::RetainedPolicyFile>,
        expected_fingerprint: &windows::DiskFingerprint,
        final_path: &Path,
        bytes: &[u8],
    ) -> Result<windows::PersistedPolicy, windows::WriteFailure>;
    /// Same as [`PolicyStorage::atomic_replace`], but must never overwrite an existing
    /// destination (used for `Create`; see `windows::atomic_create`).
    fn atomic_create(
        &self,
        hosting_dir: &windows::VerifiedHostingDirectory,
        final_path: &Path,
        bytes: &[u8],
    ) -> Result<windows::PersistedPolicy, windows::WriteFailure>;
}

/// Production storage backend: the real Windows filesystem/ACL implementation.
struct WindowsPolicyStorage {
    /// Caches the one-time, side-effecting filesystem atomic-replace capability probe
    /// (see `windows::AtomicityProbeCache`); shared across every observation this store
    /// makes for the lifetime of the process.
    probe_cache: windows::AtomicityProbeCache,
}

impl WindowsPolicyStorage {
    fn new() -> Self {
        Self {
            probe_cache: windows::AtomicityProbeCache::new(),
        }
    }
}

impl PolicyStorage for WindowsPolicyStorage {
    fn observe(&self, source: PolicyConfigurationSource, path: &Path) -> windows::DiskObservation {
        windows::observe(source, path, &self.probe_cache)
    }

    fn observe_for_write(&self, source: PolicyConfigurationSource, path: &Path) -> windows::DiskObservation {
        windows::observe_for_write(source, path, &self.probe_cache)
    }

    fn atomic_replace(
        &self,
        hosting_dir: &windows::VerifiedHostingDirectory,
        observed_target: Option<windows::RetainedPolicyFile>,
        expected_fingerprint: &windows::DiskFingerprint,
        final_path: &Path,
        bytes: &[u8],
    ) -> Result<windows::PersistedPolicy, windows::WriteFailure> {
        windows::atomic_replace(hosting_dir, observed_target, expected_fingerprint, final_path, bytes)
    }

    fn atomic_create(
        &self,
        hosting_dir: &windows::VerifiedHostingDirectory,
        final_path: &Path,
        bytes: &[u8],
    ) -> Result<windows::PersistedPolicy, windows::WriteFailure> {
        windows::atomic_create(hosting_dir, final_path, bytes)
    }
}

/// Identity of the pipe client attempting a policy write, threaded through purely for
/// audit logging; authorization itself (signature, elevation, Administrators membership)
/// is already decided by the caller before reaching [`PolicyStore::replace`].
pub struct PolicyWriteActor<'a> {
    pub sid: &'a Sid,
    pub executable: &'a Path,
}

/// Successful outcome of [`PolicyStore::replace`].
#[derive(Debug)]
pub struct ReplaceSuccess {
    pub policy: PolicyDocument,
    pub validation: PolicyValidationResult,
    pub management: PolicyManagementSnapshot,
}

/// Immutable internal snapshot backing the store; swapped atomically as a whole so
/// readers never observe a partially updated state.
struct Snapshot {
    state: PolicyManagementState,
    write_capability: PolicyWriteCapability,
    read_only_reason: Option<PolicyReadOnlyReason>,
    policy: Option<Arc<PolicyDocument>>,
    invalid_diagnostics: Option<InvalidPolicyDiagnostics>,
    store_token: PolicyStoreToken,
    /// Internal identity the published `store_token` is bound to; never itself exposed.
    /// See [`PolicyStore::token_for`].
    fingerprint: windows::DiskFingerprint,
    /// Canonical path resolved by the observation this snapshot was published from (see
    /// item 22): the *only* path value used for display (`configured_path` in
    /// [`PolicyManagementSnapshot`]), audit, and writes from that point on. Never
    /// re-derived from the original configuration string once an observation has run.
    canonical_path: PathBuf,
}

/// Serialized, transactional store for the configured package-broker policy.
pub struct PolicyStore {
    /// The literal configured (or default) path, exactly as configured: the fixed input
    /// fed to every [`PolicyStorage::observe`] call. Never itself displayed, audited, or
    /// used for a write; see [`Snapshot::canonical_path`] for the value that is.
    configured_path: PathBuf,
    source: PolicyConfigurationSource,
    snapshot: std::sync::RwLock<Arc<Snapshot>>,
    /// Serializes every disk-touching operation: API-driven replacement and
    /// watcher-driven reload from an external edit.
    write_lock: tokio::sync::Mutex<()>,
    storage: Arc<dyn PolicyStorage>,
    /// Process-random key binding every validation receipt this store issues; see
    /// [`PolicyStore::validate_draft`].
    receipt_key: receipt::ReceiptKey,
}

impl PolicyStore {
    /// Resolve the configured path, create/secure the default directory (or verify a
    /// custom one without rewriting it), and observe the current disk state.
    ///
    /// Never fails: any resolution or observation problem is reflected in the returned
    /// store's state/capability instead (fail-closed, matching the broker's existing
    /// pause-on-problem philosophy).
    pub fn load(configured_path: Option<PathBuf>) -> Arc<Self> {
        Self::load_with_storage(configured_path, Arc::new(WindowsPolicyStorage::new()))
    }

    fn load_with_storage(configured_path: Option<PathBuf>, storage: Arc<dyn PolicyStorage>) -> Arc<Self> {
        let (configured_path, source) = match configured_path {
            Some(path) => (path, PolicyConfigurationSource::ConfiguredPath),
            None => (windows::default_policy_path(), PolicyConfigurationSource::DefaultPath),
        };

        let observation = storage.observe(source, &configured_path);
        if observation.write_capability != PolicyWriteCapability::Writable {
            tracing::warn!(
                path = %observation.canonical_path.display(),
                write_capability = ?observation.write_capability,
                read_only_reason = ?observation.read_only_reason,
                "Policy directory is not writable through the management API"
            );
        }
        match &observation.state {
            PolicyManagementState::Active => {
                let policy = observation
                    .policy
                    .as_ref()
                    .expect("Active observation always carries a policy");
                tracing::info!(
                    policy_id = %policy.metadata.id,
                    revision = policy.metadata.revision,
                    path = %observation.canonical_path.display(),
                    "Loaded package broker policy"
                );
            }
            PolicyManagementState::Missing => {
                tracing::warn!(
                    path = %observation.canonical_path.display(),
                    "No configured policy found; broker will pause until one is created through the management API"
                );
            }
            PolicyManagementState::Invalid => {
                tracing::warn!(
                    path = %observation.canonical_path.display(),
                    "Configured policy is invalid; broker will pause until it is repaired through the management API"
                );
            }
        }

        // First observation ever made by this store: there is no previous fingerprint to
        // compare against, so a fresh token is always minted (see `token_for`).
        let store_token = windows::random_store_token();

        let snapshot = Arc::new(Snapshot {
            state: observation.state,
            write_capability: observation.write_capability,
            read_only_reason: observation.read_only_reason,
            policy: observation.policy.map(Arc::new),
            invalid_diagnostics: observation.invalid_diagnostics,
            store_token,
            fingerprint: observation.fingerprint,
            canonical_path: observation.canonical_path,
        });

        Arc::new(Self {
            configured_path,
            source,
            snapshot: std::sync::RwLock::new(snapshot),
            write_lock: tokio::sync::Mutex::new(()),
            storage,
            receipt_key: receipt::ReceiptKey::generate(),
        })
    }

    /// Cheap hot-path read: clones one `Arc` under a brief read-lock, never touches disk.
    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.snapshot.read().expect("policy store snapshot lock poisoned"))
    }

    /// Resolve the opaque token for a freshly observed `fingerprint`, given the
    /// previously published snapshot to compare it against.
    ///
    /// This is the *only* place a [`PolicyStoreToken`] is ever produced: reusing
    /// `previous`'s token when the fingerprint did not change, minting and remembering a
    /// fresh process-random one ([`windows::random_store_token`]) otherwise. Tokens never
    /// encode or derive from the fingerprint's content, so they cannot be correlated with
    /// file content/identity by an outside observer, and are stable only for as long as
    /// the exact observed disk state (content, identity, security) does not change.
    fn token_for(previous: &Snapshot, fingerprint: &windows::DiskFingerprint) -> PolicyStoreToken {
        if previous.fingerprint == *fingerprint {
            previous.store_token.clone()
        } else {
            windows::random_store_token()
        }
    }

    /// Authoritatively (re)validate raw draft JSON and, if valid, bind a keyed receipt
    /// under this store's own process-random key.
    ///
    /// This is the *only* place a validation receipt is ever issued or accepted: both
    /// `POST /v1/policy/validate` and the `PUT /v1/policy` replacement transaction call
    /// this same method (see [`PolicyStore::replace`]), so they always bind against the
    /// exact same key.
    pub fn validate_draft(&self, raw: &serde_json::Value) -> PolicyValidationResult {
        let mut result = validation::validate_draft(raw);
        if let Some(canonical_draft) = &result.canonical_draft {
            result.validation_receipt = Some(self.receipt_key.issue(
                &result.validator_version,
                canonical_draft,
                &result.findings,
            ));
        }
        result
    }

    /// The currently active policy, or `None` when the broker is paused
    /// (Missing/Invalid configured policy).
    pub fn active_policy(&self) -> Option<Arc<PolicyDocument>> {
        self.snapshot().policy.clone()
    }

    /// Build a store with no disk backing, for unit tests exercising `BrokerState`
    /// request handling (evaluate/execute/status/cancel) without touching the
    /// filesystem. Never used outside `#[cfg(test)]`.
    #[cfg(test)]
    pub(crate) fn for_tests(policy: Option<PolicyDocument>) -> Arc<Self> {
        let (state, fingerprint) = match &policy {
            Some(policy) => (
                PolicyManagementState::Active,
                windows::DiskFingerprint::test_active(
                    &serde_json::to_vec(policy).expect("test policy serializes"),
                    0,
                    0,
                    0,
                    0,
                ),
            ),
            None => (
                PolicyManagementState::Missing,
                windows::DiskFingerprint::test_missing(0, 0),
            ),
        };
        let snapshot = Arc::new(Snapshot {
            state,
            write_capability: PolicyWriteCapability::Writable,
            read_only_reason: None,
            policy: policy.map(Arc::new),
            invalid_diagnostics: None,
            store_token: windows::random_store_token(),
            fingerprint,
            canonical_path: PathBuf::from("test-policy.json"),
        });

        Arc::new(Self {
            configured_path: PathBuf::from("test-policy.json"),
            source: PolicyConfigurationSource::DefaultPath,
            snapshot: std::sync::RwLock::new(snapshot),
            write_lock: tokio::sync::Mutex::new(()),
            storage: Arc::new(tests::FakePolicyStorage::writable()),
            receipt_key: receipt::ReceiptKey::generate(),
        })
    }

    /// Build a store backed entirely by an injected [`PolicyStorage`], for unit tests
    /// exercising the full `replace`/`reload_from_disk` transactional logic (token
    /// comparison, revision planning, validation-receipt/warning gating, persistence
    /// failures) deterministically and without the real SYSTEM/Administrators-only ACL
    /// enforcement that production storage depends on.
    #[cfg(test)]
    pub(crate) fn for_tests_with_storage(storage: Arc<tests::FakePolicyStorage>) -> Arc<Self> {
        Self::load_with_storage(Some(PathBuf::from(r"C:\fake\package-broker-policy.json")), storage)
    }

    /// Directly (synchronously) swap the active policy, bypassing the write lock and
    /// disk entirely. Only used to exercise the hot-read Arc-swap concurrency guarantee
    /// in unit tests; production code always goes through [`PolicyStore::replace`].
    #[cfg(test)]
    pub(crate) fn test_set_active(&self, policy: Arc<PolicyDocument>) {
        let fingerprint = windows::DiskFingerprint::test_active(
            &serde_json::to_vec(&*policy).expect("test policy serializes"),
            0,
            0,
            0,
            0,
        );
        let canonical_path = self.snapshot().canonical_path.clone();
        let snapshot = Arc::new(Snapshot {
            state: PolicyManagementState::Active,
            write_capability: PolicyWriteCapability::Writable,
            read_only_reason: None,
            policy: Some(policy),
            invalid_diagnostics: None,
            store_token: windows::random_store_token(),
            fingerprint,
            canonical_path,
        });
        *self.snapshot.write().expect("policy store snapshot lock poisoned") = snapshot;
    }

    /// Atomic view of configured policy state and management guidance, suitable for
    /// `GET /v1/policy/management` and for `ErrorResponse::management`.
    pub fn management_snapshot(&self) -> PolicyManagementSnapshot {
        let snapshot = self.snapshot();
        PolicyManagementSnapshot {
            state: snapshot.state,
            configured_path: snapshot.canonical_path.display().to_string(),
            store_token: snapshot.store_token.clone(),
            source: self.source,
            write_capability: snapshot.write_capability,
            read_only_reason: snapshot.read_only_reason,
            // Writes always require an elevated, Administrators-member token regardless of
            // write capability; see `crate::auth`.
            elevation_required: true,
            policy: snapshot.policy.as_deref().cloned(),
            invalid_diagnostics: snapshot.invalid_diagnostics.clone(),
        }
    }

    /// Re-observe the configured policy file after an external (out-of-band) change and
    /// adopt it if it differs from the current snapshot.
    ///
    /// Serialized with [`PolicyStore::replace`] through the same write lock. A bad
    /// external edit can legitimately transition the store to Invalid/paused (unlike a
    /// self-replacement through the management API, which never pauses the broker: it
    /// only ever commits an already-validated document).
    pub async fn reload_from_disk(&self, cause: &str) {
        let _guard = self.write_lock.lock().await;
        let observation = self.storage.observe(self.source, &self.configured_path);
        self.publish_if_changed(observation, cause);
    }

    /// Reconcile the store's published snapshot with a freshly observed disk state,
    /// swapping it in when disk identity or capability differs from the published snapshot.
    /// Policy-change auditing occurs only when the fingerprint changes.
    /// Returns the resulting authoritative management snapshot.
    ///
    /// Write capability is always taken from this fresh `observation`, never carried
    /// forward from the previous snapshot (item 20): a directory that became writable or
    /// unwritable since the last observation must be reflected immediately, not only the
    /// next time something else about the disk state happens to change too.
    ///
    /// Must be called while holding `write_lock`.
    fn publish_if_changed(&self, observation: windows::DiskObservation, cause: &str) -> PolicyManagementSnapshot {
        let previous = self.snapshot();

        if observation.fingerprint == previous.fingerprint
            && observation.write_capability == previous.write_capability
            && observation.read_only_reason == previous.read_only_reason
        {
            // No real change: either a spurious filesystem event, this reload was
            // triggered by our own just-applied write (which already swapped the
            // snapshot before releasing the lock), or (from `replace`'s stale-token
            // check) the caller's own idea of the token was simply wrong, not the
            // store's.
            return self.management_snapshot();
        }

        let policy_changed = observation.fingerprint != previous.fingerprint;
        let store_token = Self::token_for(&previous, &observation.fingerprint);
        let new_snapshot = Arc::new(Snapshot {
            state: observation.state,
            write_capability: observation.write_capability,
            read_only_reason: observation.read_only_reason,
            policy: observation.policy.map(Arc::new),
            invalid_diagnostics: observation.invalid_diagnostics,
            store_token,
            fingerprint: observation.fingerprint,
            canonical_path: observation.canonical_path,
        });

        if policy_changed {
            match (&new_snapshot.state, &new_snapshot.policy) {
                (PolicyManagementState::Active, Some(policy)) => {
                    tracing::info!(
                        policy_id = %policy.metadata.id,
                        revision = policy.metadata.revision,
                        %cause,
                        "External policy change applied; broker resumed/updated"
                    );
                    audit::external_change_applied(
                        &new_snapshot.canonical_path,
                        &policy.metadata.id,
                        policy.metadata.revision,
                    );
                }
                (state, _) => {
                    tracing::warn!(?state, %cause, "External policy change left the configured policy unavailable");
                    audit::external_change_rejected(&new_snapshot.canonical_path, &format!("{state:?}"));
                }
            }
        }

        *self.snapshot.write().expect("policy store snapshot lock poisoned") = new_snapshot;

        self.management_snapshot()
    }

    /// Default interval for the periodic disk re-observation fallback (item 19/29):
    /// runs unconditionally alongside the event-driven filesystem watcher below, so an
    /// external change is eventually detected even if OS-level watch setup/registration
    /// fails outright, the watcher terminates unexpectedly at runtime, or an individual
    /// notification is lost (e.g. an OS-level notification buffer overflow, reported by
    /// `notify` as a callback `Err`). Short enough that an operator waiting for a
    /// external repair to take effect notices quickly; negligible overhead otherwise
    /// (a single cheap re-observation, most of which is already fast/side-effect-free).
    const FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(30);

    /// Watch the configured policy file's parent directory and reload on external
    /// changes. Runs until `shutdown` is triggered.
    pub async fn watch(self: Arc<Self>, shutdown: CancellationToken) {
        self.watch_with_poll_interval(shutdown, Self::FALLBACK_POLL_INTERVAL)
            .await;
    }

    /// Same as [`PolicyStore::watch`], but with an injectable poll interval: the seam a
    /// unit test uses to prove the periodic fallback alone -- independent of whether OS
    /// filesystem notification delivery works at all in the test environment --
    /// eventually reflects an external change (item 19).
    async fn watch_with_poll_interval(self: Arc<Self>, shutdown: CancellationToken, poll_interval: Duration) {
        let dir = self
            .snapshot()
            .canonical_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_owned();

        // Bounded, but the sending side below always uses `blocking_send` (which blocks
        // for capacity) rather than `try_send`, so a burst of events can never be
        // silently discarded by this channel filling up (item 29): the debounced
        // consumer below just coalesces a backlog into a single re-observation once it
        // catches up, exactly as it already does for a single event.
        let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel::<()>(16);
        let (watcher_stop_tx, watcher_stop_rx) = std::sync::mpsc::channel::<()>();

        let watch_path = dir.clone();
        let _watcher_handle = tokio::task::spawn_blocking(move || {
            let rt_tx = fs_tx;
            let mut watcher: RecommendedWatcher =
                match notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
                    Ok(event) => {
                        use notify::EventKind;
                        if matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                        ) {
                            // Do not filter reserved transaction names because this callback cannot verify their identity or security.
                            // The write lock and debounce coalesce legitimate internal transaction events.
                            let _ = rt_tx.blocking_send(());
                        }
                    }
                    Err(error) => {
                        // A watcher callback error can mean lost or overflowed events
                        // (e.g. the OS-level notification buffer overflowed): silently
                        // ignoring it (item 29) could leave the store serving a stale
                        // snapshot indefinitely once event delivery quietly resumes.
                        // Force an immediate re-observation, the same as an observed
                        // change, rather than only relying on the next real event or the
                        // periodic fallback poll to eventually notice. Never logs the
                        // notify-internal error's own content as anything but an opaque
                        // diagnostic string; there is no policy content involved here.
                        tracing::warn!(%error, "Policy directory watcher reported an error; forcing re-observation");
                        let _ = rt_tx.blocking_send(());
                    }
                }) {
                    Ok(watcher) => watcher,
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "Failed to create policy file watcher; \
                             relying solely on the periodic fallback poll to detect external changes"
                        );
                        return;
                    }
                };

            if let Err(error) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
                tracing::error!(
                    %error, path = %watch_path.display(),
                    "Failed to watch policy directory; \
                     relying solely on the periodic fallback poll to detect external changes"
                );
                return;
            }

            let _ = watcher_stop_rx.recv();
        });

        let debounce = Duration::from_millis(500);
        let mut poll_timer = tokio::time::interval(poll_interval);
        poll_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; the store was already observed once at
        // construction, so skip it to avoid a redundant reobservation on startup.
        poll_timer.tick().await;

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("Policy store watcher shutting down");
                    let _ = watcher_stop_tx.send(());
                    break;
                }
                Some(()) = fs_rx.recv() => {
                    tokio::time::sleep(debounce).await;
                    while fs_rx.try_recv().is_ok() {}
                    self.reload_from_disk("external file system event").await;
                }
                _ = poll_timer.tick() => {
                    self.reload_from_disk("periodic fallback poll").await;
                }
            }
        }
    }

    /// Authoritatively replace the configured policy in a single serialized transaction.
    ///
    /// Reparses/revalidates the raw draft from scratch (never trusting the caller's own
    /// validation), reobserves disk state under the write lock, compares the expected
    /// store token, applies the operation's identity/revision rule, and only then
    /// persists atomically. A failure at any step leaves the previously active policy
    /// (if any) untouched and serving.
    pub async fn replace(
        &self,
        request: PolicyReplacementRequest,
        actor: PolicyWriteActor<'_>,
    ) -> Result<ReplaceSuccess, ErrorResponse> {
        let intent = format!("{:?}", request.operation);

        let _guard = self.write_lock.lock().await;

        let previous = self.snapshot();
        let mut observation = self.storage.observe_for_write(self.source, &self.configured_path);
        let current_token = Self::token_for(&previous, &observation.fingerprint);
        // The canonical path resolved by *this* observation (item 22): every audit/write
        // call below uses only this value, never `self.configured_path` (the literal,
        // possibly non-canonical configuration string) or a value cached from a previous
        // transaction.
        let canonical_path = observation.canonical_path.clone();

        if current_token != request.expected_store_token {
            audit::write_conflict(actor.sid, actor.executable, &intent, &canonical_path);
            let management = self.publish_if_changed(observation, "replacement observed a stale store token");
            return Err(stale_token_response(
                "the configured policy has changed since the expected store token was observed; \
                 retry with the current management snapshot's store token"
                    .to_owned(),
                management,
            ));
        }

        // The directory's write capability was resolved as part of this exact same
        // observation (item 20), so it is already as fresh as any capability check right
        // before writing could be -- re-observing a second time here would only
        // reintroduce the two-separate-observations inconsistency item 20 removes.
        if observation.write_capability != PolicyWriteCapability::Writable {
            let message = match &observation.read_only_reason {
                Some(reason) => format!("the configured policy path is not currently writable ({reason:?})"),
                None => "the configured policy path is not currently writable".to_owned(),
            };
            audit::write_failed(actor.sid, actor.executable, &intent, &canonical_path, &message);
            // Preserve storage error semantics rather than collapsing every reason into
            // one code (item 31): see `responses::policy_read_only_error_code`.
            return Err(error_response(
                policy_read_only_error_code(observation.read_only_reason),
                message,
            ));
        }

        let validation = self.validate_draft(&request.draft);

        if !validation.is_valid {
            audit::write_failed(
                actor.sid,
                actor.executable,
                &intent,
                &canonical_path,
                "authoritative revalidation of the submitted draft failed",
            );
            return Err(validation_error_response(
                ErrorCode::InvalidPolicy,
                "the submitted draft failed authoritative revalidation",
                validation,
            ));
        }

        let canonical_draft = validation
            .canonical_draft
            .clone()
            .expect("a valid PolicyValidationResult always carries a canonical draft");

        // Constant-time: a receipt is a security credential (proof of authoritative
        // revalidation), and comparing it with `==` would leak timing information about
        // how many leading bytes of a forged candidate happened to match.
        let receipt_valid = self.receipt_key.verify(
            &validation.validator_version,
            &canonical_draft,
            &validation.findings,
            &request.validation_receipt,
        );
        if !receipt_valid {
            audit::write_failed(
                actor.sid,
                actor.executable,
                &intent,
                &canonical_path,
                "validation receipt does not match the draft's current authoritative validation",
            );
            return Err(validation_error_response(
                ErrorCode::ValidationFailed,
                "validation receipt does not match the current authoritative validation of this draft; \
                 re-validate and retry",
                validation,
            ));
        }

        if !validation.findings.is_empty() && !request.warnings_acknowledged {
            audit::write_failed(
                actor.sid,
                actor.executable,
                &intent,
                &canonical_path,
                "validation warnings were not acknowledged",
            );
            return Err(validation_error_response(
                ErrorCode::WarningConfirmationRequired,
                "the draft produced validation warnings that must be explicitly acknowledged",
                validation,
            ));
        }

        let new_id: &str = &canonical_draft.metadata.id;

        let new_revision = match plan_revision(
            request.operation,
            observation.state,
            observation.policy.as_ref(),
            new_id,
        ) {
            Ok(revision) => revision,
            Err(message) => {
                audit::write_failed(actor.sid, actor.executable, &intent, &canonical_path, &message);
                return Err(error_response(ErrorCode::Conflict, message));
            }
        };

        let published_at = Utc::now();
        let final_policy = match canonical_draft.into_policy_document(new_revision, published_at) {
            Ok(policy) => policy,
            Err(model_error) => {
                let message = model_error.to_string();
                audit::write_failed(actor.sid, actor.executable, &intent, &canonical_path, &message);
                return Err(error_response(ErrorCode::ValidationFailed, message));
            }
        };

        let bytes = serde_json::to_vec_pretty(&final_policy).expect("BUG: PolicyDocument always serializes");
        let hosting_dir = observation
            .hosting_dir
            .as_ref()
            .expect("BUG: a writable observation always carries its verified hosting directory");

        // `Create` must never replace an unexpectedly-reappeared destination (see
        // `windows::atomic_create`); every other operation already observed an
        // Active/Invalid document above and intentionally replaces it.
        let write_result = if request.operation == PolicyReplacementOperation::Create {
            self.storage.atomic_create(hosting_dir, &canonical_path, &bytes)
        } else {
            self.storage.atomic_replace(
                hosting_dir,
                observation.retained_target.take(),
                &observation.fingerprint,
                &canonical_path,
                &bytes,
            )
        };
        let persisted = match write_result {
            Ok(persisted) => persisted,
            Err(windows::WriteFailure::PrePublication(io_error)) => {
                let message = format!("{io_error:#}");
                audit::write_failed(actor.sid, actor.executable, &intent, &canonical_path, &message);

                let reobservation = self.storage.observe(self.source, &self.configured_path);
                if reobservation.fingerprint != observation.fingerprint {
                    let management =
                        self.publish_if_changed(reobservation, "policy storage changed before publication");
                    return Err(stale_token_response(
                        "the configured policy storage changed while attempting to write; \
                         retry with the current management snapshot's store token"
                            .to_owned(),
                        management,
                    ));
                }

                return Err(error_response(
                    ErrorCode::PolicyPersistenceFailed,
                    format!("failed to persist the policy: {message}"),
                ));
            }
            Err(windows::WriteFailure::ConcurrentChange(io_error)) => {
                tracing::warn!(
                    path = %canonical_path.display(),
                    error = %format!("{io_error:#}"),
                    "Policy replacement could not complete conditional publication"
                );
                let reobservation = self.storage.observe(self.source, &self.configured_path);
                if reobservation.fingerprint == observation.fingerprint {
                    audit::write_failed(
                        actor.sid,
                        actor.executable,
                        &intent,
                        &canonical_path,
                        "conditional publication failed without an observed storage change",
                    );
                    return Err(error_response(
                        ErrorCode::PolicyPersistenceFailed,
                        "failed to conditionally persist the policy",
                    ));
                }
                audit::write_conflict(actor.sid, actor.executable, &intent, &canonical_path);
                let management = self.publish_if_changed(reobservation, "policy storage changed during publication");
                return Err(stale_token_response(
                    "the configured policy changed while attempting to publish the replacement; \
                     retry with the current management snapshot's store token"
                        .to_owned(),
                    management,
                ));
            }
            Err(windows::WriteFailure::PostPublication(io_error)) => {
                // The atomic rename already made the new content live: whatever the
                // in-memory `previous` snapshot claimed, disk has already changed. Never
                // report `PolicyPersistenceFailed` here (it would falsely imply nothing
                // happened): synchronously reobserve and publish the actual current disk
                // state under this same lock (item 27) before returning, so a subsequent
                // `GET` is never left showing a stale "previous policy still active"
                // snapshot until the watcher or fallback poll happens to catch up.
                let message = format!("{io_error:#}");
                audit::write_failed(actor.sid, actor.executable, &intent, &canonical_path, &message);
                let reobservation = self.storage.observe(self.source, &self.configured_path);
                let management = self.publish_if_changed(reobservation, "post-write verification failed");
                // Item 27: the shared `ErrorResponse.management` field is generic, so the
                // snapshot this transaction just republished is attached directly rather
                // than making the caller issue an immediate follow-up `GET` to learn what
                // this request already observed.
                return Err(error_response_with_management(
                    ErrorCode::PolicyActivationFailed,
                    format!("the policy was written but could not be activated: {message}"),
                    management,
                ));
            }
        };

        let old_id = observation.policy.as_ref().map(|policy| policy.metadata.id.to_string());
        let old_revision = observation.policy.as_ref().map(|policy| policy.metadata.revision);

        let new_snapshot = Arc::new(Snapshot {
            state: PolicyManagementState::Active,
            write_capability: observation.write_capability,
            read_only_reason: observation.read_only_reason,
            policy: Some(Arc::new(persisted.policy.clone())),
            invalid_diagnostics: None,
            store_token: Self::token_for(&previous, &persisted.fingerprint),
            fingerprint: persisted.fingerprint,
            canonical_path: canonical_path.clone(),
        });
        *self.snapshot.write().expect("policy store snapshot lock poisoned") = new_snapshot;

        let old_id_display = old_id.as_deref().unwrap_or("<none>");
        if request.conflict_handling == PolicyConflictHandling::ConfirmOverwrite {
            audit::write_confirmed_overwrite(
                actor.sid,
                actor.executable,
                &intent,
                &canonical_path,
                old_id_display,
                old_revision,
                &persisted.policy.metadata.id,
                new_revision,
            );
        } else {
            audit::write_succeeded(
                actor.sid,
                actor.executable,
                &intent,
                &canonical_path,
                old_id_display,
                old_revision,
                &persisted.policy.metadata.id,
                new_revision,
            );
        }

        Ok(ReplaceSuccess {
            policy: persisted.policy,
            validation,
            management: self.management_snapshot(),
        })
    }
}

/// Determine the target revision for a replacement operation, validating the
/// operation's identity/state precondition against the current disk observation.
fn plan_revision(
    operation: PolicyReplacementOperation,
    current_state: PolicyManagementState,
    current_policy: Option<&PolicyDocument>,
    new_id: &str,
) -> Result<u32, String> {
    match operation {
        PolicyReplacementOperation::Update => {
            let policy = current_policy.ok_or_else(|| "Update requires an Active configured policy".to_owned())?;
            let current_id: &str = &policy.metadata.id;
            if current_id != new_id {
                return Err(format!(
                    "Update requires the same policy id ('{current_id}'); the draft specifies '{new_id}'"
                ));
            }
            if policy.metadata.revision >= 2_147_483_647 {
                return Err("policy revision has reached the maximum supported value (2147483647)".to_owned());
            }
            policy
                .metadata
                .revision
                .checked_add(1)
                .ok_or_else(|| "policy revision would overflow".to_owned())
        }
        PolicyReplacementOperation::ReplaceIdentity => {
            let policy =
                current_policy.ok_or_else(|| "ReplaceIdentity requires an Active configured policy".to_owned())?;
            let current_id: &str = &policy.metadata.id;
            if current_id == new_id {
                return Err(format!(
                    "ReplaceIdentity requires a different policy id than the active '{current_id}'"
                ));
            }
            Ok(1)
        }
        PolicyReplacementOperation::Create => {
            if current_state != PolicyManagementState::Missing {
                return Err("Create requires no existing configured policy".to_owned());
            }
            Ok(1)
        }
        PolicyReplacementOperation::Repair => {
            if current_state != PolicyManagementState::Invalid {
                return Err("Repair requires an Invalid configured policy".to_owned());
            }
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    // Disambiguated from the local `windows` submodule (`policy_store::windows`), which
    // `use super::*` also brings into scope.
    use now_policy_api::{
        API_VERSION_STR, PolicyConflictHandling, PolicyReplacementOperation, PolicyReplacementRequestKind,
        PolicyStoreToken, PolicyWriteCapability,
    };

    use super::*;
    use crate::test_support::system_sid;

    /// In-memory [`PolicyStorage`] fake letting tests drive [`PolicyStore::replace`] and
    /// [`PolicyStore::reload_from_disk`] deterministically, without requiring the real
    /// SYSTEM/Administrators-only ACL enforcement that `WindowsPolicyStorage` depends on.
    ///
    /// Tracks three independent "generation" counters standing in for the real
    /// [`windows::DiskFingerprint`]'s identity components: `target_generation` (the policy
    /// file object itself), `parent_generation` (its hosting directory), and
    /// `acl_generation` (its security state). Each is bumped only by an operation that
    /// should plausibly rotate the opaque store token, letting tests exercise every
    /// `DiskFingerprint` rotation/stability rule without a real filesystem.
    pub(crate) struct FakePolicyStorage {
        write_capability: std::sync::Mutex<PolicyWriteCapability>,
        read_only_reason: std::sync::Mutex<Option<PolicyReadOnlyReason>>,
        disk: std::sync::Mutex<Option<Vec<u8>>>,
        /// When set, the *next* (and every subsequent, until a successful write clears
        /// it) observation of an existing target reports it as insecure (item 26):
        /// forces `ReadOnly`/`UnsafePath` regardless of the directory's own
        /// `write_capability`, simulating a file whose own ACL is untrustworthy even
        /// though its hosting directory is fine (so Repair must still be blocked).
        target_insecure: std::sync::Mutex<bool>,
        fail_next_write: std::sync::Mutex<Option<String>>,
        fail_next_concurrent_check: std::sync::Mutex<Option<String>>,
        /// Same shape as `fail_next_write`, but simulates a failure discovered only
        /// *after* the atomic rename already made the new content live (item 27): the
        /// fake's `write` still applies the write to `disk` before returning this error,
        /// so tests can observe that the store re-observes and publishes that already-changed
        /// reality rather than assuming the previous snapshot is still current.
        fail_next_write_post_publication: std::sync::Mutex<Option<String>>,
        race_next_write: std::sync::Mutex<Option<Vec<u8>>>,
        race_directory_before_write: std::sync::Mutex<bool>,
        race_directory_after_publish: std::sync::Mutex<bool>,
        target_generation: std::sync::Mutex<u32>,
        parent_generation: std::sync::Mutex<u32>,
        acl_generation: std::sync::Mutex<u32>,
        dir_acl_generation: std::sync::Mutex<u32>,
    }

    impl FakePolicyStorage {
        pub(crate) fn writable() -> Self {
            Self::with_capability(PolicyWriteCapability::Writable, None)
        }

        fn read_only(reason: PolicyReadOnlyReason) -> Self {
            Self::with_capability(PolicyWriteCapability::ReadOnly, Some(reason))
        }

        fn with_capability(
            write_capability: PolicyWriteCapability,
            read_only_reason: Option<PolicyReadOnlyReason>,
        ) -> Self {
            Self {
                write_capability: std::sync::Mutex::new(write_capability),
                read_only_reason: std::sync::Mutex::new(read_only_reason),
                disk: std::sync::Mutex::new(None),
                target_insecure: std::sync::Mutex::new(false),
                fail_next_write: std::sync::Mutex::new(None),
                fail_next_concurrent_check: std::sync::Mutex::new(None),
                fail_next_write_post_publication: std::sync::Mutex::new(None),
                race_next_write: std::sync::Mutex::new(None),
                race_directory_before_write: std::sync::Mutex::new(false),
                race_directory_after_publish: std::sync::Mutex::new(false),
                target_generation: std::sync::Mutex::new(0),
                parent_generation: std::sync::Mutex::new(0),
                acl_generation: std::sync::Mutex::new(0),
                dir_acl_generation: std::sync::Mutex::new(0),
            }
        }

        /// Set the on-disk content, bumping `target_generation`: every write (through the
        /// store or, as here, simulating an out-of-band external edit) is a new file
        /// object, even when it happens to write byte-identical content.
        fn set_disk(&self, content: Option<Vec<u8>>) {
            *self.disk.lock().expect("disk lock poisoned") = content;
            *self.target_generation.lock().expect("target generation lock poisoned") += 1;
        }

        fn seed(&self, policy: &PolicyDocument) {
            let bytes = serde_json::to_vec(policy).expect("test policy serializes");
            self.set_disk(Some(bytes));
        }

        fn seed_invalid(&self, bytes: impl Into<Vec<u8>>) {
            self.set_disk(Some(bytes.into()));
        }

        fn fail_next_write(&self, message: &str) {
            *self.fail_next_write.lock().expect("fail lock poisoned") = Some(message.to_owned());
        }

        fn fail_next_concurrent_check(&self, message: &str) {
            *self
                .fail_next_concurrent_check
                .lock()
                .expect("concurrent-check lock poisoned") = Some(message.to_owned());
        }

        /// Simulate a write failure discovered only after the atomic rename already
        /// published the new content (item 27): `PolicyStore::replace` must classify
        /// this as `PolicyActivationFailed`, not `PolicyPersistenceFailed`, and
        /// synchronously publish the now-actually-active content rather than leaving the
        /// previous snapshot published.
        fn fail_next_write_after_publish(&self, message: &str) {
            *self
                .fail_next_write_post_publication
                .lock()
                .expect("post-publication fail lock poisoned") = Some(message.to_owned());
        }

        /// Simulate the parent directory itself being deleted and recreated (even with
        /// byte-identical file content underneath), which must still rotate the token.
        fn replace_parent(&self) {
            *self.parent_generation.lock().expect("parent generation lock poisoned") += 1;
        }

        /// Simulate the policy file's owner/DACL changing with no content change, which
        /// must still rotate the token.
        fn change_acl(&self) {
            *self.acl_generation.lock().expect("acl generation lock poisoned") += 1;
        }

        fn change_directory_acl(&self) {
            *self
                .dir_acl_generation
                .lock()
                .expect("directory ACL generation lock poisoned") += 1;
        }

        fn hosting_dir(&self, path: &Path) -> windows::VerifiedHostingDirectory {
            let parent_generation = *self.parent_generation.lock().expect("parent generation lock poisoned");
            let dir_acl_generation = *self
                .dir_acl_generation
                .lock()
                .expect("directory ACL generation lock poisoned");
            windows::VerifiedHostingDirectory::for_fake_storage(
                path.parent().unwrap_or_else(|| Path::new(".")).to_owned(),
                windows::test_identity(parent_generation),
                windows::test_security_digest(dir_acl_generation),
            )
        }

        /// Simulate a directory-level capability change discovered on the *next*
        /// observation (item 20): e.g. an operator loosens or tightens a custom
        /// directory's ACL, or the filesystem capability changes, after the store
        /// started.
        fn set_capability(
            &self,
            write_capability: PolicyWriteCapability,
            read_only_reason: Option<PolicyReadOnlyReason>,
        ) {
            *self.write_capability.lock().expect("capability lock poisoned") = write_capability;
            *self.read_only_reason.lock().expect("read-only reason lock poisoned") = read_only_reason;
        }

        /// Simulate the existing target file itself becoming untrustworthy (its own ACL
        /// failing storage security validation) even though the hosting directory's own
        /// capability is unaffected (item 26): distinguishes an insecure/unreadable
        /// target (Repair blocked) from a merely malformed-but-securely-stored one
        /// (Repair still allowed).
        fn mark_target_insecure(&self) {
            *self.target_insecure.lock().expect("insecure flag lock poisoned") = true;
            *self.acl_generation.lock().expect("acl generation lock poisoned") += 1;
        }

        /// Simulate an external actor writing directly to disk in the narrow window
        /// between this store's own re-observation (already completed) and its next
        /// `atomic_create`/`atomic_replace` call: the *next* write on this storage first
        /// "discovers" `policy` already present, before applying its own must-not-replace
        /// or replace semantics.
        fn race_in_content_before_next_write(&self, policy: &PolicyDocument) {
            let bytes = serde_json::to_vec(policy).expect("test policy serializes");
            *self.race_next_write.lock().expect("race lock poisoned") = Some(bytes);
        }

        fn race_directory_before_next_write(&self) {
            *self
                .race_directory_before_write
                .lock()
                .expect("directory race lock poisoned") = true;
        }

        fn race_directory_after_next_publish(&self) {
            *self
                .race_directory_after_publish
                .lock()
                .expect("directory race lock poisoned") = true;
        }

        fn write(
            &self,
            hosting_dir: &windows::VerifiedHostingDirectory,
            bytes: &[u8],
            must_not_replace_existing: bool,
        ) -> Result<windows::PersistedPolicy, windows::WriteFailure> {
            if let Some(message) = self.fail_next_write.lock().expect("fail lock poisoned").take() {
                return Err(windows::WriteFailure::PrePublication(anyhow::anyhow!("{message}")));
            }
            if let Some(message) = self
                .fail_next_concurrent_check
                .lock()
                .expect("concurrent-check lock poisoned")
                .take()
            {
                return Err(windows::WriteFailure::ConcurrentChange(anyhow::anyhow!("{message}")));
            }

            if std::mem::take(
                &mut *self
                    .race_directory_before_write
                    .lock()
                    .expect("directory race lock poisoned"),
            ) {
                *self
                    .dir_acl_generation
                    .lock()
                    .expect("directory ACL generation lock poisoned") += 1;
            }
            let parent_generation = *self.parent_generation.lock().expect("parent generation lock poisoned");
            let dir_acl_generation = *self
                .dir_acl_generation
                .lock()
                .expect("directory ACL generation lock poisoned");
            if !hosting_dir.matches_fake_state(parent_generation, dir_acl_generation) {
                return Err(windows::WriteFailure::PrePublication(anyhow::anyhow!(
                    "simulated hosting directory changed after observation"
                )));
            }

            if let Some(raced_content) = self.race_next_write.lock().expect("race lock poisoned").take() {
                self.set_disk(Some(raced_content));
                return Err(if must_not_replace_existing {
                    windows::WriteFailure::PrePublication(anyhow::anyhow!(
                        "simulated ERROR_ALREADY_EXISTS: destination already exists"
                    ))
                } else {
                    windows::WriteFailure::ConcurrentChange(anyhow::anyhow!(
                        "simulated target changed after token validation"
                    ))
                });
            }

            {
                let mut disk = self.disk.lock().expect("disk lock poisoned");
                if must_not_replace_existing && disk.is_some() {
                    return Err(windows::WriteFailure::PrePublication(anyhow::anyhow!(
                        "simulated ERROR_ALREADY_EXISTS: destination already exists"
                    )));
                }
                *disk = Some(bytes.to_vec());
            }
            // A (simulated) successful rename always publishes a fresh, trusted target:
            // clear any previously simulated insecurity.
            *self.target_insecure.lock().expect("insecure flag lock poisoned") = false;

            *self.target_generation.lock().expect("target generation lock poisoned") += 1;
            let target_generation = *self.target_generation.lock().expect("target generation lock poisoned");
            let acl_generation = *self.acl_generation.lock().expect("acl generation lock poisoned");

            if std::mem::take(
                &mut *self
                    .race_directory_after_publish
                    .lock()
                    .expect("directory race lock poisoned"),
            ) {
                *self
                    .dir_acl_generation
                    .lock()
                    .expect("directory ACL generation lock poisoned") += 1;
                return Err(windows::WriteFailure::PostPublication(anyhow::anyhow!(
                    "simulated hosting directory changed after publication"
                )));
            }

            // The rename above is the publication boundary (item 27): any failure from
            // here on is post-publication, even though this fake has no real separate
            // "reopen" step to fail independently of the rename itself.
            if let Some(message) = self
                .fail_next_write_post_publication
                .lock()
                .expect("post-publication fail lock poisoned")
                .take()
            {
                return Err(windows::WriteFailure::PostPublication(anyhow::anyhow!("{message}")));
            }

            let policy = serde_json::from_slice::<PolicyDocument>(bytes)
                .expect("fake atomic write always receives a canonical, parseable policy");

            Ok(windows::PersistedPolicy {
                policy,
                fingerprint: windows::DiskFingerprint::test_active(
                    bytes,
                    target_generation,
                    parent_generation,
                    acl_generation,
                    dir_acl_generation,
                ),
            })
        }
    }

    impl PolicyStorage for FakePolicyStorage {
        fn observe(&self, _source: PolicyConfigurationSource, path: &Path) -> windows::DiskObservation {
            let parent_generation = *self.parent_generation.lock().expect("parent generation lock poisoned");
            let write_capability = *self.write_capability.lock().expect("capability lock poisoned");
            let read_only_reason = *self.read_only_reason.lock().expect("read-only reason lock poisoned");
            let target_insecure = *self.target_insecure.lock().expect("insecure flag lock poisoned");
            let dir_acl_generation = *self
                .dir_acl_generation
                .lock()
                .expect("directory ACL generation lock poisoned");

            match &*self.disk.lock().expect("disk lock poisoned") {
                None => windows::DiskObservation {
                    state: PolicyManagementState::Missing,
                    policy: None,
                    invalid_diagnostics: None,
                    fingerprint: windows::DiskFingerprint::test_missing(parent_generation, dir_acl_generation),
                    write_capability,
                    read_only_reason,
                    canonical_path: path.to_owned(),
                    hosting_dir: (write_capability == PolicyWriteCapability::Writable).then(|| self.hosting_dir(path)),
                    retained_target: None,
                },
                Some(bytes) => {
                    let target_generation = *self.target_generation.lock().expect("target generation lock poisoned");
                    let acl_generation = *self.acl_generation.lock().expect("acl generation lock poisoned");

                    // Item 26: an insecure target always forces ReadOnly/UnsafePath,
                    // regardless of the directory's own (otherwise possibly Writable)
                    // capability -- Repair must never be attempted against it.
                    let (effective_write_capability, effective_read_only_reason) = if target_insecure {
                        (PolicyWriteCapability::ReadOnly, Some(PolicyReadOnlyReason::UnsafePath))
                    } else {
                        (write_capability, read_only_reason)
                    };

                    if target_insecure {
                        return windows::DiskObservation {
                            state: PolicyManagementState::Invalid,
                            policy: None,
                            invalid_diagnostics: Some(InvalidPolicyDiagnostics {
                                diagnostics_version: API_VERSION_STR.into(),
                                findings: vec![validation::disk_failure_finding(
                                    validation::DiskFailureReason::InsecureStorage,
                                )],
                            }),
                            fingerprint: windows::DiskFingerprint::test_invalid(
                                bytes,
                                target_generation,
                                parent_generation,
                                acl_generation,
                                dir_acl_generation,
                            ),
                            write_capability: effective_write_capability,
                            read_only_reason: effective_read_only_reason,
                            canonical_path: path.to_owned(),
                            hosting_dir: None,
                            retained_target: None,
                        };
                    }

                    match serde_json::from_slice::<PolicyDocument>(bytes) {
                        Ok(policy) => {
                            // Item 30: the fake also runs committed documents through the
                            // same authoritative semantic validator a submitted draft
                            // would go through, not just structural parseability.
                            let committed_validation = validation::validate_committed_policy(&policy);
                            if !committed_validation.is_valid {
                                return windows::DiskObservation {
                                    state: PolicyManagementState::Invalid,
                                    policy: None,
                                    invalid_diagnostics: Some(InvalidPolicyDiagnostics {
                                        diagnostics_version: API_VERSION_STR.into(),
                                        findings: vec![validation::disk_failure_finding(
                                            validation::DiskFailureReason::FailedSemanticValidation,
                                        )],
                                    }),
                                    fingerprint: windows::DiskFingerprint::test_invalid(
                                        bytes,
                                        target_generation,
                                        parent_generation,
                                        acl_generation,
                                        dir_acl_generation,
                                    ),
                                    write_capability: effective_write_capability,
                                    read_only_reason: effective_read_only_reason,
                                    canonical_path: path.to_owned(),
                                    hosting_dir: (effective_write_capability == PolicyWriteCapability::Writable)
                                        .then(|| self.hosting_dir(path)),
                                    retained_target: None,
                                };
                            }

                            windows::DiskObservation {
                                state: PolicyManagementState::Active,
                                policy: Some(policy),
                                invalid_diagnostics: None,
                                fingerprint: windows::DiskFingerprint::test_active(
                                    bytes,
                                    target_generation,
                                    parent_generation,
                                    acl_generation,
                                    dir_acl_generation,
                                ),
                                write_capability: effective_write_capability,
                                read_only_reason: effective_read_only_reason,
                                canonical_path: path.to_owned(),
                                hosting_dir: (effective_write_capability == PolicyWriteCapability::Writable)
                                    .then(|| self.hosting_dir(path)),
                                retained_target: None,
                            }
                        }
                        Err(_) => windows::DiskObservation {
                            state: PolicyManagementState::Invalid,
                            policy: None,
                            invalid_diagnostics: Some(InvalidPolicyDiagnostics {
                                diagnostics_version: API_VERSION_STR.into(),
                                findings: vec![validation::disk_failure_finding(
                                    validation::DiskFailureReason::MalformedContent,
                                )],
                            }),
                            fingerprint: windows::DiskFingerprint::test_invalid(
                                bytes,
                                target_generation,
                                parent_generation,
                                acl_generation,
                                dir_acl_generation,
                            ),
                            write_capability: effective_write_capability,
                            read_only_reason: effective_read_only_reason,
                            canonical_path: path.to_owned(),
                            hosting_dir: (effective_write_capability == PolicyWriteCapability::Writable)
                                .then(|| self.hosting_dir(path)),
                            retained_target: None,
                        },
                    }
                }
            }
        }

        fn observe_for_write(&self, source: PolicyConfigurationSource, path: &Path) -> windows::DiskObservation {
            let mut observation = self.observe(source, path);
            if observation.write_capability == PolicyWriteCapability::Writable
                && matches!(
                    observation.state,
                    PolicyManagementState::Active | PolicyManagementState::Invalid
                )
            {
                observation.retained_target =
                    Some(windows::RetainedPolicyFile::for_fake(observation.fingerprint.clone()));
            }
            observation
        }

        fn atomic_replace(
            &self,
            hosting_dir: &windows::VerifiedHostingDirectory,
            observed_target: Option<windows::RetainedPolicyFile>,
            expected_fingerprint: &windows::DiskFingerprint,
            _final_path: &Path,
            bytes: &[u8],
        ) -> Result<windows::PersistedPolicy, windows::WriteFailure> {
            let target = observed_target.ok_or_else(|| {
                windows::WriteFailure::ConcurrentChange(anyhow::anyhow!(
                    "fake write observation did not retain the target"
                ))
            })?;
            target
                .verify_matches(expected_fingerprint)
                .map_err(windows::WriteFailure::ConcurrentChange)?;
            self.write(hosting_dir, bytes, false)
        }

        fn atomic_create(
            &self,
            hosting_dir: &windows::VerifiedHostingDirectory,
            _final_path: &Path,
            bytes: &[u8],
        ) -> Result<windows::PersistedPolicy, windows::WriteFailure> {
            self.write(hosting_dir, bytes, true)
        }
    }

    fn actor(sid: &Sid) -> PolicyWriteActor<'_> {
        PolicyWriteActor {
            sid,
            executable: Path::new(r"C:\Program Files\Devolutions\Agent\DevolutionsAgent.exe"),
        }
    }

    #[test]
    fn fake_write_observation_retains_fingerprint_evidence() {
        let storage = FakePolicyStorage::writable();
        storage.seed(&policy("policy-a", 1));
        let path = Path::new(r"C:\fake\package-broker-policy.json");

        let reload = storage.observe(PolicyConfigurationSource::ConfiguredPath, path);
        let write = storage.observe_for_write(PolicyConfigurationSource::ConfiguredPath, path);

        assert!(reload.retained_target.is_none());
        let retained = write
            .retained_target
            .expect("write observation retains target evidence");
        retained.verify_matches(&write.fingerprint).unwrap();
    }

    fn draft_json(id: &str) -> serde_json::Value {
        serde_json::json!({
            "$schema": now_policy::POLICY_DRAFT_SCHEMA_URI,
            "PolicyVersion": "1.0.0",
            "PolicyType": "PackageBrokerPolicy",
            "Metadata": { "Id": id, "Publisher": "Test" },
            "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
            "Rules": [],
        })
    }

    /// Build a well-formed [`PolicyReplacementRequest`], computing its validation receipt
    /// the same way a real client would: by first calling `store.validate_draft` (so the
    /// receipt is bound to that exact store's own process-random key).
    fn replacement_request(
        store: &PolicyStore,
        expected_store_token: &PolicyStoreToken,
        operation: PolicyReplacementOperation,
        conflict_handling: PolicyConflictHandling,
        draft: serde_json::Value,
    ) -> PolicyReplacementRequest {
        let result = store.validate_draft(&draft);
        assert!(result.is_valid, "test draft must validate: {:?}", result.findings);
        PolicyReplacementRequest {
            request_kind: PolicyReplacementRequestKind,
            request_version: API_VERSION_STR.into(),
            expected_store_token: expected_store_token.clone(),
            operation,
            conflict_handling,
            warnings_acknowledged: true,
            draft,
            validation_receipt: result
                .validation_receipt
                .expect("a valid draft always carries a receipt"),
        }
    }

    fn current_token(store: &PolicyStore) -> PolicyStoreToken {
        store.management_snapshot().store_token
    }

    // ─── plan_revision ───────────────────────────────────────────────────────

    fn policy(id: &str, revision: u32) -> PolicyDocument {
        serde_json::from_value(serde_json::json!({
            "$schema": now_policy::POLICY_SCHEMA_URI,
            "PolicyVersion": "1.0.0",
            "PolicyType": "PackageBrokerPolicy",
            "Metadata": { "Id": id, "Publisher": "Test", "Revision": revision, "PublishedAt": Utc::now() },
            "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
            "Rules": [],
        }))
        .expect("test policy is well-formed")
    }

    #[test]
    fn update_requires_same_id_and_increments_revision() {
        let active = policy("policy-a", 5);
        let revision = plan_revision(
            PolicyReplacementOperation::Update,
            PolicyManagementState::Active,
            Some(&active),
            "policy-a",
        )
        .expect("same-id update is allowed");
        assert_eq!(revision, 6);
    }

    #[test]
    fn update_rejects_maximum_revision() {
        let active = policy("policy-a", 2_147_483_647);
        let error = plan_revision(
            PolicyReplacementOperation::Update,
            PolicyManagementState::Active,
            Some(&active),
            "policy-a",
        )
        .expect_err("the maximum committed revision cannot be incremented");
        assert!(error.contains("maximum supported value"));
    }

    #[test]
    fn update_rejects_different_id() {
        let active = policy("policy-a", 5);
        assert!(
            plan_revision(
                PolicyReplacementOperation::Update,
                PolicyManagementState::Active,
                Some(&active),
                "policy-b",
            )
            .is_err()
        );
    }

    #[test]
    fn update_rejects_missing_state() {
        assert!(
            plan_revision(
                PolicyReplacementOperation::Update,
                PolicyManagementState::Missing,
                None,
                "policy-a"
            )
            .is_err()
        );
    }

    #[test]
    fn replace_identity_requires_different_id_at_revision_one() {
        let active = policy("policy-a", 5);
        let revision = plan_revision(
            PolicyReplacementOperation::ReplaceIdentity,
            PolicyManagementState::Active,
            Some(&active),
            "policy-b",
        )
        .expect("different-id replace is allowed");
        assert_eq!(revision, 1);
    }

    #[test]
    fn replace_identity_rejects_same_id() {
        let active = policy("policy-a", 5);
        assert!(
            plan_revision(
                PolicyReplacementOperation::ReplaceIdentity,
                PolicyManagementState::Active,
                Some(&active),
                "policy-a",
            )
            .is_err()
        );
    }

    #[test]
    fn create_requires_missing_state_at_revision_one() {
        let revision = plan_revision(
            PolicyReplacementOperation::Create,
            PolicyManagementState::Missing,
            None,
            "policy-a",
        )
        .expect("create while missing is allowed");
        assert_eq!(revision, 1);
    }

    #[test]
    fn create_rejects_active_state() {
        let active = policy("policy-a", 5);
        assert!(
            plan_revision(
                PolicyReplacementOperation::Create,
                PolicyManagementState::Active,
                Some(&active),
                "policy-a",
            )
            .is_err()
        );
    }

    #[test]
    fn repair_requires_invalid_state_at_revision_one() {
        let revision = plan_revision(
            PolicyReplacementOperation::Repair,
            PolicyManagementState::Invalid,
            None,
            "policy-a",
        )
        .expect("repair while invalid is allowed");
        assert_eq!(revision, 1);
    }

    #[test]
    fn repair_rejects_active_state() {
        let active = policy("policy-a", 5);
        assert!(
            plan_revision(
                PolicyReplacementOperation::Repair,
                PolicyManagementState::Active,
                Some(&active),
                "policy-a",
            )
            .is_err()
        );
    }

    // ─── PolicyStore::replace ────────────────────────────────────────────────

    #[tokio::test]
    async fn create_on_missing_activates_the_policy() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::writable()));
        assert!(store.active_policy().is_none());
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let success = store.replace(request, actor(&sid)).await.expect("create succeeds");

        assert_eq!(success.policy.metadata.id.to_string(), "policy-a");
        assert_eq!(success.policy.metadata.revision, 1);
        assert_eq!(success.management.state, PolicyManagementState::Active);
        let active = store.active_policy().expect("policy now active");
        assert_eq!(active.metadata.id.to_string(), "policy-a");
    }

    #[tokio::test]
    async fn create_on_active_is_rejected() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(storage);
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-b"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("create must fail when active");
        assert_eq!(error.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn update_increments_revision_and_preserves_id() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 3));
        let store = PolicyStore::for_tests_with_storage(storage);
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let success = store.replace(request, actor(&sid)).await.expect("update succeeds");
        assert_eq!(success.policy.metadata.revision, 4);
    }

    #[tokio::test]
    async fn stale_token_conflict_carries_fresh_management_snapshot() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(storage);
        let sid = system_sid();

        let stale_token = PolicyStoreToken::from("sha256:not-the-real-token");
        let request = replacement_request(
            &store,
            &stale_token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("stale token must be rejected");
        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);
        let management = error
            .management
            .expect("stale-token error carries the current management snapshot");
        assert_eq!(management.store_token, current_token(&store));
        // The store's own active policy is untouched by a rejected conflicting write.
        assert_eq!(store.active_policy().expect("still active").metadata.revision, 1);
    }

    #[tokio::test]
    async fn confirm_overwrite_succeeds_against_the_exact_current_token() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(storage);
        let sid = system_sid();
        let current = current_token(&store);

        let request = replacement_request(
            &store,
            &current,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::ConfirmOverwrite,
            draft_json("policy-a"),
        );
        let success = store
            .replace(request, actor(&sid))
            .await
            .expect("confirmed overwrite succeeds");
        assert_eq!(success.policy.metadata.revision, 2);
    }

    #[tokio::test]
    async fn confirm_overwrite_still_conflicts_after_another_change() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(storage);
        let sid = system_sid();
        let stale = current_token(&store);

        // Someone else updates the policy first.
        let first = replacement_request(
            &store,
            &stale,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        store.replace(first, actor(&sid)).await.expect("first update succeeds");

        // A ConfirmOverwrite bound to the now-stale token must still conflict: it is not
        // an unconditional force mode.
        let second = replacement_request(
            &store,
            &stale,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::ConfirmOverwrite,
            draft_json("policy-a"),
        );
        let error = store
            .replace(second, actor(&sid))
            .await
            .expect_err("confirm overwrite bound to a stale token must still conflict");
        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);
    }

    #[tokio::test]
    async fn warnings_require_explicit_acknowledgement() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::writable()));
        let token = current_token(&store);
        let sid = system_sid();

        let mut draft = draft_json("policy-a");
        draft["Enforcement"]["AuditMode"] = serde_json::json!(true);
        let mut request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft,
        );
        request.warnings_acknowledged = false;

        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("unacknowledged warnings must be rejected");
        assert_eq!(error.code, ErrorCode::WarningConfirmationRequired);
        let validation = error.validation.expect("carries the validation result");
        assert!(validation.is_valid);
        assert!(!validation.findings.is_empty());
    }

    #[tokio::test]
    async fn tampered_validation_receipt_is_rejected() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::writable()));
        let token = current_token(&store);
        let sid = system_sid();

        let mut request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        request.validation_receipt = PolicyStoreToken::from("sha256:forged").to_string().into();

        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a receipt for a different draft must be rejected");
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[tokio::test]
    async fn invalid_draft_is_rejected_with_findings() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::writable()));
        let token = current_token(&store);
        let sid = system_sid();

        // Bypass `replacement_request`'s validity assertion: build the invalid request by hand.
        let mut draft = draft_json("policy-a");
        draft["PolicyType"] = serde_json::json!("NotAPackageBrokerPolicy");
        let request = PolicyReplacementRequest {
            request_kind: PolicyReplacementRequestKind,
            request_version: API_VERSION_STR.into(),
            expected_store_token: token,
            operation: PolicyReplacementOperation::Create,
            conflict_handling: PolicyConflictHandling::Reject,
            warnings_acknowledged: true,
            draft,
            validation_receipt: PolicyStoreToken::from("sha256:irrelevant").to_string().into(),
        };

        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("an invalid draft must be rejected");
        assert_eq!(error.code, ErrorCode::InvalidPolicy);
        assert!(
            error
                .validation
                .expect("carries findings")
                .findings
                .iter()
                .any(|finding| finding.code == now_policy_api::PolicyFindingCode::UnsupportedPolicyType)
        );
    }

    #[tokio::test]
    async fn unwritable_directory_is_reported_as_unsafe_path() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::read_only(
            PolicyReadOnlyReason::UnsafePath,
        )));
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a read-only directory must reject writes");
        assert_eq!(error.code, ErrorCode::UnsafePolicyPath);
    }

    // ─── Storage error semantics preserved end-to-end (item 31) ────────────────

    #[tokio::test]
    async fn unsupported_filesystem_maps_to_unsupported_policy_filesystem() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::read_only(
            PolicyReadOnlyReason::UnsupportedFileSystem,
        )));
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("an unsupported filesystem must reject writes");
        assert_eq!(error.code, ErrorCode::UnsupportedPolicyFilesystem);
    }

    #[tokio::test]
    async fn unsupported_format_maps_to_unsupported_policy_format() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::read_only(
            PolicyReadOnlyReason::UnsupportedFormat,
        )));
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a configured path with an unsupported format must reject writes");
        assert_eq!(error.code, ErrorCode::UnsupportedPolicyFormat);
    }

    #[tokio::test]
    async fn insufficient_permissions_maps_to_unsafe_policy_path_never_an_auth_code() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::read_only(
            PolicyReadOnlyReason::InsufficientPermissions,
        )));
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("insufficient (server-side) permissions must reject writes");
        // Never an authentication/authorization code: this describes a server-side
        // environment condition, not the caller's own identity or permissions.
        assert_eq!(error.code, ErrorCode::UnsafePolicyPath);
        assert_ne!(error.code, ErrorCode::Forbidden);
        assert_ne!(error.code, ErrorCode::Unauthorized);
        assert_ne!(error.code, ErrorCode::AdministratorRequired);
    }

    #[tokio::test]
    async fn management_disabled_maps_to_unsafe_policy_path_never_an_auth_code() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::read_only(
            PolicyReadOnlyReason::ManagementDisabled,
        )));
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a disabled management path must reject writes");
        assert_eq!(error.code, ErrorCode::UnsafePolicyPath);
        assert_ne!(error.code, ErrorCode::Forbidden);
        assert_ne!(error.code, ErrorCode::Unauthorized);
        assert_ne!(error.code, ErrorCode::AdministratorRequired);
    }

    #[tokio::test]
    async fn path_not_configured_maps_to_unsafe_policy_path_never_an_auth_code() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::read_only(
            PolicyReadOnlyReason::PathNotConfigured,
        )));
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("an unconfigured path must reject writes");
        assert_eq!(error.code, ErrorCode::UnsafePolicyPath);
        assert_ne!(error.code, ErrorCode::Forbidden);
        assert_ne!(error.code, ErrorCode::Unauthorized);
        assert_ne!(error.code, ErrorCode::AdministratorRequired);
    }

    #[tokio::test]
    async fn persistence_failure_leaves_the_previous_policy_active() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        storage.fail_next_write("simulated disk failure");
        let store = PolicyStore::for_tests_with_storage(storage);
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a persistence failure must be reported");
        assert_eq!(error.code, ErrorCode::PolicyPersistenceFailed);

        // The broker never pauses during a failed self-replacement: the old policy stays active.
        let active = store.active_policy().expect("previous policy remains active");
        assert_eq!(active.metadata.revision, 1);
    }

    #[tokio::test]
    async fn failed_concurrency_check_without_state_change_is_a_persistence_failure() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        storage.fail_next_concurrent_check("simulated identity query failure");
        let store = PolicyStore::for_tests_with_storage(storage);
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("an unchanged failed concurrency check must report persistence failure");

        assert_eq!(error.code, ErrorCode::PolicyPersistenceFailed);
        assert_eq!(current_token(&store), token);
        assert_eq!(
            store
                .active_policy()
                .expect("previous policy remains active")
                .metadata
                .revision,
            1
        );
    }

    #[tokio::test]
    async fn hosting_directory_change_before_write_fails_without_publication() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        storage.race_directory_before_next_write();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&system_sid()))
            .await
            .expect_err("a changed hosting directory must fail before publication");

        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);
        assert_ne!(current_token(&store), token);
        assert_eq!(
            store
                .active_policy()
                .expect("previous policy remains active")
                .metadata
                .revision,
            1
        );
    }

    #[tokio::test]
    async fn hosting_directory_change_after_publication_fails_and_reobserves() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        storage.race_directory_after_next_publish();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&system_sid()))
            .await
            .expect_err("a changed hosting directory must fail postverification");

        assert_eq!(error.code, ErrorCode::PolicyActivationFailed);
        assert_eq!(
            store
                .active_policy()
                .expect("published policy is reobserved")
                .metadata
                .revision,
            2
        );
    }

    #[tokio::test]
    async fn concurrent_replace_calls_are_serialized_and_only_one_wins() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = Arc::new(PolicyStore::for_tests_with_storage(storage));
        let token = current_token(&store);
        let sid = system_sid();

        let store_a = Arc::clone(&store);
        let sid_a = sid.clone();
        let token_a = token.clone();
        let task_a = tokio::spawn(async move {
            let request = replacement_request(
                &store_a,
                &token_a,
                PolicyReplacementOperation::Update,
                PolicyConflictHandling::Reject,
                draft_json("policy-a"),
            );
            store_a.replace(request, actor(&sid_a)).await
        });

        let store_b = Arc::clone(&store);
        let sid_b = sid.clone();
        let task_b = tokio::spawn(async move {
            let request = replacement_request(
                &store_b,
                &token,
                PolicyReplacementOperation::Update,
                PolicyConflictHandling::Reject,
                draft_json("policy-a"),
            );
            store_b.replace(request, actor(&sid_b)).await
        });

        let (result_a, result_b) = tokio::join!(task_a, task_b);
        let outcomes = [result_a.unwrap(), result_b.unwrap()];
        let successes = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        let conflicts = outcomes
            .iter()
            .filter(|outcome| {
                outcome
                    .as_ref()
                    .is_err_and(|error| error.code == ErrorCode::StalePolicyStoreToken)
            })
            .count();

        // Both requests read the same pre-write token; the write lock serializes them, so
        // exactly one observes it as still current and the other is a stale-token conflict.
        assert_eq!(successes, 1, "exactly one concurrent replace should succeed");
        assert_eq!(conflicts, 1, "the other concurrent replace should observe a conflict");
        assert_eq!(store.active_policy().expect("active").metadata.revision, 2);
    }

    // ─── PolicyStore::reload_from_disk ───────────────────────────────────────

    #[tokio::test]
    async fn external_change_is_applied() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        assert_eq!(store.active_policy().unwrap().metadata.revision, 1);

        // Simulate an administrator directly editing the file outside the API.
        storage.seed(&policy("policy-a", 2));

        store.reload_from_disk("test").await;
        assert_eq!(store.active_policy().unwrap().metadata.revision, 2);
    }

    #[tokio::test]
    async fn bad_external_change_transitions_to_invalid() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));

        storage.seed_invalid(b"{ not json".to_vec());

        store.reload_from_disk("test").await;
        assert!(
            store.active_policy().is_none(),
            "a broken external edit must pause the broker"
        );
        assert_eq!(store.management_snapshot().state, PolicyManagementState::Invalid);
    }

    #[tokio::test]
    async fn reload_is_a_noop_when_disk_is_unchanged() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(storage);
        let token_before = current_token(&store);

        store.reload_from_disk("test").await;

        assert_eq!(current_token(&store), token_before);
        assert_eq!(store.active_policy().unwrap().metadata.revision, 1);
    }

    // ─── Opaque store token: fingerprint-driven rotation/stability (item 1) ───

    #[tokio::test]
    async fn token_rotates_on_same_byte_external_replacement() {
        // An external actor rewrites the exact same bytes: the underlying file object
        // still changed (a new `target_generation`), so the token must still rotate.
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let before = current_token(&store);

        storage.seed(&policy("policy-a", 1));
        store.reload_from_disk("test").await;

        assert_ne!(current_token(&store), before);
    }

    #[tokio::test]
    async fn token_rotates_on_acl_change_alone() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let before = current_token(&store);

        storage.change_acl();
        store.reload_from_disk("test").await;

        assert_ne!(current_token(&store), before);
    }

    #[tokio::test]
    async fn token_rotates_on_hosting_directory_acl_change_alone() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let before = current_token(&store);

        storage.change_directory_acl();
        store.reload_from_disk("test").await;

        assert_ne!(current_token(&store), before);
    }

    #[tokio::test]
    async fn missing_token_rotates_on_hosting_directory_acl_change() {
        let storage = Arc::new(FakePolicyStorage::writable());
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let before = current_token(&store);

        storage.change_directory_acl();
        store.reload_from_disk("test").await;

        assert_ne!(current_token(&store), before);
    }

    #[tokio::test]
    async fn invalid_token_rotates_on_hosting_directory_acl_change() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed_invalid(b"not JSON");
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let before = current_token(&store);

        storage.change_directory_acl();
        store.reload_from_disk("test").await;

        assert_ne!(current_token(&store), before);
    }

    #[tokio::test]
    async fn token_rotates_on_parent_directory_replacement() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let before = current_token(&store);

        storage.replace_parent();
        store.reload_from_disk("test").await;

        assert_ne!(current_token(&store), before);
    }

    #[tokio::test]
    async fn token_is_stable_when_truly_unchanged() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(storage);
        let before = current_token(&store);

        // Repeated observation with no intervening change whatsoever.
        store.reload_from_disk("test").await;
        store.reload_from_disk("test").await;

        assert_eq!(current_token(&store), before);
    }

    #[tokio::test]
    async fn different_missing_custom_paths_yield_different_tokens() {
        // Two independently configured (here: independently faked) custom paths that are
        // both currently Missing must not be mistaken for each other: their tokens must
        // differ, since nothing about "Missing" alone should let a client's stale idea of
        // one store's token be accidentally accepted as current for a different one.
        let store_a = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::writable()));

        let storage_b = Arc::new(FakePolicyStorage::writable());
        storage_b.replace_parent(); // Give the second store a distinct parent identity.
        let store_b = PolicyStore::for_tests_with_storage(storage_b);

        assert_eq!(store_a.management_snapshot().state, PolicyManagementState::Missing);
        assert_eq!(store_b.management_snapshot().state, PolicyManagementState::Missing);
        assert_ne!(current_token(&store_a), current_token(&store_b));
    }

    // ─── Stale publication: replace reobserves and publishes before erroring (item 5) ─

    #[tokio::test]
    async fn stale_replace_publishes_the_external_change_before_returning() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let stale_token = current_token(&store);
        let sid = system_sid();

        // An external edit lands after the client observed `stale_token`, but before its
        // replacement request reaches the store.
        storage.seed(&policy("policy-a", 2));

        let request = replacement_request(
            &store,
            &stale_token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a stale token must be rejected");
        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);

        // The store's own state was published to the new reality *before* returning, not
        // left to be picked up later by the file watcher.
        assert_eq!(store.active_policy().expect("still active").metadata.revision, 2);
        let management = error
            .management
            .expect("stale-token error carries the current management snapshot");
        assert_eq!(management.state, PolicyManagementState::Active);
        assert_eq!(management.store_token, current_token(&store));
        assert_eq!(
            management
                .policy
                .expect("published snapshot carries the policy")
                .metadata
                .revision,
            2
        );
    }

    #[tokio::test]
    async fn stale_replace_publishes_missing_when_external_edit_removed_the_policy() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let stale_token = current_token(&store);
        let sid = system_sid();

        storage.set_disk(None);

        let request = replacement_request(
            &store,
            &stale_token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a stale token must be rejected");
        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);

        assert!(store.active_policy().is_none(), "broker paused: policy is now Missing");
        let management = error.management.expect("carries the current management snapshot");
        assert_eq!(management.state, PolicyManagementState::Missing);
        assert_eq!(management.store_token, current_token(&store));
    }

    #[tokio::test]
    async fn repeated_conflicting_replace_attempts_observe_the_same_published_snapshot() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let stale_token = current_token(&store);
        let sid = system_sid();

        storage.seed(&policy("policy-a", 2));

        let first = replacement_request(
            &store,
            &stale_token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let first_error = store.replace(first, actor(&sid)).await.expect_err("stale");
        let first_management = first_error.management.expect("carries a snapshot");

        // A second attempt bound to the very same now-stale token must observe the exact
        // same already-published reality, not detect yet another "change".
        let second = replacement_request(
            &store,
            &stale_token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let second_error = store.replace(second, actor(&sid)).await.expect_err("still stale");
        let second_management = second_error.management.expect("carries a snapshot");

        assert_eq!(first_management.store_token, second_management.store_token);
        assert_eq!(
            first_management.policy.map(|p| p.metadata.revision),
            second_management.policy.map(|p| p.metadata.revision)
        );
    }

    // ─── Missing `Create` race: never overwrite, publish fresh snapshot (item 12) ────

    #[tokio::test]
    async fn create_race_never_overwrites_and_reports_a_fresh_snapshot() {
        let storage = Arc::new(FakePolicyStorage::writable());
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        let sid = system_sid();

        // Simulate a different actor creating the policy in the exact window between this
        // transaction's own re-observation (Missing, above) and its `atomic_create` call.
        storage.race_in_content_before_next_write(&policy("policy-raced-in", 1));

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a raced-in leaf must never be silently overwritten");
        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);

        // The raced-in policy -- never ours -- is the one now active.
        let active = store.active_policy().expect("raced-in policy is now active");
        assert_eq!(active.metadata.id.to_string(), "policy-raced-in");

        let management = error.management.expect("carries the freshly published snapshot");
        assert_eq!(management.store_token, current_token(&store));
        assert_eq!(
            management.policy.expect("policy").metadata.id.to_string(),
            "policy-raced-in"
        );
    }

    #[tokio::test]
    async fn update_race_never_overwrites_and_reports_a_fresh_snapshot() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        let sid = system_sid();
        storage.race_in_content_before_next_write(&policy("policy-external", 7));

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("an external update must never be overwritten");

        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);
        let active = store.active_policy().expect("external policy is active");
        assert_eq!(active.metadata.id.to_string(), "policy-external");
        assert_eq!(active.metadata.revision, 7);
        let management = error.management.expect("conflict carries the current snapshot");
        assert_eq!(management.store_token, current_token(&store));
        assert_eq!(management.policy.expect("policy").metadata.revision, 7);
    }

    #[tokio::test]
    async fn replace_identity_race_never_overwrites_external_content() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        let sid = system_sid();
        storage.race_in_content_before_next_write(&policy("policy-external", 7));

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::ReplaceIdentity,
            PolicyConflictHandling::Reject,
            draft_json("policy-b"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("an external replacement must never be overwritten");

        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);
        assert_eq!(
            store
                .active_policy()
                .expect("external policy is active")
                .metadata
                .id
                .to_string(),
            "policy-external"
        );
    }

    #[tokio::test]
    async fn repair_race_never_overwrites_external_content() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed_invalid(b"{malformed".to_vec());
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        let sid = system_sid();
        storage.race_in_content_before_next_write(&policy("policy-external", 7));

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Repair,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("an external repair must never be overwritten");

        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);
        assert_eq!(
            store
                .active_policy()
                .expect("external policy is active")
                .metadata
                .id
                .to_string(),
            "policy-external"
        );
    }

    // ─── Invalid disk diagnostics redaction (item 6) ──────────────────────────

    #[tokio::test]
    async fn malformed_external_content_never_leaks_into_diagnostics() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));

        let secret_marker = "sso1kkD0-attacker-controlled-marker";
        storage.seed_invalid(format!(r#"{{"unterminated": "{secret_marker}"#).into_bytes());

        store.reload_from_disk("test").await;

        let management = store.management_snapshot();
        assert_eq!(management.state, PolicyManagementState::Invalid);
        let diagnostics = management
            .invalid_diagnostics
            .expect("Invalid state carries diagnostics");
        for finding in &diagnostics.findings {
            assert!(
                !finding.message.contains(secret_marker),
                "diagnostics leaked malformed on-disk content: {}",
                finding.message
            );
        }
        // The message is one of the fixed, generic strings `disk_failure_finding` returns
        // for every draft with this shape of failure, never anything computed from this
        // specific draft's bytes.
        assert!(diagnostics.findings.iter().all(|finding| finding.message
            == "the configured policy file does not contain valid JSON matching the expected policy schema"));
    }

    // ─── Capability refreshed on every re-observation/publication (item 20) ──

    #[tokio::test]
    async fn writable_directory_becoming_unwritable_is_reflected_on_next_observation() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        assert_eq!(
            store.management_snapshot().write_capability,
            PolicyWriteCapability::Writable
        );

        storage.set_capability(PolicyWriteCapability::ReadOnly, Some(PolicyReadOnlyReason::UnsafePath));
        store.reload_from_disk("directory ACL tightened externally").await;

        let management = store.management_snapshot();
        assert_eq!(management.write_capability, PolicyWriteCapability::ReadOnly);
        assert_eq!(management.read_only_reason, Some(PolicyReadOnlyReason::UnsafePath));
    }

    #[tokio::test]
    async fn unwritable_directory_becoming_writable_is_reflected_on_next_observation() {
        let storage = Arc::new(FakePolicyStorage::read_only(
            PolicyReadOnlyReason::InsufficientPermissions,
        ));
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        assert_eq!(
            store.management_snapshot().write_capability,
            PolicyWriteCapability::ReadOnly
        );

        storage.set_capability(PolicyWriteCapability::Writable, None);
        store.reload_from_disk("directory ACL loosened externally").await;

        let management = store.management_snapshot();
        assert_eq!(management.write_capability, PolicyWriteCapability::Writable);
        assert_eq!(management.read_only_reason, None);
    }

    #[tokio::test]
    async fn acl_only_capability_change_is_reflected_with_no_content_change() {
        let storage = Arc::new(FakePolicyStorage::read_only(PolicyReadOnlyReason::UnsafePath));
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));

        // Only the *reason* changes (e.g. the volume itself was remounted on a
        // filesystem that no longer proves atomic-replace capability), not the file
        // content at all.
        storage.set_capability(
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsupportedFileSystem),
        );
        store.reload_from_disk("filesystem capability changed").await;

        let management = store.management_snapshot();
        assert_eq!(management.write_capability, PolicyWriteCapability::ReadOnly);
        assert_eq!(
            management.read_only_reason,
            Some(PolicyReadOnlyReason::UnsupportedFileSystem)
        );
    }

    #[tokio::test]
    async fn replace_authorizes_against_freshly_resolved_capability_not_a_cached_one() {
        // The store starts out writable (Missing state), but the directory's capability
        // changes *before* the write attempt is ever made -- proving `replace` never
        // trusts a capability resolved at construction time or from a previous
        // transaction (item 20).
        let storage = Arc::new(FakePolicyStorage::writable());
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        let sid = system_sid();

        storage.set_capability(PolicyWriteCapability::ReadOnly, Some(PolicyReadOnlyReason::UnsafePath));

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a directory that became unwritable just before the write must reject it");
        assert_eq!(error.code, ErrorCode::UnsafePolicyPath);
    }

    // ─── ConfirmOverwrite cannot bypass the operation invariant (item 25) ─────

    #[tokio::test]
    async fn confirm_overwrite_does_not_bypass_update_identity_invariant() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(storage);
        let token = current_token(&store);
        let sid = system_sid();

        // `Update` with a different id must fail (it requires `ReplaceIdentity`
        // instead) even under `ConfirmOverwrite` and even with the exact current token.
        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::ConfirmOverwrite,
            draft_json("policy-b"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("Update with a changed identity must still require ReplaceIdentity");
        assert_eq!(error.code, ErrorCode::Conflict);

        // The current snapshot is exactly what it was: unaffected by the rejected request.
        let management = store.management_snapshot();
        assert_eq!(management.state, PolicyManagementState::Active);
        assert_eq!(
            management.policy.expect("still active").metadata.id.to_string(),
            "policy-a"
        );
    }

    #[tokio::test]
    async fn confirm_overwrite_does_not_bypass_replace_identity_same_id_invariant() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(storage);
        let token = current_token(&store);
        let sid = system_sid();

        // `ReplaceIdentity` with the *same* id must fail (it requires `Update` instead).
        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::ReplaceIdentity,
            PolicyConflictHandling::ConfirmOverwrite,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("ReplaceIdentity with an unchanged identity must still require Update");
        assert_eq!(error.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn confirm_overwrite_on_missing_state_still_requires_create() {
        let store = PolicyStore::for_tests_with_storage(Arc::new(FakePolicyStorage::writable()));
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::ConfirmOverwrite,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("Missing state must still require Create, not Update, even under ConfirmOverwrite");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(store.management_snapshot().state, PolicyManagementState::Missing);
    }

    #[tokio::test]
    async fn confirm_overwrite_on_invalid_state_still_requires_repair() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed_invalid(b"{not valid json".to_vec());
        let store = PolicyStore::for_tests_with_storage(storage);
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::ConfirmOverwrite,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("Invalid state must still require Repair, not Create, even under ConfirmOverwrite");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(store.management_snapshot().state, PolicyManagementState::Invalid);
    }

    // ─── Malformed-but-secure vs insecure/unreadable target (item 26) ─────────

    #[tokio::test]
    async fn malformed_but_secure_target_stays_writable_and_repair_succeeds() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed_invalid(b"{not valid json".to_vec());
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));

        let management = store.management_snapshot();
        assert_eq!(management.state, PolicyManagementState::Invalid);
        assert_eq!(management.write_capability, PolicyWriteCapability::Writable);

        let token = management.store_token;
        let sid = system_sid();
        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Repair,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        store
            .replace(request, actor(&sid))
            .await
            .expect("repairing a malformed-but-securely-stored file must succeed");
    }

    #[tokio::test]
    async fn insecure_target_forces_read_only_even_with_valid_content() {
        // The content is perfectly well-formed, but the target's own security is
        // untrustworthy: this must still be Invalid + ReadOnly, never Active, and
        // Repair must be blocked. Security failure is checked -- and fails closed --
        // before content is ever trusted, matching the real Windows backend.
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        storage.mark_target_insecure();
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));

        let management = store.management_snapshot();
        assert_eq!(management.state, PolicyManagementState::Invalid);
        assert_eq!(management.write_capability, PolicyWriteCapability::ReadOnly);
        assert_eq!(management.read_only_reason, Some(PolicyReadOnlyReason::UnsafePath));
        assert!(
            management.policy.is_none(),
            "an insecure target must never expose its content"
        );

        let sid = system_sid();
        let request = replacement_request(
            &store,
            &management.store_token,
            PolicyReplacementOperation::Repair,
            PolicyConflictHandling::Reject,
            draft_json("policy-b"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("repair of an insecure target must be blocked");
        assert_eq!(error.code, ErrorCode::UnsafePolicyPath);
    }

    #[tokio::test]
    async fn insecure_malformed_target_is_reported_read_only_not_writable() {
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed_invalid(b"{not valid json".to_vec());
        storage.mark_target_insecure();
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));

        let management = store.management_snapshot();
        assert_eq!(management.state, PolicyManagementState::Invalid);
        assert_eq!(management.write_capability, PolicyWriteCapability::ReadOnly);
        assert_eq!(management.read_only_reason, Some(PolicyReadOnlyReason::UnsafePath));
    }

    // ─── Typed pre/post-publication storage errors (item 27) ──────────────────

    #[tokio::test]
    async fn post_publication_failure_returns_activation_failed_and_publishes_actual_state() {
        let storage = Arc::new(FakePolicyStorage::writable());
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        let sid = system_sid();

        storage.fail_next_write_after_publish("simulated post-write verification failure");

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Create,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a post-publication verification failure must be reported");
        assert_eq!(error.code, ErrorCode::PolicyActivationFailed);

        // The rename already happened (the fake's `disk` was updated before the
        // simulated failure): the store must publish that actual reality immediately,
        // synchronously, under the same lock -- not leave the previous (Missing)
        // snapshot published until the watcher or fallback poll happens to catch up.
        let management = store.management_snapshot();
        assert_eq!(management.state, PolicyManagementState::Active);
        assert_eq!(
            management.policy.expect("now active").metadata.id.to_string(),
            "policy-a"
        );

        // The shared `ErrorResponse.management` field is generic (item 27): the error
        // itself must already carry the same freshly republished snapshot, so the caller
        // never has to issue a follow-up `GET` to learn what this request already knows.
        let error_management = error
            .management
            .expect("PolicyActivationFailed must carry the freshly republished management snapshot");
        assert_eq!(error_management.state, PolicyManagementState::Active);
        assert_eq!(
            error_management.policy.expect("now active").metadata.id.to_string(),
            "policy-a"
        );
    }

    #[tokio::test]
    async fn pre_publication_failure_is_distinct_from_post_publication_failure() {
        // Companion to `persistence_failure_leaves_the_previous_policy_active`: a
        // pre-publication failure must map to a different error code than a
        // post-publication one, and disk must remain provably unchanged.
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        storage.fail_next_write("simulated pre-write failure");
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));
        let token = current_token(&store);
        let sid = system_sid();

        let request = replacement_request(
            &store,
            &token,
            PolicyReplacementOperation::Update,
            PolicyConflictHandling::Reject,
            draft_json("policy-a"),
        );
        let error = store
            .replace(request, actor(&sid))
            .await
            .expect_err("a pre-publication failure must be reported");
        assert_eq!(error.code, ErrorCode::PolicyPersistenceFailed);
        assert_ne!(error.code, ErrorCode::PolicyActivationFailed);

        let management = store.management_snapshot();
        assert_eq!(management.policy.expect("unchanged").metadata.revision, 1);
    }

    // ─── Watcher periodic fallback poll (item 19/29) ──────────────────────────

    #[tokio::test]
    async fn periodic_fallback_poll_eventually_reflects_an_external_change_alone() {
        // Exercises the seam independent of real OS filesystem notification delivery
        // (item 19): even if the event-driven watcher never fires at all, the periodic
        // fallback poll alone must eventually pick up an external change.
        let storage = Arc::new(FakePolicyStorage::writable());
        storage.seed(&policy("policy-a", 1));
        let store = PolicyStore::for_tests_with_storage(Arc::clone(&storage));

        let shutdown = CancellationToken::new();
        let poll_interval = Duration::from_millis(20);
        let watch_handle = tokio::spawn({
            let store = Arc::clone(&store);
            let shutdown = shutdown.clone();
            async move { store.watch_with_poll_interval(shutdown, poll_interval).await }
        });

        // External edit, never signaled through the (nonexistent, in this test) OS
        // filesystem watcher: only the periodic poll can ever notice it.
        storage.seed(&policy("policy-b", 1));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if store
                .active_policy()
                .is_some_and(|policy| policy.metadata.id.to_string() == "policy-b")
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "periodic fallback poll never picked up the external change"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        shutdown.cancel();
        watch_handle.await.expect("watch task must not panic");
    }
}
