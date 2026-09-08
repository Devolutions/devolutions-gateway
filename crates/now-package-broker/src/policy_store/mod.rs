//! Serialized policy management, validation, persistence, and reload.
//! Store tokens serialize API writers and reloads.
//! Retained handles and conditional handle-relative publication preserve privileged out-of-band writes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::Utc;
use now_policy::PolicyDocument;
use now_policy_api::{
    API_VERSION_STR, ErrorCode, ErrorResponse, ErrorResponseKind, InvalidPolicyDiagnostics, PolicyConfigurationSource,
    PolicyManagementSnapshot, PolicyManagementState, PolicyReadOnlyReason, PolicyReplacementOperation,
    PolicyReplacementRequest, PolicyStoreToken, PolicyValidationResult, PolicyWriteCapability, ServerContext,
    Transport,
};

mod receipt;
mod validation;
mod windows;

#[derive(Clone, Copy, Debug)]
pub enum ReloadCause {
    ExternalChange,
}

type DiskFingerprint = windows::DiskFingerprint;
type Observation = windows::DiskObservation;
type PersistedPolicy = windows::PersistedPolicy;
type WriteFailure = windows::WriteFailure;

trait PolicyStorage: Send + Sync {
    fn observe(&self, source: PolicyConfigurationSource, path: &Path) -> Observation;
    fn observe_for_write(&self, source: PolicyConfigurationSource, path: &Path) -> Observation {
        self.observe(source, path)
    }
    fn create(
        &self,
        configured_path: &Path,
        observation: &Observation,
        bytes: &[u8],
    ) -> Result<PersistedPolicy, WriteFailure>;
    fn replace(
        &self,
        configured_path: &Path,
        observation: &mut Observation,
        bytes: &[u8],
    ) -> Result<PersistedPolicy, WriteFailure>;
}

struct FilePolicyStorage {
    probe_cache: windows::AtomicityProbeCache,
}

impl FilePolicyStorage {
    fn new() -> Self {
        Self {
            probe_cache: windows::AtomicityProbeCache::new(),
        }
    }
}

impl PolicyStorage for FilePolicyStorage {
    fn observe(&self, source: PolicyConfigurationSource, path: &Path) -> Observation {
        windows::observe(source, path, &self.probe_cache)
    }

    fn observe_for_write(&self, source: PolicyConfigurationSource, path: &Path) -> Observation {
        windows::observe_for_write(source, path, &self.probe_cache)
    }

    fn create(
        &self,
        configured_path: &Path,
        observation: &Observation,
        bytes: &[u8],
    ) -> Result<PersistedPolicy, WriteFailure> {
        let hosting_dir = observation
            .hosting_dir
            .as_ref()
            .expect("writable observations retain the verified hosting directory");
        windows::atomic_create(hosting_dir, &observation.canonical_path, bytes)?;
        self.authoritative_reobserve(configured_path, bytes)
    }

    fn replace(
        &self,
        configured_path: &Path,
        observation: &mut Observation,
        bytes: &[u8],
    ) -> Result<PersistedPolicy, WriteFailure> {
        let hosting_dir = observation
            .hosting_dir
            .as_ref()
            .expect("writable observations retain the verified hosting directory");
        windows::atomic_replace(
            hosting_dir,
            observation.retained_target.take(),
            &observation.fingerprint,
            &observation.canonical_path,
            bytes,
        )?;
        self.authoritative_reobserve(configured_path, bytes)
    }
}

impl FilePolicyStorage {
    fn authoritative_reobserve(
        &self,
        configured_path: &Path,
        expected_bytes: &[u8],
    ) -> Result<PersistedPolicy, WriteFailure> {
        let observation = windows::observe(
            PolicyConfigurationSource::ConfiguredPath,
            configured_path,
            &self.probe_cache,
        );
        let policy = observation
            .policy
            .ok_or_else(|| WriteFailure::PostPublication(anyhow::anyhow!("published policy failed re-observation")))?;
        let expected: serde_json::Value =
            serde_json::from_slice(expected_bytes).map_err(|error| WriteFailure::PostPublication(error.into()))?;
        if serde_json::to_value(&policy).map_err(|error| WriteFailure::PostPublication(error.into()))? != expected {
            return Err(WriteFailure::PostPublication(anyhow::anyhow!(
                "re-observed policy does not match the committed document"
            )));
        }
        Ok(PersistedPolicy {
            policy,
            fingerprint: observation.fingerprint,
        })
    }
}

struct Snapshot {
    state: PolicyManagementState,
    policy: Option<Arc<PolicyDocument>>,
    invalid_diagnostics: Option<InvalidPolicyDiagnostics>,
    write_capability: PolicyWriteCapability,
    read_only_reason: Option<PolicyReadOnlyReason>,
    configured_path: PathBuf,
    store_token: PolicyStoreToken,
    fingerprint: DiskFingerprint,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Monitoring {
    Initializing,
    Available,
    Unavailable,
}

#[derive(Debug)]
pub struct ReplaceSuccess {
    pub policy: PolicyDocument,
    pub validation: PolicyValidationResult,
    pub management: PolicyManagementSnapshot,
}

pub struct PolicyStore {
    configured_path: PathBuf,
    default_paths: Option<[PathBuf; 2]>,
    default_managed_selected: std::sync::atomic::AtomicBool,
    source: PolicyConfigurationSource,
    snapshot: RwLock<Arc<Snapshot>>,
    writer: tokio::sync::Mutex<Monitoring>,
    storage: Arc<dyn PolicyStorage>,
    receipt_key: receipt::ReceiptKey,
}

impl PolicyStore {
    pub fn load(configured_path: Option<PathBuf>) -> Arc<Self> {
        Self::load_with_storage(
            configured_path,
            Arc::new(FilePolicyStorage::new()),
            Monitoring::Initializing,
        )
    }

    fn load_with_storage(
        configured_path: Option<PathBuf>,
        storage: Arc<dyn PolicyStorage>,
        monitoring: Monitoring,
    ) -> Arc<Self> {
        let (mut configured_path, default_paths, source) = match configured_path {
            Some(path) => (path, None, PolicyConfigurationSource::ConfiguredPath),
            None => {
                let [managed, legacy] = windows::default_policy_paths();
                (
                    windows::select_default_policy_path(managed.clone(), legacy.clone()),
                    Some([managed, legacy]),
                    PolicyConfigurationSource::DefaultPath,
                )
            }
        };
        let mut default_managed_selected = default_paths
            .as_ref()
            .is_some_and(|[managed, _]| crate::policy_security::windows_paths_equal(&configured_path, managed));
        let mut observation = storage.observe(source, &configured_path);
        if let Some([managed, legacy]) = &default_paths
            && !default_managed_selected
        {
            let final_path = windows::select_default_policy_path(managed.clone(), legacy.clone());
            if crate::policy_security::windows_paths_equal(&final_path, managed) {
                configured_path = final_path;
                default_managed_selected = true;
                observation = storage.observe(source, &configured_path);
            }
        }
        let snapshot = Arc::new(snapshot_from_observation(observation, random_store_token()));
        Arc::new(Self {
            configured_path,
            default_paths,
            default_managed_selected: std::sync::atomic::AtomicBool::new(default_managed_selected),
            source,
            snapshot: RwLock::new(snapshot),
            writer: tokio::sync::Mutex::new(monitoring),
            storage,
            receipt_key: receipt::ReceiptKey::generate(),
        })
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.snapshot.read().expect("policy store snapshot lock poisoned"))
    }

    pub fn active_policy(&self) -> Option<Arc<PolicyDocument>> {
        self.snapshot().policy.clone()
    }

    pub fn management_snapshot(&self) -> PolicyManagementSnapshot {
        let snapshot = self.snapshot();
        management_from_snapshot(&snapshot, self.source)
    }

    fn observation_path(&self) -> PathBuf {
        match &self.default_paths {
            Some([managed, _]) if self.default_managed_selected.load(std::sync::atomic::Ordering::Acquire) => {
                managed.clone()
            }
            Some([managed, legacy]) => {
                let selected = windows::select_default_policy_path(managed.clone(), legacy.clone());
                if crate::policy_security::windows_paths_equal(&selected, managed) {
                    self.default_managed_selected
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                selected
            }
            None => self.configured_path.clone(),
        }
    }

    fn observe_storage(&self, retain_for_write: bool) -> (PathBuf, Observation) {
        let path = self.observation_path();
        let observation = if retain_for_write {
            self.storage.observe_for_write(self.source, &path)
        } else {
            self.storage.observe(self.source, &path)
        };
        let Some([managed, legacy]) = &self.default_paths else {
            return (path, observation);
        };
        if self.default_managed_selected.load(std::sync::atomic::Ordering::Acquire)
            || crate::policy_security::windows_paths_equal(&path, managed)
        {
            return (path, observation);
        }

        let final_path = windows::select_default_policy_path(managed.clone(), legacy.clone());
        if crate::policy_security::windows_paths_equal(&final_path, managed) {
            self.default_managed_selected
                .store(true, std::sync::atomic::Ordering::Release);
            if retain_for_write {
                (
                    final_path.clone(),
                    self.storage.observe_for_write(self.source, &final_path),
                )
            } else {
                (final_path.clone(), self.storage.observe(self.source, &final_path))
            }
        } else {
            (path, observation)
        }
    }

    pub(crate) fn watched_paths(&self) -> Vec<PathBuf> {
        match &self.default_paths {
            Some(paths) => paths.to_vec(),
            None => vec![self.configured_path.clone()],
        }
    }

    pub fn validate_draft(&self, raw: &serde_json::Value) -> PolicyValidationResult {
        let mut result = validation::validate_draft(raw);
        if let Some(draft) = &result.canonical_draft {
            result.validation_receipt = Some(self.receipt_key.issue(
                &result.validator_version,
                draft,
                &result.findings,
            ));
        }
        result
    }

    pub async fn reload_from_disk(&self, cause: ReloadCause) -> PolicyManagementSnapshot {
        let monitoring = self.writer.lock().await;
        if *monitoring != Monitoring::Available {
            return self.management_snapshot();
        }
        let (_, observation) = self.observe_storage(false);
        let management = self.publish_observation(observation);
        tracing::info!(?cause, state = ?management.state, "Reloaded package broker policy");
        management
    }

    pub(crate) async fn mark_monitoring_ready(&self) -> PolicyManagementSnapshot {
        let mut monitoring = self.writer.lock().await;
        if *monitoring != Monitoring::Initializing {
            return self.management_snapshot();
        }
        let (_, observation) = self.observe_storage(false);
        let management = self.publish_observation(observation);
        *monitoring = Monitoring::Available;
        management
    }

    pub(crate) async fn mark_watcher_unavailable(&self) {
        let mut monitoring = self.writer.lock().await;
        *monitoring = Monitoring::Unavailable;
        let previous = self.snapshot();
        let observation = Observation {
            state: PolicyManagementState::Invalid,
            policy: None,
            invalid_diagnostics: Some(InvalidPolicyDiagnostics {
                diagnostics_version: API_VERSION_STR.into(),
                findings: vec![validation::disk_failure_finding(
                    validation::DiskFailureReason::WatcherUnavailable,
                )],
            }),
            write_capability: PolicyWriteCapability::ReadOnly,
            read_only_reason: Some(PolicyReadOnlyReason::ManagementDisabled),
            canonical_path: previous.configured_path.clone(),
            fingerprint: windows::unavailable_fingerprint(previous.configured_path.clone()),
            hosting_dir: None,
            retained_target: None,
        };
        self.publish_observation(observation);
    }

    pub async fn replace(&self, request: PolicyReplacementRequest) -> Result<ReplaceSuccess, ErrorResponse> {
        let monitoring = self.writer.lock().await;
        if *monitoring != Monitoring::Available {
            return Err(error_with_management(
                ErrorCode::BrokerPaused,
                "policy change monitoring is unavailable",
                self.management_snapshot(),
            ));
        }
        let previous = self.snapshot();
        let (write_configured_path, mut observation) = self.observe_storage(true);
        let fresh_token = token_for(&previous, &observation.fingerprint);

        // Both conflict modes require this exact token.
        // ConfirmOverwrite records retry intent without retaining token history.
        if fresh_token != request.expected_store_token {
            let management = self.publish_observation(observation);
            return Err(error_with_management(
                ErrorCode::StalePolicyStoreToken,
                "the configured policy changed after the supplied store token was observed",
                management,
            ));
        }

        if observation.write_capability != PolicyWriteCapability::Writable {
            let code = match observation.read_only_reason {
                Some(PolicyReadOnlyReason::UnsupportedFileSystem) => ErrorCode::UnsupportedPolicyFilesystem,
                Some(PolicyReadOnlyReason::UnsupportedFormat) => ErrorCode::UnsupportedPolicyFormat,
                _ => ErrorCode::UnsafePolicyPath,
            };
            return Err(error_response(code, "the configured policy path is not writable"));
        }

        let validation = self.validate_draft(&request.draft);
        if !validation.is_valid {
            return Err(error_with_validation(
                ErrorCode::InvalidPolicy,
                "the submitted draft failed authoritative validation",
                validation,
            ));
        }
        let draft = validation
            .canonical_draft
            .clone()
            .expect("valid validation carries a canonical draft");
        if !self.receipt_key.verify(
            &validation.validator_version,
            &draft,
            &validation.findings,
            &request.validation_receipt,
        ) {
            return Err(error_with_validation(
                ErrorCode::ValidationFailed,
                "the validation receipt does not match this draft",
                validation,
            ));
        }
        if !validation.findings.is_empty() && !request.warnings_acknowledged {
            return Err(error_with_validation(
                ErrorCode::WarningConfirmationRequired,
                "validation warnings must be explicitly acknowledged",
                validation,
            ));
        }

        let revision = plan_revision(
            request.operation,
            observation.state,
            observation.policy.as_ref(),
            &draft.metadata.id.0,
        )
        .map_err(|message| error_response(ErrorCode::Conflict, message))?;
        let policy = draft.into_policy_document(revision, Utc::now()).map_err(|_| {
            error_response(
                ErrorCode::ValidationFailed,
                "failed to commit the validated policy draft",
            )
        })?;
        let bytes = serde_json::to_vec_pretty(&policy)
            .map_err(|_| error_response(ErrorCode::InternalError, "failed to serialize the committed policy"))?;

        let persisted = if request.operation == PolicyReplacementOperation::Create {
            self.storage.create(&write_configured_path, &observation, &bytes)
        } else {
            self.storage.replace(&write_configured_path, &mut observation, &bytes)
        };
        let persisted = match persisted {
            Ok(persisted) => persisted,
            Err(WriteFailure::PrePublication(error)) => {
                tracing::warn!(error = format!("{error:#}"), "Policy persistence failed");
                let (_, current) = self.observe_storage(false);
                if current.fingerprint != observation.fingerprint {
                    let management = self.publish_observation(current);
                    return Err(error_with_management(
                        ErrorCode::StalePolicyStoreToken,
                        "the policy storage changed before publication; retry with the current store token",
                        management,
                    ));
                }
                return Err(error_response(
                    ErrorCode::PolicyPersistenceFailed,
                    "failed to persist the policy",
                ));
            }
            Err(WriteFailure::ConcurrentChange(error)) => {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "Conditional policy publication observed a concurrent storage change"
                );
                let (_, current) = self.observe_storage(false);
                if current.fingerprint == observation.fingerprint {
                    return Err(error_response(
                        ErrorCode::PolicyPersistenceFailed,
                        "failed to conditionally persist the policy",
                    ));
                }
                let management = self.publish_observation(current);
                return Err(error_with_management(
                    ErrorCode::StalePolicyStoreToken,
                    "the policy storage changed during publication; retry with the current store token",
                    management,
                ));
            }
            Err(WriteFailure::PostPublication(error)) => {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "Published policy failed authoritative reload"
                );
                let (_, current) = self.observe_storage(false);
                let management = self.publish_observation(current);
                return Err(error_with_management(
                    ErrorCode::PolicyActivationFailed,
                    "the policy was published but failed authoritative reload",
                    management,
                ));
            }
        };

        let token = token_for(&previous, &persisted.fingerprint);
        let snapshot = Arc::new(Snapshot {
            state: PolicyManagementState::Active,
            policy: Some(Arc::new(persisted.policy.clone())),
            invalid_diagnostics: None,
            write_capability: observation.write_capability,
            read_only_reason: observation.read_only_reason,
            configured_path: observation.canonical_path,
            store_token: token,
            fingerprint: persisted.fingerprint,
        });
        *self.snapshot.write().expect("policy store snapshot lock poisoned") = snapshot;

        Ok(ReplaceSuccess {
            policy: persisted.policy,
            validation,
            management: self.management_snapshot(),
        })
    }

    fn publish_observation(&self, observation: Observation) -> PolicyManagementSnapshot {
        let previous = self.snapshot();
        if previous.fingerprint == observation.fingerprint
            && previous.write_capability == observation.write_capability
            && previous.read_only_reason == observation.read_only_reason
        {
            return management_from_snapshot(&previous, self.source);
        }
        let token = token_for(&previous, &observation.fingerprint);
        let snapshot = Arc::new(snapshot_from_observation(observation, token));
        let management = management_from_snapshot(&snapshot, self.source);
        *self.snapshot.write().expect("policy store snapshot lock poisoned") = snapshot;
        management
    }

    #[cfg(test)]
    pub(crate) fn for_tests(policy: Option<PolicyDocument>) -> Arc<Self> {
        let storage = Arc::new(TestStorage::new(policy));
        Self::load_with_storage(Some(PathBuf::from(r"C:\policy.json")), storage, Monitoring::Available)
    }

    #[cfg(test)]
    pub(crate) fn test_set_active(&self, policy: Arc<PolicyDocument>) {
        let previous = self.snapshot();
        let bytes = serde_json::to_vec(policy.as_ref()).expect("test policy serializes");
        let fingerprint = DiskFingerprint::test_active(&bytes, 1, 1, 1, 1);
        let snapshot = Arc::new(Snapshot {
            state: PolicyManagementState::Active,
            policy: Some(policy),
            invalid_diagnostics: None,
            write_capability: PolicyWriteCapability::Writable,
            read_only_reason: None,
            configured_path: previous.configured_path.clone(),
            store_token: token_for(&previous, &fingerprint),
            fingerprint,
        });
        *self.snapshot.write().expect("policy store snapshot lock poisoned") = snapshot;
    }
}

fn plan_revision(
    operation: PolicyReplacementOperation,
    state: PolicyManagementState,
    current_policy: Option<&PolicyDocument>,
    new_id: &str,
) -> Result<u32, String> {
    match operation {
        PolicyReplacementOperation::Update => {
            let current = current_policy.ok_or_else(|| "Update requires an Active policy".to_owned())?;
            if current.metadata.id.0 != new_id {
                return Err("Update must preserve the active policy identity".to_owned());
            }
            current
                .metadata
                .revision
                .checked_add(1)
                .filter(|revision| i32::try_from(*revision).is_ok())
                .ok_or_else(|| "the policy revision reached its maximum value".to_owned())
        }
        PolicyReplacementOperation::ReplaceIdentity => {
            let current = current_policy.ok_or_else(|| "ReplaceIdentity requires an Active policy".to_owned())?;
            if current.metadata.id.0 == new_id {
                return Err("ReplaceIdentity requires a different policy identity".to_owned());
            }
            Ok(1)
        }
        PolicyReplacementOperation::Create if state == PolicyManagementState::Missing => Ok(1),
        PolicyReplacementOperation::Repair if state == PolicyManagementState::Invalid => Ok(1),
        PolicyReplacementOperation::Create => Err("Create requires a Missing policy".to_owned()),
        PolicyReplacementOperation::Repair => Err("Repair requires an Invalid policy".to_owned()),
    }
}

fn snapshot_from_observation(observation: Observation, store_token: PolicyStoreToken) -> Snapshot {
    Snapshot {
        state: observation.state,
        policy: observation.policy.map(Arc::new),
        invalid_diagnostics: observation.invalid_diagnostics,
        write_capability: observation.write_capability,
        read_only_reason: observation.read_only_reason,
        configured_path: observation.canonical_path,
        store_token,
        fingerprint: observation.fingerprint,
    }
}

fn management_from_snapshot(snapshot: &Snapshot, source: PolicyConfigurationSource) -> PolicyManagementSnapshot {
    PolicyManagementSnapshot {
        state: snapshot.state,
        configured_path: snapshot.configured_path.display().to_string(),
        store_token: snapshot.store_token.clone(),
        source,
        write_capability: snapshot.write_capability,
        read_only_reason: snapshot.read_only_reason,
        elevation_required: true,
        policy: snapshot.policy.as_deref().cloned(),
        invalid_diagnostics: snapshot.invalid_diagnostics.clone(),
    }
}

fn token_for(previous: &Snapshot, fingerprint: &DiskFingerprint) -> PolicyStoreToken {
    if previous.fingerprint == *fingerprint {
        previous.store_token.clone()
    } else {
        random_store_token()
    }
}

fn random_store_token() -> PolicyStoreToken {
    windows::random_store_token()
}

fn error_response(code: ErrorCode, message: impl Into<String>) -> ErrorResponse {
    ErrorResponse {
        response_kind: ErrorResponseKind,
        response_version: API_VERSION_STR.into(),
        server: ServerContext {
            server_version: env!("CARGO_PKG_VERSION").to_owned(),
            transport: Transport::HttpNamedPipe,
        },
        code,
        message: message.into(),
        details: Vec::new(),
        validation: None,
        management: None,
    }
}

fn error_with_validation(
    code: ErrorCode,
    message: impl Into<String>,
    validation: PolicyValidationResult,
) -> ErrorResponse {
    let mut response = error_response(code, message);
    response.validation = Some(validation);
    response
}

fn error_with_management(
    code: ErrorCode,
    message: impl Into<String>,
    management: PolicyManagementSnapshot,
) -> ErrorResponse {
    let mut response = error_response(code, message);
    response.management = Some(management);
    response
}

#[cfg(test)]
fn observe_file(source: PolicyConfigurationSource, path: &Path) -> Observation {
    windows::observe(source, path, &windows::AtomicityProbeCache::new())
}

#[cfg(test)]
struct TestStorage {
    observation: parking_lot::Mutex<Observation>,
    fail_persist: std::sync::atomic::AtomicBool,
    fail_concurrent_check: std::sync::atomic::AtomicBool,
    fail_target_retention: std::sync::atomic::AtomicBool,
    race_before_persist: parking_lot::Mutex<Option<PolicyDocument>>,
}

#[cfg(test)]
impl TestStorage {
    fn new(policy: Option<PolicyDocument>) -> Self {
        Self {
            observation: parking_lot::Mutex::new(test_observation(policy, false, 0)),
            fail_persist: std::sync::atomic::AtomicBool::new(false),
            fail_concurrent_check: std::sync::atomic::AtomicBool::new(false),
            fail_target_retention: std::sync::atomic::AtomicBool::new(false),
            race_before_persist: parking_lot::Mutex::new(None),
        }
    }

    fn invalid() -> Self {
        Self {
            observation: parking_lot::Mutex::new(test_observation(None, true, 1)),
            fail_persist: std::sync::atomic::AtomicBool::new(false),
            fail_concurrent_check: std::sync::atomic::AtomicBool::new(false),
            fail_target_retention: std::sync::atomic::AtomicBool::new(false),
            race_before_persist: parking_lot::Mutex::new(None),
        }
    }

    fn set_disk_state(&self, policy: Option<PolicyDocument>, invalid: bool, marker: u8) {
        *self.observation.lock() = test_observation(policy, invalid, marker);
    }

    fn race_before_next_persist(&self, policy: PolicyDocument) {
        *self.race_before_persist.lock() = Some(policy);
    }
}

#[cfg(test)]
impl PolicyStorage for TestStorage {
    fn observe(&self, _source: PolicyConfigurationSource, _path: &Path) -> Observation {
        clone_observation(&self.observation.lock())
    }

    fn observe_for_write(&self, source: PolicyConfigurationSource, path: &Path) -> Observation {
        let mut observation = self.observe(source, path);
        if observation.state != PolicyManagementState::Missing
            && !self
                .fail_target_retention
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            observation.retained_target = Some(windows::RetainedPolicyFile::for_fake(observation.fingerprint.clone()));
        }
        observation
    }

    fn create(
        &self,
        _configured_path: &Path,
        observation: &Observation,
        bytes: &[u8],
    ) -> Result<PersistedPolicy, WriteFailure> {
        self.persist(observation, bytes)
    }

    fn replace(
        &self,
        _configured_path: &Path,
        observation: &mut Observation,
        bytes: &[u8],
    ) -> Result<PersistedPolicy, WriteFailure> {
        let retained = observation
            .retained_target
            .take()
            .ok_or_else(|| WriteFailure::ConcurrentChange(anyhow::anyhow!("missing retained test target")))?;
        retained
            .verify_matches(&observation.fingerprint)
            .map_err(WriteFailure::ConcurrentChange)?;
        self.persist(observation, bytes)
    }
}

#[cfg(test)]
impl TestStorage {
    fn persist(&self, observation: &Observation, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure> {
        if self.fail_persist.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(WriteFailure::PrePublication(anyhow::anyhow!(
                "injected persistence failure"
            )));
        }
        if self
            .fail_concurrent_check
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(WriteFailure::ConcurrentChange(anyhow::anyhow!(
                "injected identity query failure"
            )));
        }
        if let Some(external) = self.race_before_persist.lock().take() {
            *self.observation.lock() = test_observation(Some(external), false, 9);
            return Err(WriteFailure::ConcurrentChange(anyhow::anyhow!(
                "injected external policy replacement"
            )));
        }
        let policy: PolicyDocument =
            serde_json::from_slice(bytes).map_err(|error| WriteFailure::PrePublication(error.into()))?;
        let mut next = clone_observation(observation);
        next.state = PolicyManagementState::Active;
        next.policy = Some(policy.clone());
        next.invalid_diagnostics = None;
        next.fingerprint = DiskFingerprint::test_active(bytes, 2, 1, 1, 1);
        *self.observation.lock() = clone_observation(&next);
        Ok(PersistedPolicy {
            policy,
            fingerprint: next.fingerprint,
        })
    }
}

#[cfg(test)]
fn test_observation(policy: Option<PolicyDocument>, invalid: bool, marker: u8) -> Observation {
    let state = if invalid {
        PolicyManagementState::Invalid
    } else if policy.is_some() {
        PolicyManagementState::Active
    } else {
        PolicyManagementState::Missing
    };
    let bytes = policy
        .as_ref()
        .map(|policy| serde_json::to_vec(policy).expect("test policy serializes"))
        .unwrap_or_default();
    let fingerprint = match state {
        PolicyManagementState::Active => DiskFingerprint::test_active(&bytes, marker.into(), 1, 1, 1),
        PolicyManagementState::Missing => DiskFingerprint::test_missing(marker.into(), 1),
        PolicyManagementState::Invalid => DiskFingerprint::test_invalid(&bytes, marker.into(), 1, 1, 1),
    };
    Observation {
        state,
        policy,
        invalid_diagnostics: invalid.then(|| InvalidPolicyDiagnostics {
            diagnostics_version: API_VERSION_STR.into(),
            findings: vec![validation::disk_failure_finding(
                validation::DiskFailureReason::MalformedContent,
            )],
        }),
        fingerprint,
        write_capability: PolicyWriteCapability::Writable,
        read_only_reason: None,
        canonical_path: PathBuf::from(r"C:\policy.json"),
        hosting_dir: Some(windows::VerifiedHostingDirectory::for_fake_storage(
            PathBuf::from(r"C:\"),
            windows::test_identity(1),
            windows::test_security_digest(1),
        )),
        retained_target: None,
    }
}

#[cfg(test)]
fn clone_observation(observation: &Observation) -> Observation {
    Observation {
        state: observation.state,
        policy: observation.policy.clone(),
        invalid_diagnostics: observation.invalid_diagnostics.clone(),
        write_capability: observation.write_capability,
        read_only_reason: observation.read_only_reason,
        canonical_path: observation.canonical_path.clone(),
        fingerprint: observation.fingerprint.clone(),
        hosting_dir: Some(windows::VerifiedHostingDirectory::for_fake_storage(
            PathBuf::from(r"C:\"),
            windows::test_identity(1),
            windows::test_security_digest(1),
        )),
        retained_target: None,
    }
}

#[cfg(test)]
mod storage_tests {
    use now_policy::PolicyDraftDocument;
    use now_policy_api::{PolicyConflictHandling, PolicyReplacementRequestKind};

    struct DefaultTransitionStorage {
        managed: PathBuf,
        legacy_policy: PolicyDocument,
        managed_policy: parking_lot::RwLock<Option<PolicyDocument>>,
        publish_managed_while_observing_legacy: std::sync::atomic::AtomicBool,
    }

    impl PolicyStorage for DefaultTransitionStorage {
        fn observe(&self, _source: PolicyConfigurationSource, path: &Path) -> Observation {
            let managed = crate::policy_security::windows_paths_equal(path, &self.managed);
            if !managed
                && self
                    .publish_managed_while_observing_legacy
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                std::fs::create_dir_all(self.managed.parent().expect("managed path has a parent"))
                    .expect("create managed directory");
                std::fs::write(&self.managed, b"managed").expect("publish managed marker");
            }
            let (policy, invalid, marker) = if managed {
                let managed_policy = self.managed_policy.read().clone();
                let invalid = managed_policy.is_none();
                (managed_policy, invalid, 9)
            } else {
                (Some(self.legacy_policy.clone()), false, 1)
            };
            let mut observation = test_observation(policy, invalid, marker);
            observation.canonical_path = path.to_owned();
            observation
        }

        fn create(
            &self,
            _configured_path: &Path,
            _observation: &Observation,
            _bytes: &[u8],
        ) -> Result<PersistedPolicy, WriteFailure> {
            unreachable!("default transition tests do not write")
        }

        fn replace(
            &self,
            _configured_path: &Path,
            _observation: &mut Observation,
            _bytes: &[u8],
        ) -> Result<PersistedPolicy, WriteFailure> {
            unreachable!("default transition tests do not write")
        }
    }

    fn default_transition_store(paths: [PathBuf; 2], storage: Arc<DefaultTransitionStorage>) -> Arc<PolicyStore> {
        let configured_path = windows::select_default_policy_path(paths[0].clone(), paths[1].clone());
        let managed_selected = crate::policy_security::windows_paths_equal(&configured_path, &paths[0]);
        let observation = storage.observe(PolicyConfigurationSource::DefaultPath, &configured_path);
        Arc::new(PolicyStore {
            configured_path,
            default_paths: Some(paths),
            default_managed_selected: std::sync::atomic::AtomicBool::new(managed_selected),
            source: PolicyConfigurationSource::DefaultPath,
            snapshot: RwLock::new(Arc::new(snapshot_from_observation(observation, random_store_token()))),
            writer: tokio::sync::Mutex::new(Monitoring::Available),
            storage,
            receipt_key: receipt::ReceiptKey::generate(),
        })
    }

    use super::*;

    fn draft(id: &str) -> PolicyDraftDocument {
        serde_json::from_value(serde_json::json!({
            "$schema": now_policy::POLICY_DRAFT_SCHEMA_URI,
            "PolicyVersion": "1.0.0",
            "PolicyType": "PackageBrokerPolicy",
            "Metadata": { "Id": id, "Publisher": "Test" },
            "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
            "Rules": []
        }))
        .expect("valid draft")
    }

    fn policy(id: &str, revision: u32) -> PolicyDocument {
        draft(id)
            .into_policy_document(revision, Utc::now())
            .expect("valid committed policy")
    }

    fn update_request(store: &PolicyStore) -> PolicyReplacementRequest {
        let raw = serde_json::to_value(draft("current")).expect("serialize draft");
        let validation = store.validate_draft(&raw);
        PolicyReplacementRequest {
            request_kind: PolicyReplacementRequestKind,
            request_version: API_VERSION_STR.into(),
            expected_store_token: store.management_snapshot().store_token,
            operation: PolicyReplacementOperation::Update,
            conflict_handling: PolicyConflictHandling::Reject,
            warnings_acknowledged: false,
            draft: raw,
            validation_receipt: validation.validation_receipt.expect("valid receipt"),
        }
    }

    #[tokio::test]
    async fn concurrent_external_replacement_is_preserved_and_published() {
        let storage = Arc::new(TestStorage::new(Some(policy("current", 1))));
        let store = PolicyStore::load_with_storage(
            Some(PathBuf::from(r"C:\policy.json")),
            Arc::clone(&storage) as Arc<dyn PolicyStorage>,
            Monitoring::Available,
        );
        let request = update_request(&store);
        storage.race_before_next_persist(policy("external", 7));

        let error = store.replace(request).await.expect_err("external replacement wins");

        assert_eq!(error.code, ErrorCode::StalePolicyStoreToken);
        assert_eq!(
            store.active_policy().expect("external policy is active").metadata.id.0,
            "external"
        );
        assert_eq!(
            store
                .active_policy()
                .expect("external policy is active")
                .metadata
                .revision,
            7
        );
    }

    #[tokio::test]
    async fn failed_identity_check_without_change_is_a_persistence_failure() {
        let storage = Arc::new(TestStorage::new(Some(policy("current", 1))));
        let store = PolicyStore::load_with_storage(
            Some(PathBuf::from(r"C:\policy.json")),
            Arc::clone(&storage) as Arc<dyn PolicyStorage>,
            Monitoring::Available,
        );
        let request = update_request(&store);
        let previous_token = store.management_snapshot().store_token;
        storage
            .fail_concurrent_check
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let error = store.replace(request).await.expect_err("identity check fails");

        assert_eq!(error.code, ErrorCode::PolicyPersistenceFailed);
        assert_eq!(store.management_snapshot().store_token, previous_token);
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
    async fn failed_target_retention_preserves_the_active_snapshot() {
        let storage = Arc::new(TestStorage::new(Some(policy("current", 1))));
        let store = PolicyStore::load_with_storage(
            Some(PathBuf::from(r"C:\policy.json")),
            Arc::clone(&storage) as Arc<dyn PolicyStorage>,
            Monitoring::Available,
        );
        let request = update_request(&store);
        let previous_token = store.management_snapshot().store_token;
        storage
            .fail_target_retention
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let error = store.replace(request).await.expect_err("target retention fails");

        assert_eq!(error.code, ErrorCode::PolicyPersistenceFailed);
        assert_eq!(store.management_snapshot().store_token, previous_token);
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
    async fn default_store_switches_from_legacy_when_managed_policy_appears() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let managed = dir.path().join("PackageBroker").join(windows::POLICY_FILE_NAME);
        let legacy = dir.path().join("Agent").join(windows::POLICY_FILE_NAME);
        std::fs::create_dir_all(legacy.parent().expect("legacy path has a parent")).expect("create legacy directory");
        std::fs::write(&legacy, b"legacy").expect("write legacy marker");
        let storage = Arc::new(DefaultTransitionStorage {
            managed: managed.clone(),
            legacy_policy: policy("legacy", 1),
            managed_policy: parking_lot::RwLock::new(Some(policy("managed", 2))),
            publish_managed_while_observing_legacy: std::sync::atomic::AtomicBool::new(false),
        });
        let store = default_transition_store([managed.clone(), legacy], Arc::clone(&storage));
        assert_eq!(
            store.active_policy().expect("legacy policy active").metadata.id.0,
            "legacy"
        );

        std::fs::create_dir_all(managed.parent().expect("managed path has a parent"))
            .expect("create managed directory");
        std::fs::write(&managed, b"managed").expect("write managed marker");
        store.reload_from_disk(ReloadCause::ExternalChange).await;

        assert_eq!(
            store.active_policy().expect("managed policy active").metadata.id.0,
            "managed"
        );
        assert_eq!(
            store.management_snapshot().configured_path,
            managed.display().to_string()
        );

        std::fs::remove_file(&managed).expect("remove managed marker");
        *storage.managed_policy.write() = None;
        store.reload_from_disk(ReloadCause::ExternalChange).await;
        assert!(store.active_policy().is_none(), "managed selection must remain sticky");
        assert_eq!(
            store.management_snapshot().configured_path,
            managed.display().to_string()
        );
    }

    #[tokio::test]
    async fn managed_transaction_evidence_after_startup_fails_closed_instead_of_using_legacy() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let managed = dir.path().join("PackageBroker").join(windows::POLICY_FILE_NAME);
        let legacy = dir.path().join("Agent").join(windows::POLICY_FILE_NAME);
        std::fs::create_dir_all(legacy.parent().expect("legacy path has a parent")).expect("create legacy directory");
        std::fs::write(&legacy, b"legacy").expect("write legacy marker");
        let storage = Arc::new(DefaultTransitionStorage {
            managed: managed.clone(),
            legacy_policy: policy("legacy", 1),
            managed_policy: parking_lot::RwLock::new(None),
            publish_managed_while_observing_legacy: std::sync::atomic::AtomicBool::new(false),
        });
        let store = default_transition_store([managed.clone(), legacy], storage);
        assert_eq!(
            store.active_policy().expect("legacy policy active").metadata.id.0,
            "legacy"
        );

        std::fs::create_dir_all(managed.parent().expect("managed path has a parent"))
            .expect("create managed directory");
        let marker = managed.parent().expect("managed path has a parent").join(format!(
            ".{}.txn-{}.marker",
            windows::POLICY_FILE_NAME,
            uuid::Uuid::new_v4()
        ));
        std::fs::write(marker, b"unsafe remnant").expect("write managed transaction marker");
        store.reload_from_disk(ReloadCause::ExternalChange).await;

        assert!(store.active_policy().is_none());
        assert_eq!(store.management_snapshot().state, PolicyManagementState::Invalid);
        assert_eq!(
            store.management_snapshot().configured_path,
            managed.display().to_string()
        );
    }

    #[tokio::test]
    async fn managed_policy_created_during_legacy_observation_is_never_published_as_legacy() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let managed = dir.path().join("PackageBroker").join(windows::POLICY_FILE_NAME);
        let legacy = dir.path().join("Agent").join(windows::POLICY_FILE_NAME);
        std::fs::create_dir_all(legacy.parent().expect("legacy path has a parent")).expect("create legacy directory");
        std::fs::write(&legacy, b"legacy").expect("write legacy marker");
        let storage = Arc::new(DefaultTransitionStorage {
            managed: managed.clone(),
            legacy_policy: policy("legacy", 1),
            managed_policy: parking_lot::RwLock::new(Some(policy("managed", 2))),
            publish_managed_while_observing_legacy: std::sync::atomic::AtomicBool::new(false),
        });
        let store = default_transition_store([managed.clone(), legacy], Arc::clone(&storage));
        assert_eq!(
            store.active_policy().expect("legacy policy active").metadata.id.0,
            "legacy"
        );
        storage
            .publish_managed_while_observing_legacy
            .store(true, std::sync::atomic::Ordering::SeqCst);

        store.reload_from_disk(ReloadCause::ExternalChange).await;

        assert_eq!(
            store.active_policy().expect("managed policy active").metadata.id.0,
            "managed"
        );
        assert_eq!(
            store.management_snapshot().configured_path,
            managed.display().to_string()
        );
    }
}
