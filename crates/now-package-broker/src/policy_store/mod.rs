//! Serialized policy management, validation, persistence, and reload.
//! Store tokens serialize API writers and reloads, not privileged out-of-band writes.
//! Conditional handle-relative publication is deferred.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::Context as _;
use chrono::Utc;
use now_policy::PolicyDocument;
use now_policy_api::{
    API_VERSION_STR, ErrorCode, ErrorResponse, ErrorResponseKind, InvalidPolicyDiagnostics, PolicyConfigurationSource,
    PolicyManagementSnapshot, PolicyManagementState, PolicyReadOnlyReason, PolicyReplacementOperation,
    PolicyReplacementRequest, PolicyStoreToken, PolicyValidationResult, PolicyWriteCapability, ServerContext,
    Transport,
};
use sha2::{Digest as _, Sha256};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx, GetVolumeInformationW,
    GetVolumePathNameW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, READ_CONTROL,
};
use windows::core::PCWSTR;

use crate::policy_security;
mod receipt;
pub mod validation;

#[derive(Clone, Copy, Debug)]
pub enum ReloadCause {
    ExternalChange,
}

#[derive(Clone, PartialEq, Eq)]
struct DiskFingerprint([u8; 32]);

struct Observation {
    state: PolicyManagementState,
    policy: Option<PolicyDocument>,
    invalid_diagnostics: Option<InvalidPolicyDiagnostics>,
    write_capability: PolicyWriteCapability,
    read_only_reason: Option<PolicyReadOnlyReason>,
    configured_path: PathBuf,
    fingerprint: DiskFingerprint,
}

struct PersistedPolicy {
    policy: PolicyDocument,
    observation: Observation,
}

enum WriteFailure {
    PrePublication(anyhow::Error),
    PostPublication(anyhow::Error),
}

trait PolicyStorage: Send + Sync {
    fn observe(&self, source: PolicyConfigurationSource, path: &Path) -> Observation;
    fn create(&self, observation: &Observation, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure>;
    fn replace(&self, observation: &Observation, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure>;
}

struct FilePolicyStorage;

impl PolicyStorage for FilePolicyStorage {
    fn observe(&self, source: PolicyConfigurationSource, path: &Path) -> Observation {
        observe_file(source, path)
    }

    fn create(&self, observation: &Observation, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure> {
        publish_file(observation, bytes, false)
    }

    fn replace(&self, observation: &Observation, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure> {
        publish_file(observation, bytes, true)
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
    source: PolicyConfigurationSource,
    snapshot: RwLock<Arc<Snapshot>>,
    writer: tokio::sync::Mutex<Monitoring>,
    storage: Arc<dyn PolicyStorage>,
    receipt_key: receipt::ReceiptKey,
}

impl PolicyStore {
    pub fn load(configured_path: Option<PathBuf>) -> Arc<Self> {
        Self::load_with_storage(configured_path, Arc::new(FilePolicyStorage), Monitoring::Initializing)
    }

    fn load_with_storage(
        configured_path: Option<PathBuf>,
        storage: Arc<dyn PolicyStorage>,
        monitoring: Monitoring,
    ) -> Arc<Self> {
        let (configured_path, source) = match configured_path {
            Some(path) => (path, PolicyConfigurationSource::ConfiguredPath),
            None => (
                crate::policy_loader::find_default_policy()
                    .unwrap_or_else(|_| crate::policy_loader::default_policy_candidate()),
                PolicyConfigurationSource::DefaultPath,
            ),
        };
        let observation = storage.observe(source, &configured_path);
        let snapshot = Arc::new(snapshot_from_observation(observation, random_store_token()));
        Arc::new(Self {
            configured_path,
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

    pub(crate) fn configured_path(&self) -> PathBuf {
        self.snapshot().configured_path.clone()
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
        let observation = self.storage.observe(self.source, &self.configured_path);
        let management = self.publish_observation(observation);
        tracing::info!(?cause, state = ?management.state, "Reloaded package broker policy");
        management
    }

    pub(crate) async fn mark_monitoring_ready(&self) -> PolicyManagementSnapshot {
        let mut monitoring = self.writer.lock().await;
        if *monitoring != Monitoring::Initializing {
            return self.management_snapshot();
        }
        let management = self.publish_observation(self.storage.observe(self.source, &self.configured_path));
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
            configured_path: previous.configured_path.clone(),
            fingerprint: DiskFingerprint(Sha256::digest(b"watcher unavailable").into()),
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
        let observation = self.storage.observe(self.source, &self.configured_path);
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
            self.storage.create(&observation, &bytes)
        } else {
            self.storage.replace(&observation, &bytes)
        };
        let persisted = match persisted {
            Ok(persisted) => persisted,
            Err(WriteFailure::PrePublication(error)) => {
                tracing::warn!(error = format!("{error:#}"), "Policy persistence failed");
                let current = self.storage.observe(self.source, &self.configured_path);
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
            Err(WriteFailure::PostPublication(error)) => {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "Published policy failed authoritative reload"
                );
                let current = self.storage.observe(self.source, &self.configured_path);
                let management = self.publish_observation(current);
                return Err(error_with_management(
                    ErrorCode::PolicyActivationFailed,
                    "the policy was published but failed authoritative reload",
                    management,
                ));
            }
        };

        if persisted.observation.state != PolicyManagementState::Active {
            let management = self.publish_observation(persisted.observation);
            return Err(error_with_management(
                ErrorCode::PolicyActivationFailed,
                "the policy was published but failed authoritative reload",
                management,
            ));
        }
        let token = token_for(&previous, &persisted.observation.fingerprint);
        let snapshot = Arc::new(snapshot_from_observation(persisted.observation, token));
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
        let fingerprint = DiskFingerprint(
            Sha256::digest(serde_json::to_vec(policy.as_ref()).expect("test policy serializes")).into(),
        );
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
        configured_path: observation.configured_path,
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
    format!("store:{}", uuid::Uuid::new_v4().simple()).into()
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

fn observe_file(_source: PolicyConfigurationSource, configured_path: &Path) -> Observation {
    let mut hasher = Sha256::new();
    for unit in configured_path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }

    if !is_safe_path_shape(configured_path) {
        return invalid_observation(
            configured_path.to_owned(),
            PolicyWriteCapability::Unsupported,
            Some(PolicyReadOnlyReason::UnsafePath),
            validation::DiskFailureReason::UnsupportedFormat,
            hasher,
        );
    }

    let extension = configured_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if extension != "json" {
        return invalid_observation(
            configured_path.to_owned(),
            PolicyWriteCapability::Unsupported,
            Some(PolicyReadOnlyReason::UnsupportedFormat),
            validation::DiskFailureReason::UnsupportedFormat,
            hasher,
        );
    }

    let display_path = match canonical_display_path(configured_path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return missing_observation(
                configured_path.to_owned(),
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::InsufficientPermissions),
                hasher,
            );
        }
        Err(error) => {
            tracing::warn!(error = %error, "Failed to resolve policy path");
            return invalid_observation(
                configured_path.to_owned(),
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
                validation::DiskFailureReason::InsecureStorage,
                hasher,
            );
        }
    };
    for unit in display_path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }

    let Some(parent) = display_path.parent() else {
        return invalid_observation(
            display_path,
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
            validation::DiskFailureReason::Unreadable,
            hasher,
        );
    };
    let directory = match open_directory(parent) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return missing_observation(
                display_path,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::InsufficientPermissions),
                hasher,
            );
        }
        Err(error) => {
            tracing::warn!(error = %error, "Failed to open policy directory");
            return invalid_observation(
                display_path,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
                validation::DiskFailureReason::InsecureStorage,
                hasher,
            );
        }
    };
    hash_file_identity(&directory, &mut hasher);
    let directory_safe = match policy_security::verify_policy_path_ancestors(configured_path)
        .and_then(|()| policy_security::verify_policy_path_ancestors(&display_path))
        .and_then(|()| {
            let current_path = canonical_display_path(configured_path)
                .context("failed to resolve policy path after security validation")?;
            if policy_security::windows_paths_equal(&display_path, &current_path) {
                Ok(())
            } else {
                anyhow::bail!("policy path canonical chain changed during security validation")
            }
        })
        .and_then(|()| policy_security::verify_policy_directory_security(&directory))
        .and_then(|()| policy_security::security_state_digest(&directory))
    {
        Ok(digest) => {
            hasher.update(digest);
            true
        }
        Err(error) => {
            tracing::warn!(
                error = format!("{error:#}"),
                "Policy directory security validation failed"
            );
            false
        }
    };
    if !directory_safe {
        return invalid_observation(
            display_path,
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
            validation::DiskFailureReason::InsecureStorage,
            hasher,
        );
    }
    let atomic_filesystem = directory_safe && supports_atomic_replace(parent);
    let capability = if !atomic_filesystem {
        PolicyWriteCapability::Unsupported
    } else {
        PolicyWriteCapability::Writable
    };
    let read_only_reason = match capability {
        PolicyWriteCapability::Writable => None,
        PolicyWriteCapability::Unsupported => Some(PolicyReadOnlyReason::UnsupportedFileSystem),
        PolicyWriteCapability::ReadOnly => unreachable!("unsafe directories returned above"),
    };

    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(&display_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return missing_observation(display_path, capability, read_only_reason, hasher);
        }
        Err(error) => {
            tracing::warn!(error = %error, "Failed to open configured policy");
            return invalid_observation(
                display_path,
                capability,
                read_only_reason,
                validation::DiskFailureReason::Unreadable,
                hasher,
            );
        }
    };
    hash_file_identity(&file, &mut hasher);
    if let Err(error) = policy_security::verify_policy_file_path(&file, &display_path)
        .and_then(|()| policy_security::verify_policy_file_security(&file))
    {
        tracing::warn!(
            error = format!("{error:#}"),
            "Configured policy security validation failed"
        );
        return invalid_observation(
            display_path,
            PolicyWriteCapability::ReadOnly,
            Some(PolicyReadOnlyReason::UnsafePath),
            validation::DiskFailureReason::InsecureStorage,
            hasher,
        );
    }
    match policy_security::security_state_digest(&file) {
        Ok(digest) => hasher.update(digest),
        Err(error) => {
            tracing::warn!(
                error = format!("{error:#}"),
                "Failed to fingerprint configured policy security"
            );
            return invalid_observation(
                display_path,
                PolicyWriteCapability::ReadOnly,
                Some(PolicyReadOnlyReason::UnsafePath),
                validation::DiskFailureReason::InsecureStorage,
                hasher,
            );
        }
    }
    let mut bytes = Vec::new();
    if let Err(error) = file.read_to_end(&mut bytes) {
        tracing::warn!(error = %error, "Failed to read configured policy");
        return invalid_observation(
            display_path,
            capability,
            read_only_reason,
            validation::DiskFailureReason::Unreadable,
            hasher,
        );
    }
    hasher.update(&bytes);
    let policy = serde_json::from_slice::<PolicyDocument>(&bytes);
    let policy = match policy {
        Ok(policy) => policy,
        Err(error) => {
            tracing::warn!(error = %error, "Configured policy parsing failed");
            return invalid_observation(
                display_path,
                capability,
                read_only_reason,
                validation::DiskFailureReason::MalformedContent,
                hasher,
            );
        }
    };
    let committed_validation = validation::validate_committed_policy(&policy);
    if !committed_validation.is_valid {
        tracing::warn!(
            findings = ?committed_validation.findings,
            "Configured policy semantic validation failed"
        );
        return invalid_observation(
            display_path,
            capability,
            read_only_reason,
            validation::DiskFailureReason::FailedSemanticValidation,
            hasher,
        );
    }

    Observation {
        state: PolicyManagementState::Active,
        policy: Some(policy),
        invalid_diagnostics: None,
        write_capability: capability,
        read_only_reason,
        configured_path: display_path,
        fingerprint: DiskFingerprint(hasher.finalize().into()),
    }
}

fn publish_file(observation: &Observation, bytes: &[u8], replace: bool) -> Result<PersistedPolicy, WriteFailure> {
    let path = &observation.configured_path;
    let parent = path
        .parent()
        .ok_or_else(|| WriteFailure::PrePublication(anyhow::anyhow!("policy path has no parent")))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| WriteFailure::PrePublication(anyhow::anyhow!("policy path has no file name")))?;
    let temp_path = parent.join(format!(
        ".{}.{}.tmp",
        leaf.to_string_lossy(),
        uuid::Uuid::new_v4().simple()
    ));
    let prepared = (|| {
        let mut temp = OpenOptions::new().write(true).create_new(true).open(&temp_path)?;
        temp.write_all(bytes)?;
        temp.sync_all()?;
        policy_security::verify_policy_file_security(&temp)?;
        drop(temp);

        let from = wide_path(&temp_path);
        let to = wide_path(path);
        let flags = if replace {
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        } else {
            MOVEFILE_WRITE_THROUGH
        };
        // SAFETY: Both buffers are live, nul-terminated absolute paths.
        unsafe { MoveFileExW(PCWSTR(from.as_ptr()), PCWSTR(to.as_ptr()), flags) }?;
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = prepared {
        let _ = std::fs::remove_file(&temp_path);
        return Err(WriteFailure::PrePublication(error));
    }

    let reloaded = (|| {
        let reloaded = observe_file(PolicyConfigurationSource::ConfiguredPath, path);
        let policy = reloaded
            .policy
            .clone()
            .ok_or_else(|| anyhow::anyhow!("published policy failed authoritative reload"))?;
        let expected: serde_json::Value = serde_json::from_slice(bytes)?;
        if serde_json::to_value(&policy)? != expected {
            anyhow::bail!("published policy does not match the requested committed document");
        }
        Ok(PersistedPolicy {
            policy,
            observation: reloaded,
        })
    })();
    reloaded.map_err(WriteFailure::PostPublication)
}

fn missing_observation(
    path: PathBuf,
    capability: PolicyWriteCapability,
    reason: Option<PolicyReadOnlyReason>,
    mut hasher: Sha256,
) -> Observation {
    hasher.update(b"missing");
    Observation {
        state: PolicyManagementState::Missing,
        policy: None,
        invalid_diagnostics: None,
        write_capability: capability,
        read_only_reason: reason,
        configured_path: path,
        fingerprint: DiskFingerprint(hasher.finalize().into()),
    }
}

fn invalid_observation(
    path: PathBuf,
    capability: PolicyWriteCapability,
    reason: Option<PolicyReadOnlyReason>,
    failure: validation::DiskFailureReason,
    mut hasher: Sha256,
) -> Observation {
    hasher.update(format!("{failure:?}"));
    Observation {
        state: PolicyManagementState::Invalid,
        policy: None,
        invalid_diagnostics: Some(InvalidPolicyDiagnostics {
            diagnostics_version: API_VERSION_STR.into(),
            findings: vec![validation::disk_failure_finding(failure)],
        }),
        write_capability: capability,
        read_only_reason: reason,
        configured_path: path,
        fingerprint: DiskFingerprint(hasher.finalize().into()),
    }
}

fn is_safe_path_shape(path: &Path) -> bool {
    let raw = path.as_os_str().to_string_lossy();
    path.is_absolute()
        && path.file_name().is_some()
        && !raw.split(['\\', '/']).any(|segment| matches!(segment, "." | ".."))
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn canonical_display_path(path: &Path) -> std::io::Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "policy path has no parent"))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "policy path has no file name"))?;
    Ok(parent.canonicalize()?.join(leaf))
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(path)
}

fn supports_atomic_replace(path: &Path) -> bool {
    let path = wide_path(path);
    let mut root = vec![0; 512];
    // SAFETY: The path is nul-terminated and the root buffer is writable.
    if unsafe { GetVolumePathNameW(PCWSTR(path.as_ptr()), &mut root) }.is_err() {
        return false;
    }
    let mut filesystem = vec![0; 261];
    // SAFETY: GetVolumePathNameW returned a nul-terminated root and the output buffer is writable.
    if unsafe { GetVolumeInformationW(PCWSTR(root.as_ptr()), None, None, None, None, Some(&mut filesystem)) }.is_err() {
        return false;
    }
    let length = filesystem
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(filesystem.len());
    matches!(
        String::from_utf16_lossy(&filesystem[..length]).as_str(),
        "NTFS" | "ReFS"
    )
}

fn hash_file_identity(file: &File, hasher: &mut Sha256) {
    let mut info = FILE_ID_INFO::default();
    let size = u32::try_from(size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits u32");
    // SAFETY: The file handle and correctly sized output buffer are valid for the call.
    if unsafe { GetFileInformationByHandleEx(HANDLE(file.as_raw_handle()), FileIdInfo, (&raw mut info).cast(), size) }
        .is_ok()
    {
        hasher.update(info.VolumeSerialNumber.to_le_bytes());
        hasher.update(info.FileId.Identifier);
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
struct TestStorage {
    observation: parking_lot::Mutex<Observation>,
    fail_persist: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl TestStorage {
    fn new(policy: Option<PolicyDocument>) -> Self {
        let state = if policy.is_some() {
            PolicyManagementState::Active
        } else {
            PolicyManagementState::Missing
        };
        Self {
            observation: parking_lot::Mutex::new(Observation {
                state,
                policy,
                invalid_diagnostics: None,
                write_capability: PolicyWriteCapability::Writable,
                read_only_reason: None,
                configured_path: PathBuf::from(r"C:\policy.json"),
                fingerprint: DiskFingerprint([0; 32]),
            }),
            fail_persist: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn invalid() -> Self {
        let mut storage = Self::new(None);
        storage.observation = parking_lot::Mutex::new(Observation {
            state: PolicyManagementState::Invalid,
            policy: None,
            invalid_diagnostics: Some(InvalidPolicyDiagnostics {
                diagnostics_version: API_VERSION_STR.into(),
                findings: vec![validation::disk_failure_finding(
                    validation::DiskFailureReason::MalformedContent,
                )],
            }),
            write_capability: PolicyWriteCapability::Writable,
            read_only_reason: None,
            configured_path: PathBuf::from(r"C:\policy.json"),
            fingerprint: DiskFingerprint([1; 32]),
        });
        storage
    }

    fn set_disk_state(&self, policy: Option<PolicyDocument>, invalid: bool, marker: u8) {
        let mut observation = self.observation.lock();
        observation.state = if invalid {
            PolicyManagementState::Invalid
        } else if policy.is_some() {
            PolicyManagementState::Active
        } else {
            PolicyManagementState::Missing
        };
        observation.policy = policy;
        observation.invalid_diagnostics = invalid.then(|| InvalidPolicyDiagnostics {
            diagnostics_version: API_VERSION_STR.into(),
            findings: vec![validation::disk_failure_finding(
                validation::DiskFailureReason::MalformedContent,
            )],
        });
        observation.fingerprint = DiskFingerprint([marker; 32]);
    }
}

#[cfg(test)]
impl PolicyStorage for TestStorage {
    fn observe(&self, _source: PolicyConfigurationSource, _path: &Path) -> Observation {
        clone_observation(&self.observation.lock())
    }

    fn create(&self, observation: &Observation, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure> {
        self.persist(observation, bytes)
    }

    fn replace(&self, observation: &Observation, bytes: &[u8]) -> Result<PersistedPolicy, WriteFailure> {
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
        let policy: PolicyDocument =
            serde_json::from_slice(bytes).map_err(|error| WriteFailure::PrePublication(error.into()))?;
        let mut next = clone_observation(observation);
        next.state = PolicyManagementState::Active;
        next.policy = Some(policy.clone());
        next.invalid_diagnostics = None;
        next.fingerprint = DiskFingerprint(Sha256::digest(bytes).into());
        *self.observation.lock() = clone_observation(&next);
        Ok(PersistedPolicy {
            policy,
            observation: next,
        })
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
        configured_path: observation.configured_path.clone(),
        fingerprint: observation.fingerprint.clone(),
    }
}
