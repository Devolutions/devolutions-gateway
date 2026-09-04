use hmac::{Hmac, Mac as _};
use now_policy::PolicyDraftDocument;
use now_policy_api::{PolicyFinding, PolicyValidationReceipt};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const RECEIPT_PREFIX: &str = "hmac-sha256:";

pub(super) struct ReceiptKey([u8; 32]);

impl ReceiptKey {
    pub(super) fn generate() -> Self {
        let mut key = [0; 32];
        key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        Self(key)
    }

    fn mac(
        &self,
        validator_version: &str,
        canonical_draft: &PolicyDraftDocument,
        findings: &[PolicyFinding],
    ) -> HmacSha256 {
        let canonical_json = serde_json::to_vec(canonical_draft).expect("canonical policy draft serializes");
        let findings_json = serde_json::to_vec(findings).expect("policy findings serialize");
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(validator_version.as_bytes());
        mac.update(b"\0");
        mac.update(&canonical_json);
        mac.update(b"\0");
        mac.update(&findings_json);
        mac
    }

    pub(super) fn issue(
        &self,
        validator_version: &str,
        canonical_draft: &PolicyDraftDocument,
        findings: &[PolicyFinding],
    ) -> PolicyValidationReceipt {
        let tag = self
            .mac(validator_version, canonical_draft, findings)
            .finalize()
            .into_bytes();
        format!("{RECEIPT_PREFIX}{}", hex::encode(tag)).into()
    }

    pub(super) fn verify(
        &self,
        validator_version: &str,
        canonical_draft: &PolicyDraftDocument,
        findings: &[PolicyFinding],
        candidate: &PolicyValidationReceipt,
    ) -> bool {
        let Some(encoded) = candidate.strip_prefix(RECEIPT_PREFIX) else {
            return false;
        };
        let Ok(tag) = hex::decode(encoded) else {
            return false;
        };
        self.mac(validator_version, canonical_draft, findings)
            .verify_slice(&tag)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use chrono::Utc;
    use now_policy::{PolicyDocument, PolicyDraftDocument};
    use now_policy_api::{
        API_VERSION_STR, ErrorCode, PolicyConflictHandling, PolicyFindingCode, PolicyFindingSeverity,
        PolicyManagementState, PolicyReplacementOperation, PolicyReplacementRequest, PolicyReplacementRequestKind,
        PolicyStoreToken,
    };

    use super::*;
    use crate::policy_store::{Monitoring, PolicyStorage, PolicyStore, ReloadCause, TestStorage, plan_revision};
    use crate::policy_watcher::{WatcherFailure, fail_closed};
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
    fn request(
        store: &PolicyStore,
        operation: PolicyReplacementOperation,
        raw: serde_json::Value,
    ) -> PolicyReplacementRequest {
        let validation = store.validate_draft(&raw);
        PolicyReplacementRequest {
            request_kind: PolicyReplacementRequestKind,
            request_version: API_VERSION_STR.into(),
            expected_store_token: store.management_snapshot().store_token,
            operation,
            conflict_handling: PolicyConflictHandling::Reject,
            warnings_acknowledged: false,
            draft: raw,
            validation_receipt: validation.validation_receipt.expect("valid receipt"),
        }
    }
    fn warning() -> PolicyFinding {
        PolicyFinding {
            finding_version: "1.0".into(),
            severity: PolicyFindingSeverity::Warning,
            code: PolicyFindingCode::DefaultAllow,
            path: "/Enforcement/DefaultDecision".to_owned(),
            rule_id: None,
            arguments: Default::default(),
            message: "warning".to_owned(),
        }
    }
    #[test]
    fn receipt_is_stable_for_one_key_and_exact_input() {
        let key = ReceiptKey::generate();
        let draft = draft("policy-a");
        let first = key.issue("v1", &draft, &[]);
        let second = key.issue("v1", &draft, &[]);
        assert_eq!(first, second);
        assert!(key.verify("v1", &draft, &[], &first));
    }
    #[test]
    fn receipt_rejects_other_keys_and_tampering() {
        let key = ReceiptKey::generate();
        let original = draft("policy-a");
        let receipt = key.issue("v1", &original, &[]);
        assert!(!ReceiptKey::generate().verify("v1", &original, &[], &receipt));
        assert!(!key.verify("v1", &draft("policy-b"), &[], &receipt));
        assert!(!key.verify("v2", &original, &[], &receipt));
        assert!(!key.verify("v1", &original, &[warning()], &receipt));
    }
    #[test]
    fn malformed_receipts_are_rejected() {
        let key = ReceiptKey::generate();
        let draft = draft("policy-a");
        for receipt in ["invalid", "hmac-sha256:not-hex", "hmac-sha256:00"] {
            assert!(!key.verify("v1", &draft, &[], &receipt.into()));
        }
    }
    #[tokio::test]
    async fn store_rejects_stale_request_after_retargeting_and_tampered_receipts() {
        let storage = Arc::new(TestStorage::new(Some(policy("current", 1))));
        let store = PolicyStore::load_with_storage(
            Some(PathBuf::from(r"C:\policy.json")),
            Arc::clone(&storage) as Arc<dyn PolicyStorage>,
            Monitoring::Available,
        );
        let raw = serde_json::to_value(draft("current")).expect("serialize draft");
        let mut stale_request = request(&store, PolicyReplacementOperation::Update, raw.clone());
        storage.set_disk_state(Some(policy("retargeted", 9)), false, 9);
        stale_request.conflict_handling = PolicyConflictHandling::ConfirmOverwrite;
        let stale_error = store.replace(stale_request).await.expect_err("stale token rejected");
        assert_eq!(stale_error.code, ErrorCode::StalePolicyStoreToken);
        assert!(stale_error.management.is_some());
        assert_eq!(
            store.active_policy().expect("retargeted policy loaded").metadata.id.0,
            "retargeted"
        );
        let mut tampered = request(&store, PolicyReplacementOperation::Update, raw);
        tampered.draft["Metadata"]["Publisher"] = "Tampered".into();
        let receipt_error = store.replace(tampered).await.expect_err("tampered draft rejected");
        assert_eq!(receipt_error.code, ErrorCode::ValidationFailed);
    }
    #[tokio::test]
    async fn store_requires_warning_acknowledgement() {
        let store = PolicyStore::for_tests(None);
        let mut risky = serde_json::to_value(draft("risky")).expect("serialize draft");
        risky["Enforcement"]["DefaultDecision"] = "Allow".into();
        let mut replacement = request(&store, PolicyReplacementOperation::Create, risky);
        let error = store
            .replace(replacement.clone())
            .await
            .expect_err("warning must be acknowledged");
        assert_eq!(error.code, ErrorCode::WarningConfirmationRequired);
        replacement.warnings_acknowledged = true;
        store.replace(replacement).await.expect("acknowledged warning succeeds");
    }
    #[tokio::test]
    async fn all_replacement_operations_enforce_state_identity_and_revision() {
        let create = PolicyStore::for_tests(None);
        let raw = serde_json::to_value(draft("created")).expect("serialize draft");
        let created = create
            .replace(request(&create, PolicyReplacementOperation::Create, raw))
            .await
            .expect("create succeeds");
        assert_eq!(created.policy.metadata.revision, 1);
        let update = PolicyStore::for_tests(Some(policy("current", 7)));
        let raw = serde_json::to_value(draft("current")).expect("serialize draft");
        let updated = update
            .replace(request(&update, PolicyReplacementOperation::Update, raw))
            .await
            .expect("update succeeds");
        assert_eq!(updated.policy.metadata.revision, 8);
        let replace = PolicyStore::for_tests(Some(policy("current", 7)));
        let raw = serde_json::to_value(draft("replacement")).expect("serialize draft");
        let replaced = replace
            .replace(request(&replace, PolicyReplacementOperation::ReplaceIdentity, raw))
            .await
            .expect("identity replacement succeeds");
        assert_eq!(replaced.policy.metadata.revision, 1);
        let storage = Arc::new(TestStorage::invalid());
        let repair = PolicyStore::load_with_storage(
            Some(PathBuf::from(r"C:\policy.json")),
            Arc::clone(&storage) as Arc<dyn PolicyStorage>,
            Monitoring::Available,
        );
        let raw = serde_json::to_value(draft("repaired")).expect("serialize draft");
        let repaired = repair
            .replace(request(&repair, PolicyReplacementOperation::Repair, raw))
            .await
            .expect("repair succeeds");
        assert_eq!(repaired.policy.metadata.revision, 1);
        let wrong_identity = PolicyStore::for_tests(Some(policy("current", 1)));
        let raw = serde_json::to_value(draft("different")).expect("serialize draft");
        let error = wrong_identity
            .replace(request(&wrong_identity, PolicyReplacementOperation::Update, raw))
            .await
            .expect_err("update must preserve identity");
        assert_eq!(error.code, ErrorCode::Conflict);
    }
    #[tokio::test]
    async fn concurrent_writers_cannot_commit_from_one_token() {
        let store = PolicyStore::for_tests(Some(policy("current", 1)));
        let raw = serde_json::to_value(draft("current")).expect("serialize draft");
        let first = request(&store, PolicyReplacementOperation::Update, raw);
        let (first, second) = tokio::join!(store.replace(first.clone()), store.replace(first));
        let outcomes = [first, second];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(error) if error.code == ErrorCode::StalePolicyStoreToken))
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn failed_persistence_preserves_snapshot_and_reload_rotates_token() {
        let storage = Arc::new(TestStorage::new(Some(policy("current", 3))));
        let store = PolicyStore::load_with_storage(
            Some(PathBuf::from(r"C:\policy.json")),
            Arc::clone(&storage) as Arc<dyn PolicyStorage>,
            Monitoring::Available,
        );
        storage.fail_persist.store(true, std::sync::atomic::Ordering::SeqCst);
        let raw = serde_json::to_value(draft("current")).expect("serialize draft");
        let error = store
            .replace(request(&store, PolicyReplacementOperation::Update, raw))
            .await
            .expect_err("persistence failure");
        assert_eq!(error.code, ErrorCode::PolicyPersistenceFailed);
        assert_eq!(store.active_policy().expect("old policy remains").metadata.revision, 3);
        let old_token = store.management_snapshot().store_token;
        storage.set_disk_state(None, true, 2);
        let management = store.reload_from_disk(ReloadCause::ExternalChange).await;
        assert_eq!(management.state, PolicyManagementState::Invalid);
        assert_ne!(management.store_token, old_token);
        assert!(store.active_policy().is_none());
    }
    #[tokio::test]
    async fn readiness_reloads_each_disk_state_after_provisional_load() {
        for (disk_policy, invalid, expected) in [
            (Some(policy("changed", 2)), false, PolicyManagementState::Active),
            (None, false, PolicyManagementState::Missing),
            (None, true, PolicyManagementState::Invalid),
        ] {
            let storage = Arc::new(TestStorage::new(Some(policy("provisional", 1))));
            let store = PolicyStore::load_with_storage(
                Some(PathBuf::from(r"C:\policy.json")),
                Arc::clone(&storage) as Arc<dyn PolicyStorage>,
                Monitoring::Initializing,
            );
            storage.set_disk_state(disk_policy, invalid, 3);
            assert_eq!(store.mark_monitoring_ready().await.state, expected);
            assert_eq!(
                store.active_policy().is_some(),
                expected == PolicyManagementState::Active
            );
        }
    }
    #[tokio::test]
    async fn monitoring_failure_stays_unavailable_across_reload_and_put() {
        for failure in [
            WatcherFailure::Creation,
            WatcherFailure::Registration,
            WatcherFailure::Notification,
            WatcherFailure::ChannelClosed,
            WatcherFailure::TaskTerminated,
        ] {
            let storage = Arc::new(TestStorage::new(Some(policy("current", 3))));
            let store = PolicyStore::load_with_storage(
                Some(PathBuf::from(r"C:\policy.json")),
                Arc::clone(&storage) as Arc<dyn PolicyStorage>,
                Monitoring::Available,
            );
            fail_closed(&store, failure).await;
            let first_unavailable = store.management_snapshot();
            fail_closed(&store, failure).await;
            let unavailable = store.management_snapshot();
            assert_eq!(unavailable.store_token, first_unavailable.store_token);
            assert_eq!(
                unavailable.write_capability,
                now_policy_api::PolicyWriteCapability::ReadOnly
            );
            assert_eq!(
                unavailable.read_only_reason,
                Some(now_policy_api::PolicyReadOnlyReason::ManagementDisabled)
            );
            storage.set_disk_state(Some(policy("external", 9)), false, 9);
            assert_eq!(
                store.reload_from_disk(ReloadCause::ExternalChange).await.store_token,
                unavailable.store_token
            );
            for token in [PolicyStoreToken::from("store:stale"), unavailable.store_token.clone()] {
                let mut replacement = request(
                    &store,
                    PolicyReplacementOperation::Update,
                    serde_json::to_value(draft("current")).expect("serialize draft"),
                );
                replacement.expected_store_token = token;
                let error = store
                    .replace(replacement)
                    .await
                    .expect_err("monitoring failure blocks PUT");
                assert_eq!(error.code, ErrorCode::BrokerPaused);
                assert_eq!(
                    error.management.expect("management snapshot").store_token,
                    unavailable.store_token
                );
            }
            assert!(store.active_policy().is_none());
            assert_eq!(
                storage
                    .observation
                    .lock()
                    .policy
                    .as_ref()
                    .expect("disk policy")
                    .metadata
                    .revision,
                9
            );
        }
    }
    #[test]
    fn revision_planning_rejects_invalid_state_transitions_and_overflow() {
        assert!(
            plan_revision(
                PolicyReplacementOperation::Create,
                PolicyManagementState::Active,
                None,
                "id"
            )
            .is_err()
        );
        assert!(
            plan_revision(
                PolicyReplacementOperation::Repair,
                PolicyManagementState::Missing,
                None,
                "id"
            )
            .is_err()
        );
        assert!(
            plan_revision(
                PolicyReplacementOperation::Update,
                PolicyManagementState::Active,
                Some(&policy("id", i32::MAX as u32)),
                "id"
            )
            .is_err()
        );
    }
}
