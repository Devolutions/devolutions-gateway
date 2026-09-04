//! Keyed validation receipts, issued and verified only by [`PolicyStore`](super::PolicyStore).
//!
//! A receipt is not just a content hash of the canonical draft: without a key, any
//! process could compute a matching value for any draft it likes, which would defeat its
//! whole purpose (proving that *this exact* draft/validator-version/findings triple was
//! authoritatively (re)validated by *this* store immediately before a replacement commits
//! it). HMAC-SHA256 under a process-random key closes that gap -- forging a receipt
//! requires the key, not just the draft -- and verification compares the tag in constant
//! time, so a forgery attempt cannot learn anything from how long the check took.
//!
//! The key lives only in process memory (never logged, never persisted): a receipt issued
//! by one broker instance can never be replayed against a different instance, or the same
//! instance after a restart.

use hmac::{Hmac, KeyInit as _, Mac};
use now_policy::PolicyDraftDocument;
use now_policy_api::{PolicyFinding, PolicyValidationReceipt};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Prefix identifying the receipt encoding, so [`ReceiptKey::verify`] can reject a
/// malformed or foreign-format candidate before attempting a MAC comparison.
const RECEIPT_PREFIX: &str = "hmac-sha256:";

/// Process-random key binding every validation receipt issued by one [`PolicyStore`]
/// instance. Generated once at store construction and held only in memory.
pub(super) struct ReceiptKey([u8; 32]);

impl ReceiptKey {
    /// Generate a fresh 256-bit process-random key.
    pub(super) fn generate() -> Self {
        let mut key = [0u8; 32];
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
        let canonical_json = serde_json::to_vec(canonical_draft).expect("BUG: canonical draft always serializes");
        let findings_json = serde_json::to_vec(findings).expect("BUG: findings always serialize");

        // A fresh instance per call: `Mac::finalize`/`verify_slice` both consume `self`.
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC-SHA256 accepts any key length");
        mac.update(validator_version.as_bytes());
        mac.update(b"\0");
        mac.update(&canonical_json);
        mac.update(b"\0");
        mac.update(&findings_json);
        mac
    }

    /// Issue a receipt binding `canonical_draft`, `validator_version`, and the exact
    /// `findings` set observed for it.
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

    /// Verify, in constant time, that `candidate` is exactly the receipt this key would
    /// issue for `canonical_draft`/`validator_version`/`findings`. Any mismatch -- a
    /// tampered draft, a different validator version, a different warning set, or a
    /// receipt from a different store instance/process -- is rejected identically.
    pub(super) fn verify(
        &self,
        validator_version: &str,
        canonical_draft: &PolicyDraftDocument,
        findings: &[PolicyFinding],
        candidate: &PolicyValidationReceipt,
    ) -> bool {
        let Some(hex_tag) = candidate.strip_prefix(RECEIPT_PREFIX) else {
            return false;
        };
        let Ok(tag_bytes) = hex::decode(hex_tag) else {
            return false;
        };

        self.mac(validator_version, canonical_draft, findings)
            .verify_slice(&tag_bytes)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use now_policy_api::PolicyFindingSeverity;

    use super::*;

    fn draft(id: &str) -> PolicyDraftDocument {
        serde_json::from_value(serde_json::json!({
            "$schema": now_policy::POLICY_DRAFT_SCHEMA_URI,
            "PolicyVersion": "1.0.0",
            "PolicyType": "PackageBrokerPolicy",
            "Metadata": { "Id": id, "Publisher": "Test" },
            "Enforcement": { "DefaultDecision": "Deny", "RulePrecedence": "PriorityThenDeny" },
            "Rules": [],
        }))
        .unwrap()
    }

    fn finding() -> PolicyFinding {
        PolicyFinding {
            finding_version: "1.0".into(),
            severity: PolicyFindingSeverity::Warning,
            code: now_policy_api::PolicyFindingCode::DefaultAllow,
            path: "/Enforcement/DefaultDecision".to_owned(),
            rule_id: None,
            arguments: Default::default(),
            message: "test finding".to_owned(),
        }
    }

    #[test]
    fn same_store_key_is_stable() {
        let key = ReceiptKey::generate();
        let draft = draft("policy-a");
        let receipt_a = key.issue("v1", &draft, &[]);
        let receipt_b = key.issue("v1", &draft, &[]);
        assert_eq!(receipt_a, receipt_b);
        assert!(key.verify("v1", &draft, &[], &receipt_a));
    }

    #[test]
    fn different_store_key_differs() {
        let draft = draft("policy-a");
        let receipt = ReceiptKey::generate().issue("v1", &draft, &[]);
        let other = ReceiptKey::generate();
        assert_ne!(receipt.to_string(), other.issue("v1", &draft, &[]).to_string());
        assert!(!other.verify("v1", &draft, &[], &receipt));
    }

    #[test]
    fn tampered_draft_is_rejected() {
        let key = ReceiptKey::generate();
        let receipt = key.issue("v1", &draft("policy-a"), &[]);
        assert!(!key.verify("v1", &draft("policy-b"), &[], &receipt));
    }

    #[test]
    fn different_validator_version_is_rejected() {
        let key = ReceiptKey::generate();
        let draft = draft("policy-a");
        let receipt = key.issue("v1", &draft, &[]);
        assert!(!key.verify("v2", &draft, &[], &receipt));
    }

    #[test]
    fn different_warning_set_is_rejected() {
        let key = ReceiptKey::generate();
        let draft = draft("policy-a");
        let receipt = key.issue("v1", &draft, &[]);
        assert!(!key.verify("v1", &draft, std::slice::from_ref(&finding()), &receipt));
    }

    #[test]
    fn malformed_candidate_is_rejected() {
        let key = ReceiptKey::generate();
        let draft = draft("policy-a");
        assert!(!key.verify("v1", &draft, &[], &PolicyValidationReceipt::from("not-a-real-receipt")));
        assert!(!key.verify("v1", &draft, &[], &PolicyValidationReceipt::from("hmac-sha256:not-hex")));
    }
}
