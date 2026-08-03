//! Unit tests for `agent-tunnel/src/cert.rs`.
//!
//! Focus on the identity invariants exercised by enrollment (#1773) and
//! certificate renewal (#1775): the gateway must encode the agent's UUID in
//! the issued cert's URN SAN, and recover the same UUID from any cert it
//! later sees on the wire.

use agent_tunnel::cert::{CaManager, extract_agent_id_from_pem};
use camino::Utf8PathBuf;
use uuid::Uuid;

use super::common::{generate_csr_with_cn, generate_test_key_and_csr};

fn fresh_ca() -> std::sync::Arc<CaManager> {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("UTF-8 temp path");
    // Leak the TempDir for the test's lifetime: CaManager owns the files
    // already loaded, so dropping the dir while still in use is fine, but
    // leaking removes any chance of TOCTOU surprises.
    std::mem::forget(temp_dir);
    CaManager::load_or_generate(&data_dir).expect("CA generation")
}

/// Security invariant from #1775 review: when the gateway re-signs (or
/// initially signs) an agent CSR, the issued cert's URN SAN encodes the
/// `agent_id` parameter passed in by the caller, **not** anything from the
/// CSR's own subject. A compromised agent crafting a CSR with someone else's
/// CN must not be able to impersonate.
#[test]
fn sign_agent_csr_ignores_csr_subject_uses_passed_identity() {
    let ca_manager = fresh_ca();

    let real_agent_id = Uuid::new_v4();
    let (_evil_key, evil_csr_pem) = generate_csr_with_cn("evil-impersonator");

    let signed = ca_manager
        .sign_agent_csr(real_agent_id, "legit-name", &evil_csr_pem, None)
        .expect("sign agent CSR");

    let recovered = extract_agent_id_from_pem(&signed.client_cert_pem).expect("issued cert has urn:uuid SAN");
    assert_eq!(
        recovered, real_agent_id,
        "issued cert must encode the agent_id passed by the caller, not the CSR subject"
    );
}

#[test]
fn extract_agent_id_from_pem_round_trips() {
    let ca_manager = fresh_ca();

    let known_id = Uuid::new_v4();
    let (_key, csr_pem) = generate_test_key_and_csr("round-trip-agent");

    let signed = ca_manager
        .sign_agent_csr(known_id, "round-trip-agent", &csr_pem, None)
        .expect("sign agent CSR");

    let recovered = extract_agent_id_from_pem(&signed.client_cert_pem).expect("urn:uuid SAN present");
    assert_eq!(recovered, known_id);
}

#[test]
fn extract_agent_id_from_pem_rejects_cert_without_san() {
    let ca_manager = fresh_ca();

    // The CA's own root cert does not carry an `urn:uuid:` SAN.
    let error = extract_agent_id_from_pem(ca_manager.ca_cert_pem()).expect_err("CA cert has no urn:uuid SAN");

    let msg = format!("{error:#}");
    assert!(
        msg.contains("urn:uuid"),
        "error should reference the missing urn:uuid SAN, got: {msg}"
    );
}
