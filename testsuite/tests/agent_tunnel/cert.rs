use agent_tunnel::cert::{CaManager, extract_agent_id_from_pem};
use camino::Utf8PathBuf;
use tempfile::TempDir;
use uuid::Uuid;

use super::common::generate_csr_with_cn;

fn fresh_ca() -> (TempDir, std::sync::Arc<CaManager>) {
    let temp_dir = tempfile::tempdir().expect("create temporary directory");
    let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("use utf-8 temporary path");
    let manager = CaManager::load_or_generate(&data_dir).expect("generate test ca");
    (temp_dir, manager)
}

#[test]
fn sign_agent_csr_ignores_csr_subject_uses_passed_identity() {
    let (_temp_dir, ca_manager) = fresh_ca();

    let real_agent_id = Uuid::new_v4();
    let (_evil_key, evil_csr_pem) = generate_csr_with_cn("evil-impersonator");

    let signed = ca_manager
        .sign_agent_csr(real_agent_id, "legit-name", &evil_csr_pem, None)
        .expect("sign agent csr");

    let recovered = extract_agent_id_from_pem(&signed.client_cert_pem).expect("issued certificate has urn:uuid san");
    assert_eq!(
        recovered, real_agent_id,
        "issued cert must encode the agent_id passed by the caller, not the CSR subject"
    );
}

#[test]
fn extract_agent_id_from_pem_round_trips() {
    let (_temp_dir, ca_manager) = fresh_ca();

    let known_id = Uuid::new_v4();
    let (_key, csr_pem) = generate_csr_with_cn("round-trip-agent");

    let signed = ca_manager
        .sign_agent_csr(known_id, "round-trip-agent", &csr_pem, None)
        .expect("sign agent csr");

    let recovered = extract_agent_id_from_pem(&signed.client_cert_pem).expect("urn:uuid san present");
    assert_eq!(recovered, known_id);
}

#[test]
fn extract_agent_id_from_pem_rejects_cert_without_san() {
    let (_temp_dir, ca_manager) = fresh_ca();
    let error = extract_agent_id_from_pem(ca_manager.ca_cert_pem()).expect_err("ca certificate has no urn:uuid san");

    let msg = format!("{error:#}");
    assert!(
        msg.contains("urn:uuid"),
        "error should reference the missing urn:uuid SAN, got: {msg}"
    );
}
