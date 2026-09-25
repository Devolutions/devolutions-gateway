//! Run the shared vectors (`docs/agent-identity/test-vectors.json`) through the oracle's public API.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey as _;
use serde::Deserialize;
use uuid::Uuid;

use crate::oracle::{
    CertStatus, Endpoint, NonceStore, RegisteredCert, check_csr, content_digest_header, verify_channel_proof,
    verify_raw_signature, verify_request,
};

const VECTORS: &str = include_str!("../../../docs/agent-identity/test-vectors.json");

#[derive(Deserialize)]
struct Vectors {
    http_signature: SignatureSection,
    channel_proof: ChannelProofSection,
    csr: CsrSection,
    rfc9421_b_2_4: Rfc9421Case,
}

#[derive(Deserialize)]
struct SignatureSection {
    registered: Vec<RegisteredVector>,
    cases: Vec<SigCase>,
    sequences: Vec<Sequence>,
}

#[derive(Deserialize)]
struct RegisteredVector {
    device_id: Uuid,
    keyid: String,
    public_key_sec1: String,
    certificate_status: String,
    device_revoked: bool,
    not_before: i64,
    not_after: i64,
}

#[derive(Clone, Deserialize)]
struct SigCase {
    name: String,
    endpoint: String,
    method: String,
    now: i64,
    headers: HashMap<String, String>,
    signature_base: String,
    expected: String,
    body: Option<String>,
}

#[derive(Deserialize)]
struct Sequence {
    name: String,
    steps: Vec<String>,
    expected: Vec<String>,
}

#[derive(Deserialize)]
struct ChannelProofSection {
    public_key_sec1: String,
    challenge: String,
    connect_nonce: String,
    cases: Vec<ProofCase>,
}

#[derive(Deserialize)]
struct ProofCase {
    name: String,
    proof: String,
    expected_valid: bool,
}

#[derive(Deserialize)]
struct CsrSection {
    #[serde(flatten)]
    cases: HashMap<String, CsrCase>,
}

#[derive(Deserialize)]
struct CsrCase {
    csr: String,
    expected: String,
    public_key_sec1: Option<String>,
}

#[derive(Deserialize)]
struct Rfc9421Case {
    public_key_spki: String,
    signature_base: String,
    signature: String,
    expected_valid: bool,
}

fn endpoint_of(name: &str) -> Endpoint {
    match name {
        "renew" => Endpoint::Renew,
        "connect" => Endpoint::Connect,
        other => panic!("unknown endpoint {other}"),
    }
}

fn status_of(name: &str) -> CertStatus {
    match name {
        "current" => CertStatus::Current,
        "pending" => CertStatus::Pending,
        "retired" => CertStatus::Retired,
        other => panic!("unknown certificate_status {other}"),
    }
}

fn registry(registered: &[RegisteredVector]) -> HashMap<String, RegisteredCert> {
    registered
        .iter()
        .map(|r| {
            let key_bytes = STANDARD.decode(&r.public_key_sec1).expect("valid public_key_sec1");
            let cert = RegisteredCert {
                device_id: r.device_id,
                revoked: r.device_revoked,
                status: status_of(&r.certificate_status),
                not_before: r.not_before,
                not_after: r.not_after,
                public_key: VerifyingKey::from_sec1_bytes(&key_bytes).expect("valid sec1 key"),
            };
            (r.keyid.clone(), cert)
        })
        .collect()
}

fn run_case(registry: &HashMap<String, RegisteredCert>, nonces: &mut NonceStore, case: &SigCase) -> String {
    let endpoint = endpoint_of(&case.endpoint);
    let body = case.body.as_deref().unwrap_or("");
    let result = verify_request(
        endpoint,
        &case.method,
        case.headers.get("signature-input").map(String::as_bytes),
        case.headers.get("signature").map(String::as_bytes),
        case.headers.get("content-digest").map(String::as_bytes),
        body.as_bytes(),
        case.now,
        &mut |keyid| registry.get(keyid).cloned(),
        nonces,
    );
    if case.expected == "ok"
        && let Ok(auth) = &result
    {
        if endpoint == Endpoint::Renew {
            assert_eq!(
                case.headers["content-digest"],
                content_digest_header(body.as_bytes()),
                "content-digest mismatch in {}",
                case.name
            );
        }
        // The vector's signed base must verify even when the wire encoding is noncanonical.
        let encoded = case.headers["signature"]
            .trim()
            .strip_prefix("sig=:")
            .and_then(|value| value.strip_suffix(':'))
            .expect("single profile signature");
        let raw_signature = STANDARD.decode(encoded).expect("signature base64");
        assert!(
            verify_raw_signature(auth.public_key(), case.signature_base.as_bytes(), &raw_signature),
            "signature base fixture mismatch in {}",
            case.name
        );
    }
    match result {
        Ok(_) => "ok".to_owned(),
        Err(rejection) => rejection.code().to_owned(),
    }
}

#[test]
fn http_signature_cases() {
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("vectors parse");
    let registry = registry(&vectors.http_signature.registered);
    for case in &vectors.http_signature.cases {
        let mut nonces = NonceStore::default();
        let actual = run_case(&registry, &mut nonces, case);
        assert_eq!(actual, case.expected, "case {}", case.name);
    }
}

#[test]
fn noncanonical_valid_signature_input_preserves_signed_base() {
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("vectors parse");
    let registry = registry(&vectors.http_signature.registered);
    let mut case = vectors
        .http_signature
        .cases
        .iter()
        .find(|case| case.name == "valid_renew")
        .expect("valid_renew exists")
        .clone();
    let input = case.headers.get_mut("signature-input").expect("signature-input");
    *input = format!(
        " \t{}",
        input.replace("\"@method\" \"content-digest\"", "\"@method\"   \"content-digest\"")
    );
    case.headers
        .get_mut("signature")
        .expect("signature")
        .insert_str(0, " \t");
    assert_eq!(run_case(&registry, &mut NonceStore::default(), &case), "ok");
}

#[test]
fn http_signature_sequences() {
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("vectors parse");
    let registry = registry(&vectors.http_signature.registered);
    let cases: HashMap<&str, &SigCase> = vectors
        .http_signature
        .cases
        .iter()
        .map(|c| (c.name.as_str(), c))
        .collect();
    for sequence in &vectors.http_signature.sequences {
        let mut nonces = NonceStore::default();
        for (step, expected) in sequence.steps.iter().zip(&sequence.expected) {
            let case = cases
                .get(step.as_str())
                .unwrap_or_else(|| panic!("sequence {} references unknown case {step}", sequence.name));
            let actual = run_case(&registry, &mut nonces, case);
            assert_eq!(actual, *expected, "sequence {}, step {step}", sequence.name);
        }
    }
}

#[test]
fn channel_proof_cases() {
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("vectors parse");
    let section = &vectors.channel_proof;
    let key = VerifyingKey::from_sec1_bytes(&STANDARD.decode(&section.public_key_sec1).expect("valid sec1"))
        .expect("valid key");
    let challenge = STANDARD.decode(&section.challenge).expect("valid challenge");
    for case in &section.cases {
        let proof = STANDARD.decode(&case.proof).expect("valid proof base64");
        let actual = verify_channel_proof(&key, &challenge, &section.connect_nonce, &proof);
        assert_eq!(actual, case.expected_valid, "proof case {}", case.name);
    }
}

#[test]
fn csr_cases() {
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("vectors parse");
    assert!(!vectors.csr.cases.is_empty(), "CSR cases are missing");
    for (name, case) in &vectors.csr.cases {
        let der = STANDARD.decode(&case.csr).expect("valid csr base64");
        match (check_csr(&der), case.expected.as_str()) {
            (Some(key), "ok") => {
                let expected_key = STANDARD
                    .decode(case.public_key_sec1.as_ref().expect("valid case has key"))
                    .expect("valid sec1");
                assert_eq!(
                    key.to_sec1_bytes().as_ref(),
                    expected_key.as_slice(),
                    "csr case {name} public key"
                );
            }
            (None, "invalid_request") => {}
            (result, expected) => panic!("csr case {name}: got {result:?}, want {expected}"),
        }
    }
}

#[test]
fn rfc9421_b_2_4() {
    // The RFC response example checks the raw P-256 primitive, not the §6 request policy.
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("vectors parse");
    let case = &vectors.rfc9421_b_2_4;
    let spki = STANDARD.decode(&case.public_key_spki).expect("valid spki base64");
    let key = VerifyingKey::from_public_key_der(&spki).expect("valid spki");
    let sig_bytes = STANDARD.decode(&case.signature).expect("valid signature base64");
    let actual = verify_raw_signature(&key, case.signature_base.as_bytes(), &sig_bytes);
    assert_eq!(actual, case.expected_valid, "rfc9421_b_2_4");
}

#[test]
fn malformed_nonce_and_keyid_are_rejected() {
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("vectors parse");
    let registry = registry(&vectors.http_signature.registered);
    let valid = vectors
        .http_signature
        .cases
        .iter()
        .find(|case| case.name == "valid_renew")
        .expect("valid_renew exists");
    for (original, replacement) in [
        ("AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgcICQoLDA0ODw=="),
        ("AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgcICQoLDA0OD"),
        ("AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgcICQoLDA0OD!"),
        (
            "9T7LbsyWVkALFgAtl2E5ESBgMfMDbKbr_RT36B9OM7w",
            "9T7LbsyWVkALFgAtl2E5ESBgMfMDbKbr_RT36B9OM7w=",
        ),
        (
            "9T7LbsyWVkALFgAtl2E5ESBgMfMDbKbr_RT36B9OM7w",
            "9T7LbsyWVkALFgAtl2E5ESBgMfMDbKbr_RT36B9OM7",
        ),
    ] {
        let mut case = valid.clone();
        case.expected = "signature_invalid".to_owned();
        case.now = 1_790_001_000;
        *case.headers.get_mut("signature-input").expect("signature-input") =
            case.headers["signature-input"].replace(original, replacement);
        assert_eq!(
            run_case(&registry, &mut NonceStore::default(), &case),
            "signature_invalid",
            "malformed parameter: {replacement}"
        );
    }
}

#[test]
fn duplicate_signature_parameter_is_rejected() {
    let vectors: Vectors = serde_json::from_str(VECTORS).expect("vectors parse");
    let registry = registry(&vectors.http_signature.registered);
    let mut case = vectors
        .http_signature
        .cases
        .iter()
        .find(|case| case.name == "valid_renew")
        .expect("valid_renew exists")
        .clone();
    case.expected = "signature_invalid".to_owned();
    case.now = 1_790_001_000;
    case.headers
        .get_mut("signature-input")
        .expect("signature-input")
        .push_str(";created=1790000000");
    assert_eq!(
        run_case(&registry, &mut NonceStore::default(), &case),
        "signature_invalid"
    );
}
