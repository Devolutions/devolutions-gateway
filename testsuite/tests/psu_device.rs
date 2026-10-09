use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use devolutions_agent::config::{Conf, dto};
use devolutions_agent::psu_agent::device::{
    DeviceIdentity, fingerprint, retryable, unix_now, validate_device_certificate, validate_trust_anchor,
};
use devolutions_agent::psu_agent::protocol::agent_control_server::{AgentControl, AgentControlServer};
use devolutions_agent::psu_agent::protocol::agent_enrollment_server::{AgentEnrollment, AgentEnrollmentServer};
use devolutions_agent::psu_agent::protocol::{self, EnrollResponse, EnrollmentStatus};
use devolutions_gateway_task::ShutdownHandle;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use uuid::Uuid;

struct Pki {
    root: Certificate,
    issuer: Certificate,
    issuer_key: KeyPair,
    server: Certificate,
    server_key: KeyPair,
}

impl Pki {
    fn new() -> Self {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        root_params.distinguished_name.push(DnType::CommonName, "PSU test root");
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let root = root_params.self_signed(&root_key).unwrap();
        let mut issuer_params = CertificateParams::default();
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        issuer_params
            .distinguished_name
            .push(DnType::CommonName, "PSU test issuer");
        let issuer_key = KeyPair::generate().unwrap();
        let issuer = issuer_params.signed_by(&issuer_key, &root, &root_key).unwrap();
        let mut server_params = CertificateParams::default();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let server_key = KeyPair::generate().unwrap();
        let server = server_params.signed_by(&server_key, &issuer, &issuer_key).unwrap();
        Self {
            root,
            issuer,
            issuer_key,
            server,
            server_key,
        }
    }

    fn trust(&self, nonce: &str) -> protocol::TrustAnchorResponse {
        let header = serde_json::json!({
            "alg": "ES256",
            "x5c": [STANDARD.encode(self.server.der()), STANDARD.encode(self.issuer.der()), STANDARD.encode(self.root.der())]
        });
        let now = unix_now().unwrap();
        let claims = serde_json::json!({
            "aud": "psu-agent-enrollment", "nonce": nonce, "iat": now, "nbf": now - 5, "exp": now + 300
        });
        protocol::TrustAnchorResponse {
            root_certificate: self.root.der().to_vec(),
            root_thumbprint: fingerprint(self.root.der()),
            server_assertion: sign(&self.server_key, &header, &claims),
        }
    }

    fn issue(&self, csr: &[u8], device_id: &str, seconds: i64) -> EnrollResponse {
        let mut request = CertificateSigningRequestParams::from_der(&csr.into()).unwrap();
        request.params.distinguished_name = rcgen::DistinguishedName::new();
        request.params.distinguished_name.push(DnType::CommonName, device_id);
        request.params.subject_alt_names = vec![SanType::URI(format!("urn:uuid:{device_id}").try_into().unwrap())];
        request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        request.params.not_before = OffsetDateTime::now_utc() - time::Duration::minutes(5);
        request.params.not_after = OffsetDateTime::now_utc() + time::Duration::seconds(seconds);
        let expiry = request.params.not_after.unix_timestamp();
        let cert = request.signed_by(&self.issuer, &self.issuer_key).unwrap();
        EnrollResponse {
            device_id: device_id.to_owned(),
            certificate: cert.der().to_vec(),
            chain: vec![self.issuer.der().to_vec(), self.root.der().to_vec()],
            status: EnrollmentStatus::Approved as i32,
            certificate_thumbprint: fingerprint(cert.der()),
            not_after: Some(prost_types::Timestamp {
                seconds: expiry,
                nanos: 0,
            }),
        }
    }
}

fn sign(key: &KeyPair, header: &serde_json::Value, claims: &serde_json::Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    let key = EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &key.serialize_der(),
        &SystemRandom::new(),
    )
    .unwrap();
    let signature = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

struct MockState {
    pki: Pki,
    device_id: String,
    enrollees: AtomicUsize,
    renewals: AtomicUsize,
    connections: AtomicUsize,
    pending: AtomicBool,
    revoked: AtomicBool,
    lose_enrollment_response: AtomicBool,
    corrupt_renewal: AtomicBool,
    first_lifetime: i64,
    hardware_id: Mutex<Option<String>>,
    jtis: Mutex<HashSet<String>>,
}

impl MockState {
    async fn verify_assertion(&self, auth: String) -> Result<String, Status> {
        let token = auth
            .strip_prefix("Device ")
            .expect("device mode must never send Bearer");
        let parts = token.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["x5c"].as_array().unwrap().len(), 1);
        assert_eq!(claims["aud"], "psu-agent");
        assert_eq!(claims["sub"], self.device_id);
        assert!(claims["exp"].as_i64().unwrap() - claims["nbf"].as_i64().unwrap() <= 300);
        let now = unix_now().unwrap();
        assert!(claims["exp"].as_i64().unwrap() > now);
        assert!(claims["iat"].as_i64().unwrap() <= now + 2);
        assert!(claims["nbf"].as_i64().unwrap() <= now);
        let jti = claims["jti"].as_str().unwrap().to_owned();
        assert!(Uuid::parse_str(&jti).is_ok());
        assert!(self.jtis.lock().await.insert(jti));
        let cert = STANDARD.decode(header["x5c"][0].as_str().unwrap()).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&cert).unwrap();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(signature.len(), 64, "ES256 signatures use JOSE r||s, not ASN.1");
        signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            cert.public_key().subject_public_key.data.as_ref(),
        )
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
        if self.revoked.load(Ordering::SeqCst) {
            return Err(Status::permission_denied("The device is revoked."));
        }
        if self.pending.load(Ordering::SeqCst) {
            return Err(Status::permission_denied("The device is waiting for approval."));
        }
        Ok(self.device_id.clone())
    }
}

#[derive(Clone)]
struct Mock(Arc<MockState>);

#[tonic::async_trait]
impl AgentEnrollment for Mock {
    async fn get_trust_anchor(
        &self,
        request: Request<protocol::TrustAnchorRequest>,
    ) -> Result<Response<protocol::TrustAnchorResponse>, Status> {
        assert!(
            !request.metadata().contains_key("authorization"),
            "bootstrap must not disclose enrollment token"
        );
        Ok(Response::new(self.0.pki.trust(&request.into_inner().nonce)))
    }

    async fn enroll(&self, request: Request<protocol::EnrollRequest>) -> Result<Response<EnrollResponse>, Status> {
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer enrollment-token"
        );
        self.0.enrollees.fetch_add(1, Ordering::SeqCst);
        let request = request.into_inner();
        assert_ne!(request.hardware_id, self.0.device_id);
        assert!(!request.machine_name.is_empty());
        *self.0.hardware_id.lock().await = Some(request.hardware_id);
        if self.0.lose_enrollment_response.load(Ordering::SeqCst) {
            return Err(Status::unavailable("response was lost"));
        }
        let mut response = self.0.pki.issue(&request.csr, &self.0.device_id, self.0.first_lifetime);
        if self.0.pending.load(Ordering::SeqCst) {
            response.status = EnrollmentStatus::PendingApproval as i32;
        }
        Ok(Response::new(response))
    }

    async fn renew(&self, request: Request<protocol::RenewRequest>) -> Result<Response<EnrollResponse>, Status> {
        self.0
            .verify_assertion(
                request
                    .metadata()
                    .get("authorization")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
            )
            .await?;
        self.0.renewals.fetch_add(1, Ordering::SeqCst);
        let mut response = self
            .0
            .pki
            .issue(&request.into_inner().csr, &self.0.device_id, 90 * 86400);
        if self.0.corrupt_renewal.load(Ordering::SeqCst) {
            response.certificate_thumbprint = "00".repeat(32);
        }
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl AgentControl for Mock {
    type ConnectStream = ReceiverStream<Result<protocol::ServerMessage, Status>>;

    async fn connect(
        &self,
        request: Request<tonic::Streaming<protocol::AgentMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let authorization = request
            .metadata()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let device_id = if authorization == "Bearer legacy-agent-token" {
            "legacy-agent-id".to_owned()
        } else {
            self.0.verify_assertion(authorization).await?
        };
        let mut incoming = request.into_inner();
        let registration = incoming.message().await?.unwrap();
        assert_eq!(registration.agent_id, device_id);
        match registration.payload.unwrap() {
            protocol::agent_message::Payload::RegisterAgent(registration) => {
                assert_eq!(registration.agent_id, device_id)
            }
            _ => panic!("registration must be the first message"),
        }
        self.0.connections.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(4);
        tx.send(Ok(protocol::ServerMessage {
            request_id: String::new(),
            connection_id: "connection".to_owned(),
            timestamp: None,
            payload: Some(protocol::server_message::Payload::RegisterAccepted(
                protocol::RegisterAccepted {
                    connection_id: "connection".to_owned(),
                },
            )),
        }))
        .await
        .unwrap();
        tokio::spawn(async move {
            let _hold_sender = tx;
            while incoming.next().await.is_some() {}
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

struct Harness {
    state: Arc<MockState>,
    server_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    directory: TempDir,
}

impl Harness {
    async fn new(seconds: i64) -> Self {
        let state = Arc::new(MockState {
            pki: Pki::new(),
            device_id: Uuid::new_v4().to_string(),
            enrollees: AtomicUsize::new(0),
            renewals: AtomicUsize::new(0),
            connections: AtomicUsize::new(0),
            pending: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            lose_enrollment_response: AtomicBool::new(false),
            corrupt_renewal: AtomicBool::new(false),
            first_lifetime: seconds,
            hardware_id: Mutex::new(None),
            jtis: Mutex::new(HashSet::new()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let mock = Mock(Arc::clone(&state));
        let server = tokio::spawn(
            Server::builder()
                .add_service(AgentEnrollmentServer::new(mock.clone()))
                .add_service(AgentControlServer::new(mock))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                }),
        );
        Self {
            state,
            server_url,
            shutdown: Some(shutdown),
            server,
            directory: TempDir::new().unwrap(),
        }
    }

    fn config(&self) -> devolutions_agent::config::PsuConf {
        let file: dto::ConfFile = serde_json::from_value(serde_json::json!({
            "PsuAgent": { "Enabled": true, "ServerUrl": self.server_url, "AgentId": "untrusted-agent-name",
                "PowerShell": { "ExecutablePath": "missing-test-pwsh" },
                "DeviceEnrollment": {
                    "RootThumbprint": fingerprint(self.state.pki.root.der()),
                    "EnrollmentToken": "enrollment-token",
                    "StateDirectory": self.directory.path()
                }
            }
        }))
        .unwrap();
        Conf::from_conf_file(&file).unwrap().psu_agent.unwrap()
    }

    async fn channel(&self) -> tonic::transport::Channel {
        tonic::transport::Endpoint::new(self.server_url.clone())
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    async fn stop(mut self) {
        self.shutdown.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[test]
fn trust_anchor_rejects_pin_nonce_signature_and_missing_intermediate() {
    let pki = Pki::new();
    let response = pki.trust("nonce");
    let pin = fingerprint(pki.root.der());
    validate_trust_anchor(&response, &pin, "nonce", unix_now().unwrap()).unwrap();
    assert!(validate_trust_anchor(&response, &"00".repeat(32), "nonce", unix_now().unwrap()).is_err());
    assert!(validate_trust_anchor(&response, &pin, "other-nonce", unix_now().unwrap()).is_err());
    let mut altered = response.clone();
    altered.server_assertion.push('A');
    assert!(validate_trust_anchor(&altered, &pin, "nonce", unix_now().unwrap()).is_err());
    let parts = response.server_assertion.split('.').collect::<Vec<_>>();
    let mut header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    header["x5c"] = serde_json::json!([STANDARD.encode(pki.server.der()), STANDARD.encode(pki.root.der())]);
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    altered.server_assertion = sign(&pki.server_key, &header, &claims);
    assert!(validate_trust_anchor(&altered, &pin, "nonce", unix_now().unwrap()).is_err());
}

#[test]
fn trust_anchor_rejects_wrong_audience_expiry_and_algorithm() {
    let pki = Pki::new();
    let mut response = pki.trust("nonce");
    let parts = response.server_assertion.split('.').collect::<Vec<_>>();
    let header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    for (field, value) in [
        ("aud", serde_json::json!("psu-agent")),
        ("exp", serde_json::json!(unix_now().unwrap() - 1)),
        ("exp", serde_json::json!(unix_now().unwrap() + 3600)),
        ("iat", serde_json::json!(i64::MIN)),
        ("nbf", serde_json::json!(i64::MIN)),
    ] {
        let mut bad = claims.clone();
        bad[field] = value;
        response.server_assertion = sign(&pki.server_key, &header, &bad);
        assert!(validate_trust_anchor(&response, &fingerprint(pki.root.der()), "nonce", unix_now().unwrap()).is_err());
    }
    let mut bad = header;
    bad["alg"] = serde_json::json!("HS256");
    response.server_assertion = sign(&pki.server_key, &bad, &claims);
    assert!(validate_trust_anchor(&response, &fingerprint(pki.root.der()), "nonce", unix_now().unwrap()).is_err());
}

#[tokio::test]
async fn bootstrap_enroll_restart_expired_renew_and_device_connect() {
    let harness = Harness::new(2).await;
    let mut config = harness.config();
    let mut identity = DeviceIdentity::open(&config).unwrap();
    identity
        .prepare(harness.channel().await, &config, "test-machine")
        .await
        .unwrap();
    assert_eq!(identity.device_id().unwrap(), harness.state.device_id);
    let first_assertion = identity.authorization().unwrap();
    assert_ne!(first_assertion, identity.authorization().unwrap());
    assert!(
        DeviceIdentity::open(&config).is_err(),
        "identity must have an exclusive process lock"
    );
    let state_path = identity.status()["StatePath"].as_str().unwrap().to_owned();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(
        !std::fs::read_to_string(&state_path)
            .unwrap()
            .contains("enrollment-token")
    );
    drop(identity);
    config.device_enrollment.as_mut().unwrap().enrollment_token = None;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (shutdown, signal) = ShutdownHandle::new();
    let agent = tokio::spawn(devolutions_agent::psu_agent::run_psu_agent(config, signal));
    tokio::time::timeout(Duration::from_secs(10), async {
        while harness.state.connections.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    shutdown.signal();
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(harness.state.enrollees.load(Ordering::SeqCst), 1);
    assert_eq!(harness.state.renewals.load(Ordering::SeqCst), 1);
    harness.stop().await;
}

#[tokio::test]
async fn pending_identity_retries_without_spending_enrollment_token() {
    let harness = Harness::new(90 * 86400).await;
    harness.state.pending.store(true, Ordering::SeqCst);
    let config = harness.config();
    let (shutdown, signal) = ShutdownHandle::new();
    let agent = tokio::spawn(devolutions_agent::psu_agent::run_psu_agent(config.clone(), signal));
    tokio::time::timeout(Duration::from_secs(10), async {
        while harness.state.enrollees.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        while harness.state.jtis.lock().await.len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    harness.state.pending.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(10), async {
        while harness.state.connections.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    shutdown.signal();
    agent.await.unwrap().unwrap();
    assert_eq!(harness.state.enrollees.load(Ordering::SeqCst), 1);
    assert!(DeviceIdentity::open(&config).unwrap().device_id().is_ok());
    harness.stop().await;
}

#[tokio::test]
async fn ambiguous_enrollment_is_not_resubmitted_after_restart() {
    let harness = Harness::new(90 * 86400).await;
    harness.state.lose_enrollment_response.store(true, Ordering::SeqCst);
    let config = harness.config();
    let mut identity = DeviceIdentity::open(&config).unwrap();
    assert!(
        identity
            .prepare(harness.channel().await, &config, "test")
            .await
            .is_err()
    );
    drop(identity);
    let mut identity = DeviceIdentity::open(&config).unwrap();
    let error = identity
        .prepare(harness.channel().await, &config, "test")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("outcome is unknown"));
    assert_eq!(harness.state.enrollees.load(Ordering::SeqCst), 1);
    drop(identity);
    harness.stop().await;
}

#[tokio::test]
async fn bad_bootstrap_pin_never_discloses_enrollment_token() {
    let harness = Harness::new(90 * 86400).await;
    let mut config = harness.config();
    config.device_enrollment.as_mut().unwrap().root_thumbprint = "00".repeat(32);
    let mut identity = DeviceIdentity::open(&config).unwrap();
    assert!(
        identity
            .prepare(harness.channel().await, &config, "test")
            .await
            .is_err()
    );
    assert_eq!(harness.state.enrollees.load(Ordering::SeqCst), 0);
    drop(identity);
    harness.stop().await;
}

#[tokio::test]
async fn revoked_identity_stops_without_downgrade_or_reenrollment() {
    let harness = Harness::new(90 * 86400).await;
    let config = harness.config();
    let mut identity = DeviceIdentity::open(&config).unwrap();
    identity
        .prepare(harness.channel().await, &config, "test")
        .await
        .unwrap();
    drop(identity);
    harness.state.revoked.store(true, Ordering::SeqCst);
    let (_shutdown, signal) = ShutdownHandle::new();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        devolutions_agent::psu_agent::run_psu_agent(config, signal),
    )
    .await
    .unwrap();
    assert!(result.unwrap_err().to_string().contains("operator action"));
    assert_eq!(harness.state.enrollees.load(Ordering::SeqCst), 1);
    harness.stop().await;
}

#[test]
fn retry_policy_distinguishes_pending_from_revocation_and_reset() {
    assert!(retryable(&anyhow::Error::new(Status::permission_denied(
        "The device is waiting for approval."
    ))));
    assert!(!retryable(&anyhow::Error::new(Status::permission_denied(
        "The device is revoked."
    ))));
    assert!(!retryable(&anyhow::Error::new(Status::unauthenticated(
        "The certificate does not match the one recorded for this device."
    ))));
}

#[tokio::test]
async fn failed_renewal_preserves_previous_usable_identity() {
    let harness = Harness::new(90 * 86400).await;
    let config = harness.config();
    let mut identity = DeviceIdentity::open(&config).unwrap();
    identity
        .prepare(harness.channel().await, &config, "test")
        .await
        .unwrap();
    let path = identity.status()["StatePath"].as_str().unwrap().to_owned();
    let previous = std::fs::read(&path).unwrap();
    drop(identity);
    harness.state.corrupt_renewal.store(true, Ordering::SeqCst);
    assert!(devolutions_agent::psu_agent::device::renew(&config).await.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), previous);
    let identity = DeviceIdentity::open(&config).unwrap();
    assert_eq!(identity.device_id().unwrap(), harness.state.device_id);
    drop(identity);
    harness.stop().await;
}

#[test]
fn device_certificate_rejects_wrong_identity_key_chain_and_eku() {
    let pki = Pki::new();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "test-csr");
    let csr = params.serialize_request(&key).unwrap();
    let id = Uuid::new_v4().to_string();
    let response = pki.issue(csr.der(), &id, 3600);
    let public_key = signature::KeyPair::public_key(
        &EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &key.serialize_der(),
            &SystemRandom::new(),
        )
        .unwrap(),
    )
    .as_ref()
    .to_vec();
    let pin = fingerprint(pki.root.der());
    validate_device_certificate(
        &response.certificate,
        &response.chain,
        pki.root.der(),
        &pin,
        &public_key,
        &id,
        unix_now().unwrap(),
    )
    .unwrap();
    assert!(
        validate_device_certificate(
            &response.certificate,
            &response.chain,
            pki.root.der(),
            &pin,
            &public_key,
            &Uuid::new_v4().to_string(),
            unix_now().unwrap()
        )
        .is_err()
    );
    assert!(
        validate_device_certificate(
            &response.certificate,
            &response.chain,
            pki.root.der(),
            &pin,
            &[0; 65],
            &id,
            unix_now().unwrap()
        )
        .is_err()
    );
    assert!(
        validate_device_certificate(
            &response.certificate,
            &[pki.root.der().to_vec()],
            pki.root.der(),
            &pin,
            &public_key,
            &id,
            unix_now().unwrap()
        )
        .is_err()
    );
    assert!(
        validate_device_certificate(
            pki.server.der(),
            &response.chain,
            pki.root.der(),
            &pin,
            &public_key,
            &id,
            unix_now().unwrap()
        )
        .is_err()
    );
    assert!(
        validate_device_certificate(
            &response.certificate,
            &response.chain,
            pki.root.der(),
            &pin,
            &public_key,
            &id,
            response.not_after.unwrap().seconds + 1
        )
        .is_err()
    );
}

#[tokio::test]
async fn corrupt_or_rebound_state_is_rejected_without_enrollment() {
    let harness = Harness::new(90 * 86400).await;
    let config = harness.config();
    let mut identity = DeviceIdentity::open(&config).unwrap();
    identity
        .prepare(harness.channel().await, &config, "test")
        .await
        .unwrap();
    let path = identity.status()["StatePath"].as_str().unwrap().to_owned();
    drop(identity);
    let state: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (field, value) in [
        ("key_pkcs8", serde_json::json!("corrupt")),
        ("device_id", serde_json::json!(Uuid::new_v4())),
        ("root_thumbprint", serde_json::json!("00".repeat(32))),
        ("server_url", serde_json::json!("http://other-server:5006")),
    ] {
        let mut bad = state.clone();
        bad[field] = value;
        std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(DeviceIdentity::open(&config).is_err());
    }
    assert_eq!(harness.state.enrollees.load(Ordering::SeqCst), 1);
    harness.stop().await;
}

#[test]
fn device_config_is_explicit_and_never_falls_back_to_app_token() {
    for value in [
        serde_json::json!({"Enabled": true, "ServerUrl": "http://localhost:5006", "AppToken": "legacy"}),
        serde_json::json!({"Enabled": true, "ServerUrl": "http://localhost:5006",
            "DeviceEnrollment": {"RootThumbprint": "00".repeat(32)}}),
    ] {
        let conf: dto::ConfFile = serde_json::from_value(serde_json::json!({"PsuAgent": value})).unwrap();
        assert!(Conf::from_conf_file(&conf).is_ok());
    }

    let invalid: dto::ConfFile = serde_json::from_value(serde_json::json!({"PsuAgent": {
        "Enabled": true, "ServerUrl": "http://localhost:5006", "AppToken": "legacy",
        "DeviceEnrollment": {"RootThumbprint": "00".repeat(32), "EnrollmentToken": "never-log-this"}
    }}))
    .unwrap();
    assert!(Conf::from_conf_file(&invalid).is_err());
    assert!(!format!("{invalid:?}").contains("never-log-this"));
}

#[tokio::test]
async fn legacy_runtime_connects_with_bearer_without_enrollment() {
    let harness = Harness::new(90 * 86400).await;
    let mut config = harness.config();
    config.device_enrollment = None;
    config.app_token = "legacy-agent-token".to_owned();
    config.agent_id = Some("legacy-agent-id".to_owned());
    let (shutdown, signal) = ShutdownHandle::new();
    let agent = tokio::spawn(devolutions_agent::psu_agent::run_psu_agent(config, signal));
    tokio::time::timeout(Duration::from_secs(5), async {
        while harness.state.connections.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    shutdown.signal();
    agent.await.unwrap().unwrap();
    assert_eq!(harness.state.enrollees.load(Ordering::SeqCst), 0);
    assert_eq!(harness.state.renewals.load(Ordering::SeqCst), 0);
    harness.stop().await;
}
