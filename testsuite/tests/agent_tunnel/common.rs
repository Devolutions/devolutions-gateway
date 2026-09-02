use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_tunnel::AgentTunnelHandle;
use agent_tunnel::authorization::{EnrollmentAttempt, EnrollmentOutcome};
use agent_tunnel::cert::{CaManager, SignedAgentCert};
use agent_tunnel::listener::AgentTunnelListener;
use agent_tunnel::registry::AgentRegistry;
use agent_tunnel_proto::{ControlMessage, ControlStream, DomainAdvertisement, SessionStream};
use camino::Utf8PathBuf;
use devolutions_gateway_task::ShutdownHandle;
use ipnetwork::Ipv4Network;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use uuid::Uuid;

pub(super) async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo server");
    let addr = listener.local_addr().expect("read echo server address");
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept echo connection");
        let (mut read, mut write) = stream.into_split();
        tokio::io::copy(&mut read, &mut write).await.expect("echo data");
    });

    (addr, task)
}

pub(super) fn generate_csr_with_cn(cn: &str) -> (rcgen::KeyPair, String) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate test key pair");
    let csr_pem = generate_csr_with_key(cn, &key_pair);
    (key_pair, csr_pem)
}

pub(super) fn generate_csr_with_key(cn: &str, key_pair: &rcgen::KeyPair) -> String {
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    let csr = params.serialize_request(key_pair).expect("serialize test csr");
    csr.pem().expect("encode test csr")
}

async fn connect_quinn_client(
    ca_cert_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
    server_addr: SocketAddr,
) -> quinn::Connection {
    use rustls_pemfile::{certs, private_key};

    let _ = rustls::crypto::ring::default_provider().install_default();

    let client_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        certs(&mut std::io::BufReader::new(client_cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .expect("parse client certificates");
    let client_key = private_key(&mut std::io::BufReader::new(client_key_pem.as_bytes()))
        .expect("parse client key")
        .expect("find client key");

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        certs(&mut std::io::BufReader::new(ca_cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .expect("parse ca certificates");
    for cert in ca_certs {
        roots.add(cert).expect("add ca certificate");
    }

    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("build server verifier");
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_certs, client_key)
        .expect("configure client authentication");
    client_crypto.alpn_protocols = vec![agent_tunnel_proto::ALPN_PROTOCOL.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).expect("configure quic client"),
    ));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("parse client bind address"))
        .expect("create client endpoint");
    endpoint.set_default_client_config(client_config);

    endpoint
        .connect(server_addr, "localhost")
        .expect("start quic connection")
        .await
        .expect("complete quic handshake")
}

pub(super) struct TestListener {
    pub handle: AgentTunnelHandle,
    pub server_addr: SocketAddr,
    shutdown: ShutdownHandle,
    task: JoinHandle<anyhow::Result<()>>,
    _temp_dir: TempDir,
}

impl TestListener {
    pub(super) async fn connect_agent(&self, agent_name: &str) -> (Uuid, quinn::Connection) {
        let (agent_id, connection, _key_pair) = self.connect_agent_with_key(agent_name).await;
        (agent_id, connection)
    }

    pub(super) async fn connect_agent_with_key(&self, agent_name: &str) -> (Uuid, quinn::Connection, rcgen::KeyPair) {
        let agent_id = Uuid::new_v4();
        let (key_pair, csr_pem) = generate_csr_with_cn(agent_name);
        let signed = self
            .handle
            .ca_manager()
            .sign_agent_csr(agent_id, agent_name, &csr_pem, Some("localhost"))
            .expect("sign agent csr");
        let client_cert_der = rustls_pemfile::certs(&mut std::io::BufReader::new(signed.client_cert_pem.as_bytes()))
            .next()
            .expect("find signed Agent certificate")
            .expect("parse signed Agent certificate");
        let client_spki_sha256 =
            agent_tunnel::cert::spki_sha256_digest_from_der(&client_cert_der).expect("hash Agent public key");
        let enrollment = self
            .handle
            .enroll(EnrollmentAttempt {
                token_id: Uuid::new_v4(),
                token_expires_at: 1_999_999_999,
                agent_id,
                name: agent_name.to_owned(),
                client_spki_sha256,
                request_sha256: [0; 32],
            })
            .await
            .expect("accept test Agent");
        assert!(matches!(enrollment, EnrollmentOutcome::Created(_)));
        let connection = connect_quinn_client(
            &signed.ca_cert_pem,
            &signed.client_cert_pem,
            &key_pair.serialize_pem(),
            self.server_addr,
        )
        .await;

        (agent_id, connection, key_pair)
    }

    /// Connect with a CA-signed certificate without going through enrollment,
    /// so tests can drive the listener admission gate directly.
    pub(super) async fn connect_signed(
        &self,
        signed: &SignedAgentCert,
        key_pair: &rcgen::KeyPair,
    ) -> quinn::Connection {
        connect_quinn_client(
            &signed.ca_cert_pem,
            &signed.client_cert_pem,
            &key_pair.serialize_pem(),
            self.server_addr,
        )
        .await
    }

    pub(super) async fn shutdown(self) {
        self.shutdown.signal();
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("listener shutdown timed out")
            .expect("listener task panicked")
            .expect("listener shutdown failed");
    }
}

pub(super) async fn bind_test_listener() -> TestListener {
    let temp_dir = tempfile::tempdir().expect("create temporary directory");
    let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("use utf-8 temporary path");
    let ca_manager = CaManager::load_or_generate(&data_dir).expect("generate test ca");
    let ca_spki_sha256 = ca_manager.ca_spki_sha256().expect("hash test CA public key");
    let authorization_store = agent_tunnel_libsql::LibSqlAgentAuthorizationStore::open(":memory:", ca_spki_sha256)
        .await
        .expect("open test Agent authorization store");
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse listener address");
    let (listener, handle) =
        AgentTunnelListener::bind(listen_addr, ca_manager, "localhost", Arc::new(authorization_store))
            .await
            .expect("bind quic listener");
    let server_addr = listener.local_addr();
    let (shutdown, shutdown_signal) = ShutdownHandle::new();
    let task = tokio::spawn(async move {
        use devolutions_gateway_task::Task;
        listener.run(shutdown_signal).await
    });

    TestListener {
        handle,
        server_addr,
        shutdown,
        task,
        _temp_dir: temp_dir,
    }
}

pub(super) async fn wait_for_route_advertised(registry: &AgentRegistry, agent_id: Uuid, min_epoch: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(peer) = registry.get(&agent_id).await
            && peer.route_state().epoch >= min_epoch
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "agent {agent_id} did not advertise route at epoch >= {min_epoch} within 5s"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub(super) async fn advertise_routes(
    connection: &quinn::Connection,
    registry: &AgentRegistry,
    agent_id: Uuid,
    epoch: u64,
    subnets: Vec<Ipv4Network>,
    domains: Vec<DomainAdvertisement>,
) -> ControlStream<quinn::SendStream, quinn::RecvStream> {
    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.expect("open control stream").into();
    ctrl.send(&ControlMessage::route_advertise(epoch, subnets, domains))
        .await
        .expect("send route advertisement");
    wait_for_route_advertised(registry, agent_id, epoch).await;
    ctrl
}

pub(super) async fn accept_session_request(
    connection: &quinn::Connection,
    session_id: Uuid,
    expected_target: &str,
) -> SessionStream<quinn::SendStream, quinn::RecvStream> {
    let (send, recv) = connection.accept_bi().await.expect("accept session stream");
    let mut session: SessionStream<_, _> = (send, recv).into();
    let request = session.recv_request().await.expect("receive connect request");
    assert_eq!(request.session_id(), session_id);
    assert_eq!(request.target(), expected_target);
    session
}
