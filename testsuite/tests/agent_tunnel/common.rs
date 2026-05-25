//! Shared helpers for the agent-tunnel test suite.
//!
//! These were originally private to `integration.rs`; consolidated here so
//! the cert-renewal E2E and the routing tests can reuse them without
//! duplicating ~80 lines of QUIC + mTLS scaffolding per test.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agent_tunnel::AgentTunnelHandle;
use agent_tunnel::cert::CaManager;
use agent_tunnel::listener::AgentTunnelListener;
use camino::Utf8PathBuf;
use devolutions_gateway_task::ShutdownHandle;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Start a TCP echo server that echoes back whatever it receives.
pub(super) async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    (addr, handle)
}

/// Generate a key pair and CSR (same as the real agent does during enrollment).
pub(super) fn generate_test_key_and_csr(agent_name: &str) -> (rcgen::KeyPair, String) {
    generate_csr_with_cn(agent_name)
}

/// Generate a key pair and CSR with the given Common Name on the CSR subject.
///
/// Useful for the security-invariant test that checks `sign_agent_csr` ignores
/// the CSR subject in favor of the mTLS-authenticated agent name.
pub(super) fn generate_csr_with_cn(cn: &str) -> (rcgen::KeyPair, String) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate test key pair");
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    let csr = params.serialize_request(&key_pair).expect("serialize test CSR");
    let csr_pem = csr.pem().expect("CSR to PEM");
    (key_pair, csr_pem)
}

/// Create a Quinn client connection to the gateway with mTLS.
pub(super) async fn connect_quinn_client(
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
            .expect("parse client certs");
    let client_key = private_key(&mut std::io::BufReader::new(client_key_pem.as_bytes()))
        .expect("parse private key")
        .expect("no private key found");

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        certs(&mut std::io::BufReader::new(ca_cert_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .expect("parse CA certs");
    for cert in ca_certs {
        roots.add(cert).expect("add CA cert to root store");
    }

    // Trust only the test CA. Hostname verification is still on (SNI = "localhost").
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("build verifier");

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_certs, client_key)
        .expect("client auth config");

    client_crypto.alpn_protocols = vec![agent_tunnel_proto::ALPN_PROTOCOL.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).expect("QUIC client config"),
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind addr")).expect("create endpoint");
    endpoint.set_default_client_config(client_config);

    endpoint
        .connect(server_addr, "localhost")
        .expect("initiate connection")
        .await
        .expect("QUIC handshake")
}

/// Live `AgentTunnelListener` running on a random localhost port, plus the
/// resources needed to drive and shut it down cleanly.
pub(super) struct TestListener {
    pub handle: AgentTunnelHandle,
    shutdown: ShutdownHandle,
    task: JoinHandle<()>,
    _temp_dir: TempDir,
}

impl TestListener {
    /// Signal shutdown and wait for the listener task to exit (or time out).
    pub(super) async fn shutdown(self) {
        self.shutdown.signal();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.task).await;
    }
}

/// Bring up a fresh `AgentTunnelListener` on `127.0.0.1:0` with a freshly
/// generated CA in a temp directory.
pub(super) async fn bind_test_listener() -> TestListener {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let data_dir = Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).expect("UTF-8 temp path");
    let ca_manager = CaManager::load_or_generate(&data_dir).expect("CA generation");

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (listener, handle) = AgentTunnelListener::bind(listen_addr, ca_manager, "localhost")
        .await
        .expect("bind QUIC listener");

    let (shutdown, shutdown_signal) = ShutdownHandle::new();
    let task = tokio::spawn(async move {
        use devolutions_gateway_task::Task;
        let _ = listener.run(shutdown_signal).await;
    });

    // Give listener time to be ready.
    tokio::time::sleep(Duration::from_millis(50)).await;

    TestListener {
        handle,
        shutdown,
        task,
        _temp_dir: temp_dir,
    }
}
