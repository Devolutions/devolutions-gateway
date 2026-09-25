//! `agent-identity-mock` binary: HTTPS (ALPN h2 + http/1.1) mock server for the Agent
//! Identity V1 contract. Writes `<state-dir>/ready.json` once listening.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_identity_mock::{App, Dispatcher, MockClock, State, serve};
use anyhow::Context as _;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use uuid::Uuid;

struct Args {
    listen: SocketAddr,
    path_prefix: String,
    admin_token: String,
    state_dir: PathBuf,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut listen = None;
    let mut path_prefix = None;
    let mut admin_token = None;
    let mut state_dir = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or_else(|| anyhow::anyhow!("missing value for {flag}"));
        match arg.as_str() {
            "--listen" => {
                listen = Some(
                    value("--listen")?
                        .parse::<SocketAddr>()
                        .context("--listen must be host:port")?,
                );
            }
            "--path-prefix" => path_prefix = Some(value("--path-prefix")?),
            "--admin-token" => admin_token = Some(value("--admin-token")?),
            "--state-dir" => state_dir = Some(PathBuf::from(value("--state-dir")?)),
            other => anyhow::bail!("unknown argument {other:?}"),
        }
    }
    let path_prefix = path_prefix.context("missing --path-prefix")?;
    if !path_prefix.starts_with('/') || path_prefix.ends_with('/') {
        anyhow::bail!("--path-prefix must start with `/` and not end with `/`");
    }
    Ok(Args {
        listen: listen.context("missing --listen")?,
        path_prefix,
        admin_token: admin_token.context("missing --admin-token")?,
        state_dir: state_dir.context("missing --state-dir")?,
    })
}

/// TLS CA + server certificate for `localhost` and `127.0.0.1` (rcgen), with ALPN
/// `h2` and `http/1.1`.
fn tls_config() -> anyhow::Result<(tokio_rustls::rustls::ServerConfig, String)> {
    let ca_key = rcgen::KeyPair::generate().context("generate TLS CA key")?;
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).context("TLS CA params")?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Mock TLS Root");
    let ca_cert = ca_params.self_signed(&ca_key).context("self-sign TLS CA")?;

    let server_key = rcgen::KeyPair::generate().context("generate TLS server key")?;
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
        .context("TLS server params")?;
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .context("sign TLS server certificate")?;

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert.der().clone(), ca_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .context("build TLS config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok((config, ca_cert.pem()))
}

/// Writes `ready.json` atomically (write temp + rename).
fn write_ready_file(state_dir: &Path, contents: &str) -> anyhow::Result<()> {
    let target = state_dir.join("ready.json");
    let temp = state_dir.join("ready.json.tmp");
    std::fs::write(&temp, contents).context("write ready.json.tmp")?;
    if target.exists() {
        std::fs::remove_file(&target).context("remove stale ready.json")?;
    }
    std::fs::rename(&temp, &target).context("rename ready.json into place")
}

#[expect(
    clippy::print_stderr,
    reason = "single startup line for a human running the binary; the harness uses ready.json"
)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    std::fs::create_dir_all(&args.state_dir).context("create state dir")?;

    let (tls_config, ca_pem) = tls_config()?;
    let ca_pem_path = args.state_dir.join("mock-tls-ca.pem");
    std::fs::write(&ca_pem_path, &ca_pem).context("write TLS CA PEM")?;

    let listener = TcpListener::bind(args.listen).await.context("bind listener")?;
    let local_addr = listener.local_addr().context("local address")?;
    let base_url = format!("https://127.0.0.1:{}{}", local_addr.port(), args.path_prefix);

    let clock = MockClock::new();
    let state = State::new(clock.now()).context("initial state")?;
    let app = Arc::new(App {
        authority_id: Uuid::new_v4(),
        base_url: base_url.clone(),
        prefix: args.path_prefix,
        unprivileged_token: format!("{}-unprivileged", args.admin_token),
        admin_token: args.admin_token,
        clock,
        handshake_gate: tokio::sync::watch::channel(true).0,
        state: Mutex::new(state),
    });

    let ready = serde_json::json!({
        "base_url": base_url,
        "tls_ca_pem": ca_pem_path.to_string_lossy(),
        "authority_id": app.authority_id,
    });
    write_ready_file(&args.state_dir, &ready.to_string())?;

    // Rotation deadline and rate-limited push ticker (§9.3); the lazy check on every
    // request is the primary path, this covers idle servers with live streams.
    let ticker_app = Arc::clone(&app);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            ticker_app.tick().await;
        }
    });

    eprintln!("agent-identity-mock listening on {base_url}");
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    serve(listener, acceptor, Dispatcher::new(app)).await
}
