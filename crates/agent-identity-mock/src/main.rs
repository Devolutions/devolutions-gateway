//! `agent-identity-mock` binary: HTTPS (ALPN h2 + http/1.1) mock server for the Agent
//! Identity V1 contract. Writes `<state-dir>/ready.json` once listening.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_identity_mock::{App, Dispatcher, ManagementLogin, MockClock, State, serve};
use anyhow::Context as _;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use uuid::Uuid;

struct Args {
    listen: SocketAddr,
    path_prefix: String,
    app_key: String,
    app_secret: String,
    token_lifetime: Duration,
    state_dir: PathBuf,
}

/// DVLS's `tokenId` lifetime.
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(7 * 60);

/// Parses the command-line arguments, without the program name.
///
/// The listen address must be a loopback address because the control surface is unauthenticated
/// ([mock intent][mock-intent], "Mock-only control").
///
/// [mock-intent]: ../INTENT.md#mock-only-control
fn parse_args(args: impl IntoIterator<Item = String>) -> anyhow::Result<Args> {
    let mut listen = None;
    let mut path_prefix = None;
    let mut app_key = None;
    let mut app_secret = None;
    let mut token_lifetime = DEFAULT_TOKEN_LIFETIME;
    let mut state_dir = None;
    let mut args = args.into_iter();
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
            "--app-key" => app_key = Some(value("--app-key")?),
            "--app-secret" => app_secret = Some(value("--app-secret")?),
            "--token-lifetime-secs" => {
                token_lifetime = Duration::from_secs(
                    value("--token-lifetime-secs")?
                        .parse()
                        .context("--token-lifetime-secs must be a number of seconds")?,
                );
            }
            "--state-dir" => state_dir = Some(PathBuf::from(value("--state-dir")?)),
            other => anyhow::bail!("unknown argument {other:?}"),
        }
    }
    let path_prefix = path_prefix.context("missing --path-prefix")?;
    if !path_prefix.starts_with('/') || path_prefix.ends_with('/') {
        anyhow::bail!("--path-prefix must start with `/` and not end with `/`");
    }
    let listen: SocketAddr = listen.context("missing --listen")?;
    if !listen.ip().is_loopback() {
        anyhow::bail!("--listen must be a loopback address because the mock control surface is unauthenticated");
    }
    Ok(Args {
        listen,
        path_prefix,
        app_key: app_key.context("missing --app-key")?,
        app_secret: app_secret.context("missing --app-secret")?,
        token_lifetime,
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
    let args = parse_args(std::env::args().skip(1))?;
    std::fs::create_dir_all(&args.state_dir).context("create state dir")?;

    let (tls_config, ca_pem) = tls_config()?;
    let ca_pem_path = args.state_dir.join("mock-tls-ca.pem");
    std::fs::write(&ca_pem_path, &ca_pem).context("write TLS CA PEM")?;

    let listener = TcpListener::bind(args.listen).await.context("bind listener")?;
    let local_addr = listener.local_addr().context("local address")?;
    let base_url = format!("https://127.0.0.1:{}{}", local_addr.port(), args.path_prefix);

    let clock = MockClock::new();
    let state = State::new(clock.now());
    let app = Arc::new(App {
        authority_id: Uuid::new_v4(),
        base_url: base_url.clone(),
        prefix: args.path_prefix,
        login: ManagementLogin::new(args.app_key, args.app_secret, args.token_lifetime),
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

    // Rotation deadlines (CONTRACT.agent-identity.md §8.3) and the rotation notification rate
    // (INTENT.DVLS.md, "Load") are applied on each request.
    // The ticker covers idle servers with live streams.
    let ticker_app = Arc::clone(&app);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rstest::rstest;

    use super::parse_args;

    fn args_with_listen(listen: &str) -> Vec<String> {
        [
            "--listen",
            listen,
            "--path-prefix",
            "/mock",
            "--app-key",
            "admin",
            "--app-secret",
            "secret",
            "--state-dir",
            "state",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    #[rstest]
    #[case::ipv4("127.0.0.1:0")]
    #[case::ipv6("[::1]:0")]
    fn loopback_listen_address_is_accepted(#[case] listen: &str) {
        let args = parse_args(args_with_listen(listen)).expect("loopback address is accepted");
        assert_eq!(args.listen.to_string(), listen);
    }

    #[rstest]
    #[case::ipv4_unspecified("0.0.0.0:0")]
    #[case::ipv6_unspecified("[::]:0")]
    #[case::ipv4_routable("192.0.2.1:0")]
    fn non_loopback_listen_address_is_refused(#[case] listen: &str) {
        let error = parse_args(args_with_listen(listen))
            .err()
            .expect("non-loopback address is refused");
        assert!(error.to_string().contains("loopback"), "{error}");
    }

    /// DVLS's `tokenId` lifetime, 7 minutes, is the default.
    #[rstest]
    #[case::default(&[], Duration::from_secs(7 * 60))]
    #[case::flag(&["--token-lifetime-secs", "30"], Duration::from_secs(30))]
    fn token_lifetime_is_dvls_lifetime_unless_set(#[case] extra_args: &[&str], #[case] expected: Duration) {
        let mut args = args_with_listen("127.0.0.1:0");
        args.extend(extra_args.iter().map(|arg| (*arg).to_owned()));
        let lifetime = parse_args(args).ok().map(|args| args.token_lifetime);
        assert_eq!(lifetime, Some(expected));
    }
}
