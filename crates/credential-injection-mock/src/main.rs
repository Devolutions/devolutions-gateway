//! `credential-injection-mock` binary: the peers around Gateway in the credential-injection
//! tests, one role per process.
//!
//! The testsuite drives this program instead of linking the RDP and Kerberos crates it needs.
//! Every role binds a loopback port, prints `{"event":"listening","port":..}` and then one JSON
//! line per thing it observed, so the test reads what happened from standard output.

mod client;
mod event;
mod kdc;
mod rdp_server;
mod rdp_target;
mod tls;

use anyhow::Context as _;

/// Fixture world shared with the tests: the testsuite provisions and asserts these values.
mod fixture {
    pub(crate) const CLIENT_COOKIE: &str = "client-cookie-user";
    pub(crate) const TARGET_USER: &str = "injected-target-user";
    pub(crate) const PROXY_USER: &str = "injected-proxy-user";
    pub(crate) const PROXY_PASSWORD: &str = "proxy-secret";
    pub(crate) const TARGET_PASSWORD: &str = "target-secret";
    pub(crate) const KERBEROS_TARGET_USER: &str = "administrator@example.invalid";
    pub(crate) const PROXY_KERBEROS_USER: &str = "injected-proxy-user@example.invalid";
    pub(crate) const REALM: &str = "EXAMPLE.INVALID";
    // sspi-rs downgrades Negotiate to NTLM when the SPN host is an IP address.
    pub(crate) const SERVICE_HOST: &str = "localhost";
    pub(crate) const KRBTGT_KEY: [u8; 32] = [0x11; 32];
    pub(crate) const TERMSRV_KEY: [u8; 32] = [0x22; 32];
}

enum Role {
    RdpTarget,
    ClosedTarget,
    RdpServer(rdp_server::Auth),
    Kdc,
    RefusingKdc,
    SendConnectionRequest {
        gateway_port: u16,
        token: String,
        request: client::ConnectionRequest,
    },
    CredsspClient {
        gateway_port: u16,
        token: String,
        auth: client::Auth,
    },
}

const USAGE: &str = "usage: credential-injection-mock <role> [options]
roles:
  rdp-target
  closed-target
  rdp-server --auth ntlm
  rdp-server --auth kerberos --kdc-url <tcp://host:port>
  kdc
  refusing-kdc
  send-connection-request --gateway-port <port> --token <jwt> --cr full|hybrid
  credssp-client --gateway-port <port> --token <jwt> --auth ntlm|raw-ntlm
  credssp-client --gateway-port <port> --token <jwt> --auth kerberos --kdc-proxy-url <url>";

fn parse_args(args: impl IntoIterator<Item = String>) -> anyhow::Result<Role> {
    let mut args = args.into_iter();
    let role = args.next().context(USAGE)?;

    let mut gateway_port = None;
    let mut token = None;
    let mut auth = None;
    let mut kdc_url = None;
    let mut kdc_proxy_url = None;
    let mut cr = None;
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().with_context(|| format!("missing value for {flag}"));
        match arg.as_str() {
            "--gateway-port" => {
                gateway_port = Some(
                    value("--gateway-port")?
                        .parse::<u16>()
                        .context("--gateway-port must be a port number")?,
                );
            }
            "--token" => token = Some(value("--token")?),
            "--auth" => auth = Some(value("--auth")?),
            "--kdc-url" => kdc_url = Some(value("--kdc-url")?),
            "--kdc-proxy-url" => kdc_proxy_url = Some(value("--kdc-proxy-url")?),
            "--cr" => cr = Some(value("--cr")?),
            other => anyhow::bail!("unknown argument {other:?}\n{USAGE}"),
        }
    }

    let role = match role.as_str() {
        "rdp-target" => Role::RdpTarget,
        "closed-target" => Role::ClosedTarget,
        "rdp-server" => match auth.as_deref() {
            Some("ntlm") => Role::RdpServer(rdp_server::Auth::Ntlm),
            Some("kerberos") => Role::RdpServer(rdp_server::Auth::Kerberos {
                kdc_url: kdc_url.context("rdp-server --auth kerberos needs --kdc-url")?,
            }),
            other => anyhow::bail!("rdp-server --auth must be ntlm or kerberos, got {other:?}"),
        },
        "kdc" => Role::Kdc,
        "refusing-kdc" => Role::RefusingKdc,
        "send-connection-request" => Role::SendConnectionRequest {
            gateway_port: gateway_port.context("missing --gateway-port")?,
            token: token.context("missing --token")?,
            request: match cr.as_deref() {
                Some("full") => client::ConnectionRequest::Full,
                Some("hybrid") => client::ConnectionRequest::Hybrid,
                other => anyhow::bail!("--cr must be full or hybrid, got {other:?}"),
            },
        },
        "credssp-client" => Role::CredsspClient {
            gateway_port: gateway_port.context("missing --gateway-port")?,
            token: token.context("missing --token")?,
            auth: match auth.as_deref() {
                Some("ntlm") => client::Auth::Ntlm,
                Some("raw-ntlm") => client::Auth::RawNtlm,
                Some("kerberos") => client::Auth::Kerberos {
                    kdc_proxy_url: kdc_proxy_url.context("credssp-client --auth kerberos needs --kdc-proxy-url")?,
                },
                other => anyhow::bail!("credssp-client --auth must be ntlm, raw-ntlm or kerberos, got {other:?}"),
            },
        },
        other => anyhow::bail!("unknown role {other:?}\n{USAGE}"),
    };
    Ok(role)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let role = parse_args(std::env::args().skip(1))?;
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider is installed once per process");

    match role {
        Role::RdpTarget => rdp_target::run_rdp_target().await,
        Role::ClosedTarget => rdp_target::run_closed_target().await,
        Role::RdpServer(auth) => rdp_server::run(auth).await,
        Role::Kdc => kdc::run_kdc().await,
        Role::RefusingKdc => kdc::run_refusing_kdc().await,
        Role::SendConnectionRequest {
            gateway_port,
            token,
            request,
        } => client::send_connection_request(gateway_port, &token, request).await,
        Role::CredsspClient {
            gateway_port,
            token,
            auth,
        } => client::run_credssp(gateway_port, &token, auth).await,
    }
}
