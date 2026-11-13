//! The peers around Gateway, each a `credential-injection-mock` child process.
//!
//! A peer prints one JSON event per line. The handles here collect those events and answer
//! the questions tests ask: which cookies the target saw, which account finished CredSSP,
//! which Kerberos requests the KDC got.

use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, BufReader};
use tokio::process::Child;
use tokio::task::JoinHandle;

use super::{REALM, SERVICE_HOST};
use crate::cli::credential_injection_mock_tokio_cmd;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ObservedKdcReq {
    As { cname: String, realm: String },
    Tgs { sname: Vec<String>, realm: String },
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservedKdcReply {
    AsRep,
    TgsRep,
    KrbError,
    Other,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
enum Event {
    Listening { port: u16 },
    Accepted,
    Cookie { cookie: String },
    CredsspFinished { account: String },
    KdcRequest { request: ObservedKdcReq },
    KdcExchangeServed,
    ConnectionRequestSent,
    TlsConnected,
    KdcProxyRequest { request: ObservedKdcReq },
    KdcProxyReply { reply: ObservedKdcReply },
}

struct MockProcess {
    process: Child,
    events: Arc<Mutex<Vec<Event>>>,
    stderr: Arc<Mutex<String>>,
    collectors: [JoinHandle<()>; 2],
}

impl MockProcess {
    async fn start(args: &[&str]) -> anyhow::Result<Self> {
        let mut process = credential_injection_mock_tokio_cmd()
            .args(args)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("start credential-injection-mock {args:?}"))?;

        let events = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        let collectors = [
            collect_lines(process.stdout.take().context("mock stdout")?, {
                let events = Arc::clone(&events);
                let stderr = Arc::clone(&stderr);
                move |line| match serde_json::from_str::<Event>(&line) {
                    Ok(event) => events.lock().expect("event mutex").push(event),
                    Err(error) => stderr
                        .lock()
                        .expect("stderr mutex")
                        .push_str(&format!("unparsed event {line:?}: {error}\n")),
                }
            }),
            collect_lines(process.stderr.take().context("mock stderr")?, {
                let stderr = Arc::clone(&stderr);
                move |line| {
                    let mut stderr = stderr.lock().expect("stderr mutex");
                    stderr.push_str(&line);
                    stderr.push('\n');
                }
            }),
        ];

        Ok(Self {
            process,
            events,
            stderr,
            collectors,
        })
    }

    async fn start_listening(args: &[&str]) -> anyhow::Result<(Self, u16)> {
        let mut mock = Self::start(args).await?;
        mock.wait_for(&format!("{args:?} to listen"), |event| {
            matches!(event, Event::Listening { .. })
        })
        .await?;
        let port = mock
            .events()
            .iter()
            .find_map(|event| match event {
                Event::Listening { port } => Some(*port),
                _ => None,
            })
            .context("listening event")?;
        Ok((mock, port))
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().expect("event mutex").clone()
    }

    fn count(&self, matches: impl Fn(&Event) -> bool) -> usize {
        self.events
            .lock()
            .expect("event mutex")
            .iter()
            .filter(|event| matches(event))
            .count()
    }

    // A peer that died would make checks like "no connection reached the target" pass.
    fn live_events(&self) -> Vec<Event> {
        assert!(
            !self.collectors[0].is_finished(),
            "credential-injection-mock exited; stderr:\n{}",
            self.stderr()
        );
        self.events()
    }

    fn live_count(&self, matches: impl Fn(&Event) -> bool) -> usize {
        self.live_events().iter().filter(|event| matches(event)).count()
    }

    fn stderr(&self) -> String {
        self.stderr.lock().expect("stderr mutex").clone()
    }

    async fn wait_for(&mut self, what: &str, matches: impl Fn(&Event) -> bool) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let stdout_done = self.collectors[0].is_finished();
            if self.count(&matches) > 0 {
                return Ok(());
            }
            if stdout_done && let Some(status) = self.process.try_wait().context("poll credential-injection-mock")? {
                let _ = (&mut self.collectors[1]).await;
                anyhow::bail!(
                    "credential-injection-mock exited ({status}) before {what}; stderr:\n{}",
                    self.stderr()
                );
            }
            if Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for {what}; stderr:\n{}", self.stderr());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_exit(mut self) -> anyhow::Result<(ExitStatus, Vec<Event>, String)> {
        let status = self.process.wait().await.context("wait credential-injection-mock")?;
        for collector in self.collectors {
            collector.await.context("collect credential-injection-mock output")?;
        }
        let events = self.events.lock().expect("event mutex").clone();
        let stderr = self.stderr.lock().expect("stderr mutex").clone();
        Ok((status, events, stderr))
    }
}

fn collect_lines<R>(stream: R, mut on_line: impl FnMut(String) + Send + 'static) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            on_line(line);
        }
    })
}

/// Stands in for the destination RDP server and records the X.224 Connection Request cookie
/// the proxy forwards.
pub struct FakeRdpTarget {
    pub port: u16,
    mock: MockProcess,
}

impl FakeRdpTarget {
    pub async fn start() -> anyhow::Result<Self> {
        let (mock, port) = MockProcess::start_listening(&["rdp-target"]).await?;
        Ok(Self { port, mock })
    }

    pub fn accepted(&self) -> usize {
        self.mock.live_count(|event| matches!(event, Event::Accepted))
    }

    pub async fn wait_cookies(&self, count: usize) -> anyhow::Result<Vec<String>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let cookies = cookies(&self.mock);
            if cookies.len() >= count {
                return Ok(cookies);
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "timed out waiting for {count} decoded X.224 cookie(s); accepted={}",
                    self.accepted()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Accepts connections and never speaks; proves the proxy did (or did not) dial the target.
pub struct FakeClosedTarget {
    pub port: u16,
    mock: MockProcess,
}

impl FakeClosedTarget {
    pub async fn start() -> anyhow::Result<Self> {
        let (mock, port) = MockProcess::start_listening(&["closed-target"]).await?;
        Ok(Self { port, mock })
    }

    pub fn accepted(&self) -> usize {
        self.mock.live_count(|event| matches!(event, Event::Accepted))
    }
}

/// Fake RDP server that completes CredSSP as the target account.
pub struct MockRdp {
    pub port: u16,
    mock: MockProcess,
}

impl MockRdp {
    pub async fn start_kerberos(kdc_url: String) -> anyhow::Result<Self> {
        let (mock, port) =
            MockProcess::start_listening(&["rdp-server", "--auth", "kerberos", "--kdc-url", kdc_url.as_str()]).await?;
        Ok(Self { port, mock })
    }

    pub async fn start_ntlm() -> anyhow::Result<Self> {
        let (mock, port) = MockProcess::start_listening(&["rdp-server", "--auth", "ntlm"]).await?;
        Ok(Self { port, mock })
    }

    pub fn credssp_ok(&self) -> bool {
        self.finished_account().is_some()
    }

    pub fn finished_account(&self) -> Option<String> {
        self.mock.live_events().into_iter().find_map(|event| match event {
            Event::CredsspFinished { account } => Some(account),
            _ => None,
        })
    }

    pub fn cookies(&self) -> Vec<String> {
        cookies(&self.mock)
    }

    pub async fn wait_credssp(&self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.credssp_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "timed out waiting for CredSSP on mock RDP; mock stderr:\n{}",
                    self.mock.stderr()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn cookies(mock: &MockProcess) -> Vec<String> {
    mock.live_events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Cookie { cookie } => Some(cookie),
            _ => None,
        })
        .collect()
}

/// Real Kerberos KDC (the `kdc` crate) that records every request it gets.
pub struct MockKdc {
    port: u16,
    mock: MockProcess,
}

impl MockKdc {
    pub async fn start() -> anyhow::Result<Self> {
        let (mock, port) = MockProcess::start_listening(&["kdc"]).await?;
        Ok(Self { port, mock })
    }

    pub fn url(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }

    pub fn exchanges(&self) -> usize {
        self.mock.live_count(|event| matches!(event, Event::KdcExchangeServed))
    }

    pub fn requests(&self) -> Vec<ObservedKdcReq> {
        self.mock
            .live_events()
            .into_iter()
            .filter_map(|event| match event {
                Event::KdcRequest { request } => Some(request),
                _ => None,
            })
            .collect()
    }
}

pub fn assert_target_kdc_as_and_tgs(kdc: &MockKdc) -> anyhow::Result<()> {
    let reqs = kdc.requests();
    anyhow::ensure!(
        reqs.iter().any(|req| matches!(
            req,
            ObservedKdcReq::As { cname, realm }
                if cname.eq_ignore_ascii_case("administrator") && realm.eq_ignore_ascii_case(REALM)
        )),
        "KDC must see AS-REQ cname=administrator realm={REALM}; requests={reqs:?}"
    );
    anyhow::ensure!(
        reqs.iter().any(|req| matches!(
            req,
            ObservedKdcReq::Tgs { sname, realm }
                if *sname == ["TERMSRV", SERVICE_HOST] && realm.eq_ignore_ascii_case(REALM)
        )),
        "KDC must see TGS-REQ sname=TERMSRV/{SERVICE_HOST} realm={REALM}; requests={reqs:?}"
    );
    Ok(())
}

/// Accepts TCP and closes it at once, so ticket fetching fails.
pub struct RefusingKdc {
    port: u16,
    mock: MockProcess,
}

impl RefusingKdc {
    pub async fn start() -> anyhow::Result<Self> {
        let (mock, port) = MockProcess::start_listening(&["refusing-kdc"]).await?;
        Ok(Self { port, mock })
    }

    pub fn url(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }

    pub fn accepted(&self) -> usize {
        self.mock.live_count(|event| matches!(event, Event::Accepted))
    }
}

/// An RDP client connection that sent its opening bytes and stays open until dropped.
pub struct RdpConnection {
    _mock: MockProcess,
}

/// Sends the preconnection blob and an X.224 Connection Request offering SSL, HYBRID and HYBRID_EX.
pub async fn connect_rdp_client(gateway_tcp: u16, association_token: &str) -> anyhow::Result<RdpConnection> {
    send_connection_request(gateway_tcp, association_token, "full").await
}

/// Sends the preconnection blob and an X.224 Connection Request offering SSL and HYBRID only.
pub async fn send_hybrid_connection_request(
    gateway_tcp: u16,
    association_token: &str,
) -> anyhow::Result<RdpConnection> {
    send_connection_request(gateway_tcp, association_token, "hybrid").await
}

async fn send_connection_request(gateway_tcp: u16, association_token: &str, cr: &str) -> anyhow::Result<RdpConnection> {
    let gateway_port = gateway_tcp.to_string();
    let mut mock = MockProcess::start(&[
        "send-connection-request",
        "--gateway-port",
        gateway_port.as_str(),
        "--token",
        association_token,
        "--cr",
        cr,
    ])
    .await?;
    mock.wait_for("the connection request", |event| {
        matches!(event, Event::ConnectionRequestSent)
    })
    .await?;
    Ok(RdpConnection { _mock: mock })
}

pub enum ClientAuth {
    /// SPNEGO restricted to NTLM, as the proxy user.
    Ntlm,
    /// Bare NTLM, as the proxy user.
    RawNtlm,
    /// SPNEGO restricted to Kerberos, as the Kerberos proxy user, with tickets from `kdc_proxy_url`.
    Kerberos { kdc_proxy_url: String },
}

/// An RDP client that reached TLS with Gateway and is running CredSSP.
pub struct CredsspClient {
    mock: MockProcess,
}

/// What the client sent to and got back from `/jet/KdcProxy`.
pub struct KdcProxyTraffic {
    pub requests: Vec<ObservedKdcReq>,
    pub replies: Vec<ObservedKdcReply>,
}

/// Connects to the Gateway TCP listener with the association token and waits until TLS is up.
pub async fn connect_credssp_client(
    gateway_tcp: u16,
    association_token: &str,
    auth: ClientAuth,
) -> anyhow::Result<CredsspClient> {
    let gateway_port = gateway_tcp.to_string();
    let mut args = vec![
        "credssp-client",
        "--gateway-port",
        gateway_port.as_str(),
        "--token",
        association_token,
    ];
    match &auth {
        ClientAuth::Ntlm => args.extend(["--auth", "ntlm"]),
        ClientAuth::RawNtlm => args.extend(["--auth", "raw-ntlm"]),
        ClientAuth::Kerberos { kdc_proxy_url } => {
            args.extend(["--auth", "kerberos", "--kdc-proxy-url", kdc_proxy_url.as_str()]);
        }
    }
    let mut mock = MockProcess::start(&args).await?;
    mock.wait_for("TLS with Gateway", |event| matches!(event, Event::TlsConnected))
        .await?;
    Ok(CredsspClient { mock })
}

impl CredsspClient {
    /// Waits for CredSSP to end; fails when the client did not finish it.
    pub async fn finish(self) -> anyhow::Result<KdcProxyTraffic> {
        let (status, events, stderr) = self.mock.wait_exit().await?;
        anyhow::ensure!(status.success(), "client CredSSP failed ({status}):\n{stderr}");
        let mut traffic = KdcProxyTraffic {
            requests: Vec::new(),
            replies: Vec::new(),
        };
        for event in events {
            match event {
                Event::KdcProxyRequest { request } => traffic.requests.push(request),
                Event::KdcProxyReply { reply } => traffic.replies.push(reply),
                _ => {}
            }
        }
        Ok(traffic)
    }
}
