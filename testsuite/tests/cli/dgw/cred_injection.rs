//! Process-level tests for RDP credential injection, reconnect, and fail-closed routing.
//!
//! These tests start a real Gateway, provision credentials over `/jet/preflight` the way DVLS
//! does, then connect to the TCP listener with an RDP preconnection blob. A loopback peer stands
//! in for the destination RDP server and records the X.224 Connection Request the proxy forwards.
//! Injection is observed from Gateway logs and from the rewritten mstshash cookie. CredSSP is not
//! completed: the contract under test is checkout, reconnect, and fail-closed routing.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use base64::Engine as _;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle, VerbosityProfile};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Child;

const CLIENT_COOKIE: &str = "client-cookie-user";
const TARGET_USER: &str = "injected-target-user";
const PROXY_USER: &str = "injected-proxy-user";
const KERBEROS_TARGET_USER: &str = "administrator@example.invalid";
const INJECT_LOG: &str = "RDP-TLS forwarding with credential injection";
const FORWARD_LOG: &str = "Upstream forwarding";
const MISSING_LOG: &str = "missing or expired; re-provision to retry";
const PUBLISHED_KDC_LOG: &str = "Published synthetic KDC";
const REGISTERED_KDC_LOG: &str = "Registered synthetic KDC for credential-injection session";

fn next_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("00000000-0000-4000-a000-{n:012x}")
}

fn unsigned_jws(header: serde_json::Value, payload: serde_json::Value) -> anyhow::Result<String> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(serde_json::to_vec(&header).context("serialize JWT header")?);
    let payload = engine.encode(serde_json::to_vec(&payload).context("serialize JWT payload")?);
    Ok(format!("{header}.{payload}.ZHVtbXlfc2lnbmF0dXJl"))
}

fn preflight_scope_token() -> anyhow::Result<String> {
    unsigned_jws(
        serde_json::json!({"alg":"RS256","typ":"JWT","cty":"SCOPE"}),
        serde_json::json!({
            "scope": "gateway.preflight",
            "exp": 9_999_999_999i64,
            "jti": next_id(),
        }),
    )
}

fn association_token(jti: &str, jet_aid: &str, dest_port: u16, jet_reuse: u32) -> anyhow::Result<String> {
    unsigned_jws(
        serde_json::json!({"alg":"RS256","typ":"JWT","cty":"ASSOCIATION"}),
        serde_json::json!({
            "dst_hst": format!("127.0.0.1:{dest_port}"),
            "exp": 9_999_999_999i64,
            "jet_aid": jet_aid,
            "jet_ap": "rdp",
            "jet_cm": "fwd",
            "jet_rec": "none",
            "jet_reuse": jet_reuse,
            "jti": jti,
            "nbf": 0,
        }),
    )
}

fn encode_pcb(token: &str) -> anyhow::Result<Vec<u8>> {
    let pcb = ironrdp_pdu::pcb::PreconnectionBlob {
        version: ironrdp_pdu::pcb::PcbVersion::V2,
        id: 0,
        v2_payload: Some(token.to_owned()),
    };
    ironrdp_core::encode_vec(&pcb).context("encode preconnection blob")
}

fn encode_connection_request(cookie: &str) -> anyhow::Result<Vec<u8>> {
    use ironrdp_pdu::nego::{ConnectionRequest, NegoRequestData, RequestFlags, SecurityProtocol};
    use ironrdp_pdu::x224::X224;

    let pdu = X224(ConnectionRequest {
        nego_data: Some(NegoRequestData::cookie(cookie.to_owned())),
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX | SecurityProtocol::SSL,
    });
    ironrdp_core::encode_vec(&pdu).context("encode X.224 connection request")
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct LogBuffer(Arc<Mutex<String>>);

impl LogBuffer {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(String::new())))
    }

    fn snapshot(&self) -> String {
        strip_ansi(&self.0.lock().expect("log mutex"))
    }

    async fn wait_contains(&self, needle: &str) -> anyhow::Result<String> {
        self.wait_count(needle, 1).await
    }

    async fn wait_count(&self, needle: &str, count: usize) -> anyhow::Result<String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let snapshot = self.snapshot();
            if snapshot.matches(needle).count() >= count {
                return Ok(snapshot);
            }
            if Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for {count} occurrence(s) of {needle:?}; logs:\n{snapshot}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

struct FakeRdpTarget {
    port: u16,
    accepted: Arc<AtomicUsize>,
    payloads: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeRdpTarget {
    async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind fake RDP target")?;
        let port = listener.local_addr().context("fake RDP local_addr")?.port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let payloads = Arc::new(Mutex::new(Vec::new()));
        let accepted_task = Arc::clone(&accepted);
        let payloads_task = Arc::clone(&payloads);

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                accepted_task.fetch_add(1, Ordering::SeqCst);
                let payloads = Arc::clone(&payloads_task);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    // CredSSP cert generation can delay the rewritten X.224 CR.
                    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buf)).await
                        && n > 0
                    {
                        payloads.lock().expect("payload mutex").push(buf[..n].to_vec());
                    }
                    // Keep the accepted socket open so the proxy can finish writing the CR.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });

        Ok(Self {
            port,
            accepted,
            payloads,
        })
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    async fn wait_payloads(&self, count: usize) -> anyhow::Result<Vec<Vec<u8>>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            {
                let payloads = self.payloads.lock().expect("payload mutex");
                if payloads.len() >= count {
                    return Ok(payloads.clone());
                }
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "timed out waiting for {count} target payload(s); accepted={}",
                    self.accepted()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

struct GatewayProc {
    config: DgwConfigHandle,
    process: Child,
    logs: LogBuffer,
}

impl GatewayProc {
    async fn start(kerberos: bool) -> anyhow::Result<Self> {
        let config = DgwConfig::builder()
            .disable_token_validation(true)
            .verbosity_profile(VerbosityProfile::DEBUG)
            .enable_unstable(kerberos)
            .kerberos_credential_injection(kerberos)
            .build()
            .init()
            .context("init gateway config")?;

        let mut process = dgw_tokio_cmd()
            .env("DGATEWAY_CONFIG_PATH", config.config_dir())
            .env("RUST_LOG", "devolutions_gateway=debug")
            .env("NO_COLOR", "1")
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("start Devolutions Gateway")?;

        let logs = LogBuffer::new();
        spawn_stdio_collector(process.stdout.take(), Arc::clone(&logs.0));
        spawn_stdio_collector(process.stderr.take(), Arc::clone(&logs.0));

        wait_for_tcp_port(config.http_port())
            .await
            .context("wait for gateway HTTP port")?;

        Ok(Self { config, process, logs })
    }
}

fn spawn_stdio_collector<R>(stream: Option<R>, logs: Arc<Mutex<String>>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Some(stream) = stream else {
        return;
    };
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => logs.lock().expect("log mutex").push_str(&line),
            }
        }
    });
}

async fn post_preflight(http_port: u16, operations: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let bearer = preflight_scope_token()?;
    let body = serde_json::to_string(&operations).context("serialize preflight body")?;
    let request = format!(
        "POST /jet/preflight HTTP/1.1\r\n\
         Host: 127.0.0.1:{http_port}\r\n\
         Content-Type: application/json\r\n\
         Authorization: Bearer {bearer}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );

    let mut stream = TcpStream::connect(("127.0.0.1", http_port))
        .await
        .context("connect to gateway HTTP")?;
    stream.write_all(request.as_bytes()).await.context("write preflight")?;
    stream.flush().await.context("flush preflight")?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .context("read preflight status")?;
    anyhow::ensure!(status_line.contains("200"), "preflight HTTP status was {status_line:?}");

    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.context("read preflight header")?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().to_owned())
        {
            content_length = Some(value.parse::<usize>().context("parse Content-Length")?);
        }
    }

    let response_body = if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await.context("read preflight body")?;
        String::from_utf8(buf).context("preflight body utf-8")?
    } else {
        let mut buf = String::new();
        reader
            .read_to_string(&mut buf)
            .await
            .context("read preflight eof body")?;
        buf
    };

    let json: serde_json::Value =
        serde_json::from_str(&response_body).with_context(|| format!("parse preflight JSON: {response_body}"))?;
    let outputs = json.as_array().context("preflight response is not an array")?;
    // Re-provisioning the same JTI emits an info alert, then still acks.
    let mut acked = 0usize;
    for output in outputs {
        match output["kind"].as_str() {
            Some("ack") => acked += 1,
            Some("alert") if output["alert_status"] == "info" => {}
            _ => anyhow::bail!("preflight operation was not ack: {output}"),
        }
    }
    anyhow::ensure!(acked > 0, "preflight returned no ack: {json}");
    Ok(json)
}

async fn provision_credentials(
    http_port: u16,
    token: &str,
    target_username: &str,
    time_to_live: u32,
    krb_kdc: Option<&str>,
) -> anyhow::Result<()> {
    let mut operations = vec![serde_json::json!({
        "id": next_id(),
        "kind": "provision-credentials",
        "token": token,
        "proxy_credential": {
            "kind": "username-password",
            "username": PROXY_USER,
            "password": "proxy-secret"
        },
        "target_credential": {
            "kind": "username-password",
            "username": target_username,
            "password": "target-secret"
        },
        "time_to_live": time_to_live
    })];

    if let Some(krb_kdc) = krb_kdc {
        operations.push(serde_json::json!({
            "id": next_id(),
            "kind": "provision-connection-options",
            "token": token,
            "connection_options": { "krb_kdc": krb_kdc },
            "time_to_live": time_to_live
        }));
    }

    post_preflight(http_port, serde_json::Value::Array(operations)).await?;
    Ok(())
}

async fn connect_rdp_client(gateway_tcp: u16, association_jwt: &str) -> anyhow::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", gateway_tcp))
        .await
        .context("connect to gateway TCP")?;
    stream
        .write_all(&encode_pcb(association_jwt)?)
        .await
        .context("write preconnection blob")?;
    stream
        .write_all(&encode_connection_request(CLIENT_COOKIE)?)
        .await
        .context("write connection request")?;
    stream.flush().await.context("flush RDP client")?;
    Ok(stream)
}

fn cookie_line(username: &str) -> String {
    format!("Cookie: mstshash={username}")
}

fn payloads_contain(payloads: &[Vec<u8>], needle: &str) -> bool {
    payloads
        .iter()
        .any(|payload| String::from_utf8_lossy(payload).contains(needle))
}

#[tokio::test]
async fn first_rdp_connection_injects_ntlm() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start(false).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 300, None).await?;

    let _client = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_contains(INJECT_LOG).await?;
    assert!(
        logs.contains("kerberos=false"),
        "expected NTLM injection; logs:\n{logs}"
    );
    assert!(
        !logs.contains(FORWARD_LOG),
        "injection must not fall back to ordinary forward; logs:\n{logs}"
    );

    let payloads = target.wait_payloads(1).await?;
    assert!(
        payloads_contain(&payloads, &cookie_line(TARGET_USER)),
        "target should see injected cookie; payloads={payloads:?}"
    );
    assert!(
        !payloads_contain(&payloads, &cookie_line(CLIENT_COOKIE)),
        "target must not see the client cookie; payloads={payloads:?}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn reconnect_same_jwt_still_injects() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start(false).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 300, None).await?;

    let first = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    gateway.logs.wait_count(INJECT_LOG, 1).await?;
    target.wait_payloads(1).await?;
    drop(first);

    let _second = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_count(INJECT_LOG, 2).await?;
    assert!(
        !logs.contains(FORWARD_LOG),
        "reconnect must keep injecting, not ordinary-forward; logs:\n{logs}"
    );

    let payloads = target.wait_payloads(2).await?;
    assert_eq!(payloads.len(), 2, "both connections should reach the fake RDP target");
    assert!(
        payloads
            .iter()
            .all(|payload| String::from_utf8_lossy(payload).contains(&cookie_line(TARGET_USER))),
        "both reconnects should inject the target cookie; payloads={payloads:?}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn required_missing_fails_closed() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start(false).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 1, None).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let _client = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_contains(MISSING_LOG).await?;
    assert!(
        !logs.contains(INJECT_LOG),
        "expired mapping must not inject; logs:\n{logs}"
    );
    assert!(
        !logs.contains(FORWARD_LOG),
        "expired mapping must fail closed, never silent ordinary forward; logs:\n{logs}"
    );

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(target.accepted(), 0, "fail-closed routing must not connect upstream");

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn unprovisioned_rdp_uses_ordinary_forward() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start(false).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;

    let _client = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_contains(FORWARD_LOG).await?;
    assert!(
        !logs.contains(INJECT_LOG),
        "absent mapping should ordinary-forward; logs:\n{logs}"
    );

    let payloads = target.wait_payloads(1).await?;
    assert!(
        payloads_contain(&payloads, &cookie_line(CLIENT_COOKIE)),
        "ordinary forward should keep the client cookie; payloads={payloads:?}"
    );
    assert!(
        !payloads_contain(&payloads, &cookie_line(TARGET_USER)),
        "ordinary forward must not invent an injection cookie; payloads={payloads:?}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_reconnect_reuses_generation_until_reprovision() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start(true).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some("tcp://127.0.0.1:88"),
    )
    .await?;

    // Keep overlapping reconnect sockets so the same-generation KDC lease stays live.
    let _first = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_count(INJECT_LOG, 1).await?;
    assert!(
        logs.contains("kerberos=true"),
        "expected Kerberos injection; logs:\n{logs}"
    );
    gateway.logs.wait_count(PUBLISHED_KDC_LOG, 1).await?;

    let _second = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_count(INJECT_LOG, 2).await?;
    assert_eq!(
        logs.matches("kerberos=true").count(),
        2,
        "same generation reconnect should still inject Kerberos; logs:\n{logs}"
    );
    gateway.logs.wait_count(REGISTERED_KDC_LOG, 2).await?;
    assert_eq!(
        logs.matches(PUBLISHED_KDC_LOG).count(),
        1,
        "same provisioning generation must reuse the interned synthetic KDC; logs:\n{logs}"
    );

    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some("tcp://127.0.0.1:88"),
    )
    .await?;

    let _third = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_count(INJECT_LOG, 3).await?;
    assert_eq!(
        logs.matches("kerberos=true").count(),
        3,
        "newer provisioning generation should replace and still inject; logs:\n{logs}"
    );
    let logs = gateway.logs.wait_count(PUBLISHED_KDC_LOG, 2).await?;
    assert_eq!(
        logs.matches(REGISTERED_KDC_LOG).count(),
        3,
        "each connection should register a synthetic KDC lease; logs:\n{logs}"
    );
    assert!(
        !logs.contains(FORWARD_LOG),
        "Kerberos injection must not ordinary-forward; logs:\n{logs}"
    );

    let payloads = target.wait_payloads(3).await?;
    assert!(
        payloads
            .iter()
            .all(|payload| String::from_utf8_lossy(payload).contains(&cookie_line(KERBEROS_TARGET_USER))),
        "each generation should inject the Kerberos target username; payloads={payloads:?}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}
