//! Kerberos credential injection against a mock KDC and IronRDP CredSSP server.
//!
//! Proves the target-leg path: Gateway fetches tickets from a TCP KDC (`kdc` crate from
//! sspi-rs) and completes CredSSP with a fake RDP acceptor. The Gateway-facing client uses
//! NTLM so the test does not depend on the in-process synthetic KDC.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_pdu::nego::{
    ConnectionConfirm, ConnectionRequest, NegoRequestData, RequestFlags, ResponseFlags, SecurityProtocol,
};
use ironrdp_pdu::x224::X224;
use ironrdp_tokio::{FramedWrite as _, TokioFramed};
use picky_krb::data_types::PrincipalName;
use picky_krb::messages::{AsRep, AsReq, KdcProxyMessage, KrbError, TgsRep, TgsReq};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use x509_cert::der::Decode as _;

use super::cred_injection::{
    FORWARD_LOG, GatewayProc, INJECT_LOG, KERBEROS_TARGET_USER, MISSING_LOG, PROXY_KERBEROS_USER, PROXY_PASSWORD,
    PROXY_USER, TARGET_PASSWORD, TARGET_USER, encode_pcb, next_id, provision_credentials, provision_mapping,
    unsigned_jws,
};

const REALM: &str = "EXAMPLE.INVALID";
// sspi-rs downgrades Negotiate to NTLM when the SPN host is an IP address.
const SERVICE_HOST: &str = "localhost";
const KRBTGT_KEY: [u8; 32] = [0x11; 32];
const TERMSRV_KEY: [u8; 32] = [0x22; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
enum ObservedKdcReq {
    As { cname: String, realm: String },
    Tgs { sname: Vec<String>, realm: String },
    Other,
}

struct MockKdc {
    port: u16,
    exchanges: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<ObservedKdcReq>>>,
}

impl MockKdc {
    async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind mock KDC")?;
        let port = listener.local_addr().context("mock KDC local_addr")?.port();
        let exchanges = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let exchanges_task = Arc::clone(&exchanges);
        let requests_task = Arc::clone(&requests);
        let config = kdc_config();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let config = config.clone();
                let exchanges = Arc::clone(&exchanges_task);
                let requests = Arc::clone(&requests_task);
                tokio::spawn(async move {
                    match serve_kdc_exchange(stream, &config, &requests).await {
                        Ok(()) => {
                            exchanges.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(error) => eprintln!("mock KDC exchange failed: {error:#}"),
                    }
                });
            }
        });

        Ok(Self {
            port,
            exchanges,
            requests,
        })
    }

    fn url(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }

    fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<ObservedKdcReq> {
        self.requests.lock().expect("kdc request mutex").clone()
    }
}

fn kdc_config() -> kdc::config::KerberosServer {
    let username = format!("administrator@{REALM}");
    kdc::config::KerberosServer {
        realm: REALM.to_owned(),
        users: vec![kdc::config::DomainUser {
            username,
            password: TARGET_PASSWORD.to_owned(),
            salt: format!("{}administrator", REALM.to_ascii_uppercase()),
        }],
        max_time_skew: 300,
        krbtgt_key: KRBTGT_KEY.to_vec(),
        ticket_decryption_key: Some(TERMSRV_KEY.to_vec()),
        service_user: None,
    }
}

async fn serve_kdc_exchange(
    mut stream: TcpStream,
    config: &kdc::config::KerberosServer,
    requests: &Mutex<Vec<ObservedKdcReq>>,
) -> anyhow::Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("read KDC length")?;
    let len = usize::try_from(u32::from_be_bytes(len_buf)).context("KDC length")?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.context("read KDC body")?;

    requests.lock().expect("kdc request mutex").push(observe_kdc_req(&body));

    let mut raw = Vec::with_capacity(4 + len);
    raw.extend_from_slice(&len_buf);
    raw.extend_from_slice(&body);

    let request = KdcProxyMessage::from_raw_kerb_message(&raw).context("wrap KDC TCP payload")?;
    let reply = kdc::handle_kdc_proxy_message(request, config, SERVICE_HOST).context("handle KDC message")?;
    stream
        .write_all(&reply.kerb_message.0.0)
        .await
        .context("write KDC reply")?;
    Ok(())
}

fn principal_strings(name: &PrincipalName) -> Vec<String> {
    name.name_string.0.0.iter().map(|part| part.0.to_string()).collect()
}

fn observe_kdc_req(body: &[u8]) -> ObservedKdcReq {
    if let Ok(as_req) = picky_asn1_der::from_bytes::<AsReq>(body) {
        let req = &as_req.0.req_body.0;
        let cname = req
            .cname
            .0
            .as_ref()
            .map(|name| principal_strings(&name.0).join("/"))
            .unwrap_or_default();
        return ObservedKdcReq::As {
            cname,
            realm: req.realm.0.to_string(),
        };
    }
    if let Ok(tgs_req) = picky_asn1_der::from_bytes::<TgsReq>(body) {
        let req = &tgs_req.0.req_body.0;
        let sname = req
            .sname
            .0
            .as_ref()
            .map(|name| principal_strings(&name.0))
            .unwrap_or_default();
        return ObservedKdcReq::Tgs {
            sname,
            realm: req.realm.0.to_string(),
        };
    }
    ObservedKdcReq::Other
}

fn observe_kdc_reply(body: &[u8]) -> ObservedKdcReply {
    let krb = body.get(4..).unwrap_or(body);
    if picky_asn1_der::from_bytes::<AsRep>(krb).is_ok() {
        ObservedKdcReply::AsRep
    } else if picky_asn1_der::from_bytes::<TgsRep>(krb).is_ok() {
        ObservedKdcReply::TgsRep
    } else if picky_asn1_der::from_bytes::<KrbError>(krb).is_ok() {
        ObservedKdcReply::KrbError
    } else {
        ObservedKdcReply::Other
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ObservedKdcReply {
    AsRep,
    TgsRep,
    KrbError,
    Other,
}

#[derive(Clone)]
enum MockRdpMode {
    Kerberos { kdc_url: String },
    Ntlm,
}

struct MockRdp {
    port: u16,
    credssp_ok: Arc<AtomicBool>,
    finished_account: Arc<Mutex<Option<String>>>,
    cookies: Arc<Mutex<Vec<String>>>,
}

impl MockRdp {
    async fn start_kerberos(kdc_url: String) -> anyhow::Result<Self> {
        Self::start(MockRdpMode::Kerberos { kdc_url }).await
    }

    async fn start_ntlm() -> anyhow::Result<Self> {
        Self::start(MockRdpMode::Ntlm).await
    }

    async fn start(mode: MockRdpMode) -> anyhow::Result<Self> {
        install_crypto_provider();
        // Dual-stack so Windows `localhost` (IPv6 first) still hits the fake server.
        let listener = match TcpListener::bind("[::]:0").await {
            Ok(listener) => listener,
            Err(_) => TcpListener::bind("127.0.0.1:0").await.context("bind mock RDP")?,
        };
        let port = listener.local_addr().context("mock RDP local_addr")?.port();
        let credssp_ok = Arc::new(AtomicBool::new(false));
        let finished_account = Arc::new(Mutex::new(None));
        let cookies = Arc::new(Mutex::new(Vec::new()));
        let credssp_ok_task = Arc::clone(&credssp_ok);
        let finished_account_task = Arc::clone(&finished_account);
        let cookies_task = Arc::clone(&cookies);
        let acceptor = tls_acceptor()?;
        let public_key = server_public_key()?;

        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let public_key = public_key.clone();
                let credssp_ok = Arc::clone(&credssp_ok_task);
                let finished_account = Arc::clone(&finished_account_task);
                let cookies = Arc::clone(&cookies_task);
                let mode = mode.clone();
                tokio::spawn(async move {
                    let result = match &mode {
                        MockRdpMode::Kerberos { kdc_url } => {
                            accept_kerberos_rdp(
                                stream,
                                peer,
                                acceptor,
                                public_key,
                                kdc_url,
                                &cookies,
                                &finished_account,
                            )
                            .await
                        }
                        MockRdpMode::Ntlm => {
                            accept_ntlm_rdp(stream, peer, acceptor, public_key, &cookies, &finished_account).await
                        }
                    };
                    match result {
                        Ok(()) => credssp_ok.store(true, Ordering::SeqCst),
                        Err(error) => eprintln!("mock RDP CredSSP failed: {error:#}"),
                    }
                });
            }
        });

        Ok(Self {
            port,
            credssp_ok,
            finished_account,
            cookies,
        })
    }

    fn credssp_ok(&self) -> bool {
        self.credssp_ok.load(Ordering::SeqCst)
    }

    fn finished_account(&self) -> Option<String> {
        self.finished_account.lock().expect("finished account mutex").clone()
    }

    fn cookies(&self) -> Vec<String> {
        self.cookies.lock().expect("cookie mutex").clone()
    }

    async fn wait_credssp(&self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.credssp_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for Kerberos CredSSP on mock RDP");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn accept_kerberos_rdp(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    public_key: Vec<u8>,
    kdc_url: &str,
    cookies: &Mutex<Vec<String>>,
    finished_account: &Mutex<Option<String>>,
) -> anyhow::Result<()> {
    let mut framed = TokioFramed::new(stream);
    let (_, request) = framed.read_pdu().await.context("read X.224 CR")?;
    let cr: X224<ConnectionRequest> = ironrdp_core::decode(&request).context("decode X.224 CR")?;
    record_cookie(&cr, cookies);

    let confirm = X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::HYBRID,
    });
    framed
        .write_all(&ironrdp_core::encode_vec(&confirm).context("encode X.224 CC")?)
        .await
        .context("write X.224 CC")?;

    let tcp = framed.into_inner_no_leftover();
    let tls = acceptor.accept(tcp).await.context("TLS accept")?;
    let mut framed = TokioFramed::new(tls);

    let identity = sspi::AuthIdentity {
        username: sspi::Username::parse(KERBEROS_TARGET_USER).context("parse target username")?,
        password: TARGET_PASSWORD.to_owned().into(),
    };
    let kerberos_config = sspi::KerberosServerConfig {
        kerberos_config: sspi::KerberosConfig {
            kdc_url: Some(kdc_url.parse().context("parse mock KDC URL")?),
            client_computer_name: peer.to_string(),
        },
        server_properties: sspi::kerberos::ServerProperties::new(
            &["TERMSRV", SERVICE_HOST],
            Some(sspi::CredentialsBuffers::AuthIdentity(
                sspi::AuthIdentityBuffers::from_utf8(identity.username.account_name(), REALM, TARGET_PASSWORD),
            )),
            Duration::from_secs(300),
            Some(sspi::Secret::new(TERMSRV_KEY.to_vec())),
        )
        .context("Kerberos server properties")?,
    };

    let mut server = sspi::credssp::CredSspServer::new(
        public_key,
        IdentityProxy(identity),
        sspi::credssp::ServerMode::Negotiate(sspi::NegotiateConfig::new(
            Box::new(kerberos_config),
            Some("kerberos,!ntlm".to_owned()),
            peer.to_string(),
        )),
    )
    .context("init Kerberos-only CredSSP server")?;

    let hint = TsRequestHint;
    let mut buf = ironrdp_pdu::WriteBuf::new();
    for _ in 0..6 {
        let pdu = framed.read_by_hint(&hint).await.context("read CredSSP TSRequest")?;
        let ts_request = sspi::credssp::TsRequest::from_buffer(&pdu).context("decode CredSSP")?;
        let result = {
            let mut generator = server.process(ts_request);
            resolve_sspi_server(&mut generator)
                .await
                .map_err(|error| anyhow::anyhow!("mock RDP CredSSP: {error:?}"))?
        };
        match result {
            sspi::credssp::ServerState::ReplyNeeded(outbound) => {
                buf.clear();
                let length = usize::from(outbound.buffer_len());
                outbound
                    .encode_ts_request(buf.unfilled_to(length))
                    .context("encode server TSRequest")?;
                buf.advance(length);
                framed.write_all(&buf[..length]).await.context("write CredSSP")?;
            }
            sspi::credssp::ServerState::Finished(identity) => {
                *finished_account.lock().expect("finished account mutex") =
                    Some(identity.username.account_name().to_owned());
                return Ok(());
            }
        }
    }
    anyhow::bail!("mock RDP CredSSP exceeded 6 round trips")
}

async fn accept_ntlm_rdp(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    public_key: Vec<u8>,
    cookies: &Mutex<Vec<String>>,
    finished_account: &Mutex<Option<String>>,
) -> anyhow::Result<()> {
    let mut framed = TokioFramed::new(stream);
    let (_, request) = framed.read_pdu().await.context("read X.224 CR")?;
    let cr: X224<ConnectionRequest> = ironrdp_core::decode(&request).context("decode X.224 CR")?;
    record_cookie(&cr, cookies);

    let confirm = X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::HYBRID,
    });
    framed
        .write_all(&ironrdp_core::encode_vec(&confirm).context("encode X.224 CC")?)
        .await
        .context("write X.224 CC")?;

    let tcp = framed.into_inner_no_leftover();
    let tls = acceptor.accept(tcp).await.context("TLS accept")?;
    let mut framed = TokioFramed::new(tls);

    let identity = sspi::AuthIdentity {
        username: sspi::Username::parse(TARGET_USER).context("parse NTLM target username")?,
        password: TARGET_PASSWORD.to_owned().into(),
    };
    let mut server = sspi::credssp::CredSspServer::new(
        public_key,
        IdentityProxy(identity),
        sspi::credssp::ServerMode::Ntlm(sspi::ntlm::NtlmConfig {
            client_computer_name: Some(peer.to_string()),
        }),
    )
    .context("init NTLM CredSSP server")?;

    let hint = TsRequestHint;
    let mut buf = ironrdp_pdu::WriteBuf::new();
    for _ in 0..6 {
        let pdu = framed.read_by_hint(&hint).await.context("read CredSSP TSRequest")?;
        let ts_request = sspi::credssp::TsRequest::from_buffer(&pdu).context("decode CredSSP")?;
        let result = {
            let mut generator = server.process(ts_request);
            resolve_sspi_server(&mut generator)
                .await
                .map_err(|error| anyhow::anyhow!("mock RDP NTLM CredSSP: {error:?}"))?
        };
        match result {
            sspi::credssp::ServerState::ReplyNeeded(outbound) => {
                buf.clear();
                let length = usize::from(outbound.buffer_len());
                outbound
                    .encode_ts_request(buf.unfilled_to(length))
                    .context("encode server TSRequest")?;
                buf.advance(length);
                framed.write_all(&buf[..length]).await.context("write CredSSP")?;
            }
            sspi::credssp::ServerState::Finished(identity) => {
                *finished_account.lock().expect("finished account mutex") =
                    Some(identity.username.account_name().to_owned());
                return Ok(());
            }
        }
    }
    anyhow::bail!("mock RDP NTLM CredSSP exceeded 6 round trips")
}

fn record_cookie(cr: &X224<ConnectionRequest>, cookies: &Mutex<Vec<String>>) {
    if let Some(NegoRequestData::Cookie(cookie)) = &cr.0.nego_data {
        cookies.lock().expect("cookie mutex").push(cookie.0.clone());
    }
}

async fn resolve_sspi_server(
    generator: &mut sspi::generator::Generator<
        '_,
        sspi::generator::NetworkRequest,
        sspi::Result<Vec<u8>>,
        Result<sspi::credssp::ServerState, sspi::credssp::ServerError>,
    >,
) -> Result<sspi::credssp::ServerState, sspi::credssp::ServerError> {
    let mut state = generator.start();
    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let reply = send_kdc_tcp(&request)
                    .await
                    .map_err(|error| sspi::credssp::ServerError {
                        ts_request: None,
                        error: sspi::Error::new(sspi::ErrorKind::NoAuthenticatingAuthority, error),
                    })?;
                state = generator.resume(Ok(reply));
            }
            GeneratorState::Completed(result) => break result,
        }
    }
}

async fn send_kdc_tcp(request: &sspi::generator::NetworkRequest) -> anyhow::Result<Vec<u8>> {
    let host = request.url.host_str().context("KDC host")?;
    let port = request.url.port().unwrap_or(88);
    let mut stream = TcpStream::connect((host, port)).await.context("connect mock KDC")?;
    stream.write_all(&request.data).await.context("write KDC request")?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("read KDC length")?;
    let len = usize::try_from(u32::from_be_bytes(len_buf)).context("KDC length")?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.context("read KDC body")?;
    let mut reply = Vec::with_capacity(4 + len);
    reply.extend_from_slice(&len_buf);
    reply.extend_from_slice(&body);
    Ok(reply)
}

struct IdentityProxy(sspi::AuthIdentity);

impl sspi::credssp::CredentialsProxy for IdentityProxy {
    type AuthenticationData = sspi::AuthIdentity;

    fn auth_data_by_user(&mut self, username: &sspi::Username) -> std::io::Result<Self::AuthenticationData> {
        if username.account_name() != self.0.username.account_name() {
            return Err(std::io::Error::other("invalid username"));
        }
        let mut data = self.0.clone();
        data.username = username.clone();
        Ok(data)
    }

    fn auth_data(&mut self) -> Result<Vec<Self::AuthenticationData>, std::io::Error> {
        Ok(vec![self.0.clone()])
    }
}

async fn connect_ntlm_client(
    gateway_tcp: u16,
    association_jwt: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut stream = TcpStream::connect(("127.0.0.1", gateway_tcp))
        .await
        .context("connect gateway TCP")?;
    stream
        .write_all(&encode_pcb(association_jwt)?)
        .await
        .context("write PCB")?;
    stream.write_all(&encode_hybrid_cr()?).await.context("write X.224 CR")?;
    stream.flush().await.context("flush CR")?;

    let mut framed = TokioFramed::new(stream);
    let (_, confirm) = framed.read_pdu().await.context("read X.224 CC")?;
    let confirm: X224<ConnectionConfirm> = ironrdp_core::decode(&confirm).context("decode X.224 CC")?;
    anyhow::ensure!(
        matches!(confirm.0, ConnectionConfirm::Response { protocol, .. } if protocol.contains(SecurityProtocol::HYBRID)),
        "gateway did not confirm CredSSP: {confirm:?}"
    );

    let tcp = framed.into_inner_no_leftover();
    let connector = dangerous_tls_connector();
    let server_name = ServerName::try_from("localhost").map_err(|error| anyhow::anyhow!("{error}"))?;
    connector.connect(server_name, tcp).await.context("TLS to gateway")
}

async fn complete_ntlm_credssp(tls: tokio_rustls::client::TlsStream<TcpStream>) -> anyhow::Result<()> {
    complete_client_credssp(tls, PROXY_USER, None, false, None).await
}

async fn complete_raw_ntlm_credssp(tls: tokio_rustls::client::TlsStream<TcpStream>) -> anyhow::Result<()> {
    complete_client_credssp(tls, PROXY_USER, None, true, None).await
}

async fn complete_client_credssp(
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    username: &str,
    kdc_proxy_url: Option<&str>,
    raw_ntlm: bool,
    proxy_replies: Option<&Mutex<Vec<ObservedKdcReply>>>,
) -> anyhow::Result<()> {
    use sspi::credssp::{ClientMode, ClientState, CredSspClient, CredSspMode, TsRequest};
    use sspi::ntlm::NtlmConfig;

    let public_key = peer_public_key(&tls)?;
    let mut framed = TokioFramed::new(tls);
    let identity = sspi::AuthIdentity {
        username: sspi::Username::parse(username).context("parse client username")?,
        password: PROXY_PASSWORD.to_owned().into(),
    };
    let client_mode = if let Some(kdc_url) = kdc_proxy_url {
        ClientMode::Negotiate(sspi::NegotiateConfig::new(
            Box::new(sspi::KerberosConfig {
                kdc_url: Some(kdc_url.parse().context("parse KDC proxy URL")?),
                client_computer_name: "cred-injection-e2e".to_owned(),
            }),
            Some("kerberos,!ntlm".to_owned()),
            "cred-injection-e2e".to_owned(),
        ))
    } else if raw_ntlm {
        // Gateway NTLM injection uses ServerMode::Ntlm, which rejects SPNEGO.
        ClientMode::Ntlm(NtlmConfig {
            client_computer_name: Some("cred-injection-e2e".to_owned()),
        })
    } else {
        ClientMode::Negotiate(sspi::NegotiateConfig::new(
            Box::new(NtlmConfig {
                client_computer_name: Some("cred-injection-e2e".to_owned()),
            }),
            Some("ntlm,!kerberos,!pku2u".to_owned()),
            "cred-injection-e2e".to_owned(),
        ))
    };
    let mut client = CredSspClient::new(
        public_key,
        identity.into(),
        CredSspMode::WithCredentials,
        client_mode,
        format!("TERMSRV/{SERVICE_HOST}"),
    )
    .context("init CredSSP client")?;

    let mut ts_request = TsRequest::default();
    let mut buf = ironrdp_pdu::WriteBuf::new();
    let hint = TsRequestHint;

    for _ in 0..8 {
        let client_state = {
            let mut generator = client.process(std::mem::take(&mut ts_request));
            resolve_sspi_client(&mut generator, proxy_replies).await?
        };
        let (outbound, finished) = match client_state {
            ClientState::ReplyNeeded(request) => (request, false),
            ClientState::FinalMessage(request) => (request, true),
        };
        buf.clear();
        let length = usize::from(outbound.buffer_len());
        outbound
            .encode_ts_request(buf.unfilled_to(length))
            .context("encode client TSRequest")?;
        buf.advance(length);
        framed.write_all(&buf[..length]).await.context("write client CredSSP")?;
        if finished {
            return Ok(());
        }
        let pdu = framed.read_by_hint(&hint).await.context("read server CredSSP")?;
        ts_request = TsRequest::from_buffer(&pdu).context("decode server TSRequest")?;
    }

    anyhow::bail!("CredSSP exceeded 8 round trips")
}

async fn resolve_sspi_client(
    generator: &mut sspi::generator::Generator<
        '_,
        sspi::generator::NetworkRequest,
        sspi::Result<Vec<u8>>,
        sspi::Result<sspi::credssp::ClientState>,
    >,
    proxy_replies: Option<&Mutex<Vec<ObservedKdcReply>>>,
) -> anyhow::Result<sspi::credssp::ClientState> {
    let mut state = generator.start();
    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let reply = match request.url.scheme() {
                    "tcp" | "udp" => send_kdc_tcp(&request).await?,
                    "http" | "https" => send_kdc_http(&request, proxy_replies).await?,
                    other => anyhow::bail!("unsupported KDC scheme {other}: {}", request.url),
                };
                state = generator.resume(Ok(reply));
            }
            GeneratorState::Completed(result) => {
                break result.map_err(|error| anyhow::anyhow!("client CredSSP: {error}"));
            }
        }
    }
}

async fn send_kdc_http(
    request: &sspi::generator::NetworkRequest,
    proxy_replies: Option<&Mutex<Vec<ObservedKdcReply>>>,
) -> anyhow::Result<Vec<u8>> {
    let host = request.url.host_str().context("KDC proxy host")?;
    let port = request.url.port_or_known_default().unwrap_or(80);
    let path = if request.url.query().is_some() {
        format!("{}?{}", request.url.path(), request.url.query().unwrap_or_default())
    } else {
        request.url.path().to_owned()
    };
    let mut stream = TcpStream::connect((host, port)).await.context("connect KDC proxy")?;
    let header = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        request.data.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .context("write KDC proxy headers")?;
    stream.write_all(&request.data).await.context("write KDC proxy body")?;
    stream.flush().await.context("flush KDC proxy")?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .context("read KDC proxy status")?;
    anyhow::ensure!(status_line.contains("200"), "KDC proxy HTTP status was {status_line:?}");

    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.context("read KDC proxy header")?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().to_owned())
        {
            content_length = Some(value.parse::<usize>().context("parse KDC proxy Content-Length")?);
        }
    }

    let buf = if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut buf)
            .await
            .context("read KDC proxy body")?;
        buf
    } else {
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .context("read KDC proxy eof body")?;
        buf
    };
    if let Ok(message) = KdcProxyMessage::from_raw(&buf)
        && let Some(log) = proxy_replies
    {
        log.lock()
            .expect("proxy reply mutex")
            .push(observe_kdc_reply(&message.kerb_message.0.0));
    }
    Ok(buf)
}

fn kdc_inject_token(association_jti: &str) -> anyhow::Result<String> {
    unsigned_jws(
        serde_json::json!({"alg":"RS256","typ":"JWT","cty":"KDC"}),
        serde_json::json!({
            "exp": 9_999_999_999i64,
            "jet_cred_id": association_jti,
            "jti": next_id(),
        }),
    )
}

fn kdc_proxy_url(http_port: u16, association_jti: &str) -> anyhow::Result<String> {
    let token = kdc_inject_token(association_jti)?;
    Ok(format!("http://127.0.0.1:{http_port}/jet/KdcProxy/{token}"))
}

#[derive(Debug)]
struct TsRequestHint;

impl ironrdp_pdu::PduHint for TsRequestHint {
    fn find_size(&self, bytes: &[u8]) -> ironrdp_core::DecodeResult<Option<(bool, usize)>> {
        match sspi::credssp::TsRequest::read_length(bytes) {
            Ok(length) => Ok(Some((true, length))),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(ironrdp_core::other_err!("TsRequestHint", source: error)),
        }
    }
}

fn association_token_for_host(jti: &str, jet_aid: &str, dest_port: u16, jet_reuse: u32) -> anyhow::Result<String> {
    unsigned_jws(
        serde_json::json!({"alg":"RS256","typ":"JWT","cty":"ASSOCIATION"}),
        serde_json::json!({
            "dst_hst": format!("{SERVICE_HOST}:{dest_port}"),
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

fn encode_hybrid_cr() -> anyhow::Result<Vec<u8>> {
    let pdu = X224(ConnectionRequest {
        nego_data: Some(NegoRequestData::cookie(super::cred_injection::CLIENT_COOKIE.to_owned())),
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::HYBRID | SecurityProtocol::SSL,
    });
    ironrdp_core::encode_vec(&pdu).context("encode hybrid CR")
}

fn peer_public_key(tls: &tokio_rustls::client::TlsStream<TcpStream>) -> anyhow::Result<Vec<u8>> {
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .context("gateway TLS certificate missing")?;
    extract_public_key(cert)
}

fn server_public_key() -> anyhow::Result<Vec<u8>> {
    let cert = CertificateDer::from_pem_slice(CERT_PEM.as_bytes()).context("parse mock RDP cert")?;
    extract_public_key(&cert)
}

fn extract_public_key(cert: &CertificateDer<'_>) -> anyhow::Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(cert.as_ref()).context("parse X509")?;
    let public_key = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .context("unaligned subject public key")?
        .to_owned();
    Ok(public_key)
}

fn tls_acceptor() -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let cert = CertificateDer::from_pem_slice(CERT_PEM.as_bytes()).context("parse cert PEM")?;
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM.as_bytes()).context("parse key PEM")?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("TLS server config")?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

fn dangerous_tls_connector() -> tokio_rustls::TlsConnector {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn install_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
struct NoCertificateVerification;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::ED25519,
        ]
    }
}

fn assert_target_kdc_as_and_tgs(kdc: &MockKdc) -> anyhow::Result<()> {
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

#[tokio::test]
async fn kerberos_injection_completes_credssp_against_mock_kdc() -> anyhow::Result<()> {
    install_crypto_provider();
    let kdc = MockKdc::start().await?;
    let rdp = MockRdp::start_kerberos(kdc.url()).await?;
    let mut gateway = GatewayProc::start(true).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some(&kdc.url()),
    )
    .await?;

    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    complete_ntlm_credssp(tls)
        .await
        .context("Gateway-facing NTLM CredSSP")?;
    rdp.wait_credssp()
        .await
        .with_context(|| format!("gateway logs:\n{}", gateway.logs.snapshot()))?;
    anyhow::ensure!(
        kdc.exchanges() >= 2,
        "expected AS-REQ and TGS-REQ against the mock KDC; exchanges={}; gateway logs:\n{}",
        kdc.exchanges(),
        gateway.logs.snapshot()
    );
    assert_target_kdc_as_and_tgs(&kdc)?;
    anyhow::ensure!(
        rdp.finished_account().as_deref() == Some("administrator"),
        "RDP CredSSP Finished account must be administrator; got={:?}; cookies={:?}",
        rdp.finished_account(),
        rdp.cookies()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == KERBEROS_TARGET_USER),
        "RDP X.224 cookie must be {KERBEROS_TARGET_USER}; cookies={:?}",
        rdp.cookies()
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_client_and_target_legs_complete_credssp() -> anyhow::Result<()> {
    install_crypto_provider();
    let kdc = MockKdc::start().await?;
    let rdp = MockRdp::start_kerberos(kdc.url()).await?;
    let mut gateway = GatewayProc::start(true).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_mapping(
        gateway.config.http_port(),
        &token,
        PROXY_KERBEROS_USER,
        KERBEROS_TARGET_USER,
        TARGET_PASSWORD,
        300,
        Some(&kdc.url()),
    )
    .await?;

    let kdc_proxy = kdc_proxy_url(gateway.config.http_port(), &jti)?;
    let proxy_replies = Mutex::new(Vec::new());
    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    complete_client_credssp(tls, PROXY_KERBEROS_USER, Some(&kdc_proxy), false, Some(&proxy_replies))
        .await
        .with_context(|| {
            format!(
                "client-leg Kerberos CredSSP; gateway logs:\n{}",
                gateway.logs.snapshot()
            )
        })?;
    rdp.wait_credssp().await.with_context(|| {
        format!(
            "target-leg Kerberos CredSSP; gateway logs:\n{}",
            gateway.logs.snapshot()
        )
    })?;
    anyhow::ensure!(
        kdc.exchanges() >= 2,
        "target-leg must talk to the mock KDC; exchanges={}; logs:\n{}",
        kdc.exchanges(),
        gateway.logs.snapshot()
    );
    assert_target_kdc_as_and_tgs(&kdc)?;
    let replies = proxy_replies.lock().expect("proxy reply mutex").clone();
    anyhow::ensure!(
        replies.contains(&ObservedKdcReply::AsRep) && replies.contains(&ObservedKdcReply::TgsRep),
        "/jet/KdcProxy must return AS-REP and TGS-REP (PREAUTH KRB-ERROR is allowed first); replies={replies:?}"
    );
    anyhow::ensure!(
        rdp.finished_account().as_deref() == Some("administrator"),
        "RDP CredSSP Finished account must be administrator; got={:?}",
        rdp.finished_account()
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_wrong_target_password_fails_closed() -> anyhow::Result<()> {
    install_crypto_provider();
    let kdc = MockKdc::start().await?;
    let rdp = MockRdp::start_kerberos(kdc.url()).await?;
    let mut gateway = GatewayProc::start(true).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_mapping(
        gateway.config.http_port(),
        &token,
        PROXY_USER,
        KERBEROS_TARGET_USER,
        "wrong-target-password",
        300,
        Some(&kdc.url()),
    )
    .await?;

    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    let _ = complete_ntlm_credssp(tls).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    anyhow::ensure!(
        !rdp.credssp_ok() && rdp.finished_account().is_none(),
        "wrong target password must not complete Kerberos CredSSP; account={:?}; logs:\n{}",
        rdp.finished_account(),
        gateway.logs.snapshot()
    );
    let logs = gateway.logs.snapshot();
    anyhow::ensure!(
        !logs.contains(FORWARD_LOG),
        "wrong password must not ordinary-forward; logs:\n{logs}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_kdc_down_fails_closed() -> anyhow::Result<()> {
    install_crypto_provider();
    let rdp = MockRdp::start_kerberos("tcp://127.0.0.1:1".to_owned()).await?;
    let mut gateway = GatewayProc::start(true).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some("tcp://127.0.0.1:1"),
    )
    .await?;

    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    let _ = complete_ntlm_credssp(tls).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    anyhow::ensure!(
        !rdp.credssp_ok() && rdp.finished_account().is_none(),
        "unreachable KDC must not complete CredSSP; account={:?}; logs:\n{}",
        rdp.finished_account(),
        gateway.logs.snapshot()
    );
    let logs = gateway.logs.snapshot();
    anyhow::ensure!(
        !logs.contains(FORWARD_LOG),
        "KDC down must not ordinary-forward; logs:\n{logs}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_missing_krb_kdc_fails_closed() -> anyhow::Result<()> {
    let rdp = FakeClosedTarget::start().await?;
    let mut gateway = GatewayProc::start(true).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, KERBEROS_TARGET_USER, 300, None).await?;

    let mut stream = TcpStream::connect(("127.0.0.1", gateway.config.tcp_port()))
        .await
        .context("connect gateway TCP")?;
    stream.write_all(&encode_pcb(&token)?).await.context("write PCB")?;
    stream.write_all(&encode_hybrid_cr()?).await.context("write CR")?;
    stream.flush().await.context("flush CR")?;
    let logs = gateway.logs.wait_contains(MISSING_LOG).await?;
    anyhow::ensure!(
        !logs.contains(FORWARD_LOG),
        "missing krb_kdc must fail closed; logs:\n{logs}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn ntlm_injection_completes_credssp_both_legs() -> anyhow::Result<()> {
    install_crypto_provider();
    let rdp = MockRdp::start_ntlm().await?;
    let mut gateway = GatewayProc::start(false).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 300, None).await?;

    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    complete_raw_ntlm_credssp(tls)
        .await
        .with_context(|| format!("client-leg NTLM CredSSP; logs:\n{}", gateway.logs.snapshot()))?;
    rdp.wait_credssp()
        .await
        .with_context(|| format!("target-leg NTLM CredSSP; logs:\n{}", gateway.logs.snapshot()))?;
    let logs = gateway.logs.wait_contains(INJECT_LOG).await?;
    anyhow::ensure!(
        logs.contains("kerberos=false"),
        "expected NTLM injection; logs:\n{logs}"
    );
    anyhow::ensure!(
        rdp.finished_account().as_deref() == Some(TARGET_USER),
        "RDP NTLM CredSSP Finished account must be {TARGET_USER}; got={:?}",
        rdp.finished_account()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == TARGET_USER),
        "RDP X.224 cookie must be {TARGET_USER}; cookies={:?}",
        rdp.cookies()
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

struct FakeClosedTarget {
    port: u16,
}

impl FakeClosedTarget {
    async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind closed target")?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            loop {
                let Ok((_stream, _)) = listener.accept().await else {
                    break;
                };
            }
        });
        Ok(Self { port })
    }
}

const CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUPRJa8i280unV3/kW6TE2fSUw8PwwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI1MTEyNTA5NDAzMFoYDzIxMjUx
MTAxMDk0MDMwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDHpBlyRgUx/V9cQGw/eqDFc6odxB2hvnbudi67LvEj
cNIWOU79R1e/NswME4oecqT9W05n4UyxkABfm2qjODO0nDf47W0DsgbEA87qE715
RWg8AtC529CZAazqTV3gqYyRMsCuVKzPVxgWa8rhPc7E6In1uDRak0lWKQPQSBbc
34nxMOVIusZNlkAEar8/aYPr/YWvdEqkobEvXp+g9WsuMaU913ecacWDjyWDkf80
pPPtf+uet7WMysKMhzGQtpbgilT8XCo8uTsgUbK+TMWvkF9bcxAQDnJsrZRL7Jfh
ofsFfQbTIvbvpn+4J4kmHN36BTohlNL8TX1jrU3cPA7dAgMBAAGjUzBRMB0GA1Ud
DgQWBBTT+m6dyc/c3mXF3JAsZr9OqUwgWTAfBgNVHSMEGDAWgBTT+m6dyc/c3mXF
3JAsZr9OqUwgWTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBB
i/yonZY3ztaeGElzD8xkI+rJ+daJ5WzdfKnzudJllg/Ht8m7wO5SdQnMt2T44gbH
05uekc1zXnXb7fJKqs3R6DacctG0nQ3acuI+IMtTaBbbAcf3PJJlo0Pap0ypVC0R
IUiUhJGFNi4cCBOvJqsly0d3T5xqOXU1Q5j3mIwRBY68+m9btwwuZWvASRADtCyZ
RpisBzS4a6jSeHXa4iG/VhskbiZkcnfHNTw7yNJJdv125y2zQkWWF9wlLbYwWr40
x9Ba6YbssOz6epATKhvt80yclO34AzUyimssvViIUpgFEyaPhZZTw46Q/6X3ixK4
/v4eYM0cCHN0h+rynSor
-----END CERTIFICATE-----"#;

const KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHpBlyRgUx/V9c
QGw/eqDFc6odxB2hvnbudi67LvEjcNIWOU79R1e/NswME4oecqT9W05n4UyxkABf
m2qjODO0nDf47W0DsgbEA87qE715RWg8AtC529CZAazqTV3gqYyRMsCuVKzPVxgW
a8rhPc7E6In1uDRak0lWKQPQSBbc34nxMOVIusZNlkAEar8/aYPr/YWvdEqkobEv
Xp+g9WsuMaU913ecacWDjyWDkf80pPPtf+uet7WMysKMhzGQtpbgilT8XCo8uTsg
UbK+TMWvkF9bcxAQDnJsrZRL7JfhofsFfQbTIvbvpn+4J4kmHN36BTohlNL8TX1j
rU3cPA7dAgMBAAECggEAKh7KK5zwTaq6atlAvWfe8anEk4EkC1MG/qq6k02FHMgZ
2wx+SNu7fKFQDaA1vNTNUJLqCOq05qWOHp3IsuURq6JmAMP/Aw+Vc9el2ScPC74E
Dt09MmlZKl77H3fxPYwoFx5RHrbIuvoSH/DgHgOPU2YIbWpOyWlXyLDgmBoNkM3N
fXYLXJONpStPHeQLhh7LcHO3CZgn6kycJyByEO2NtcchS5zITiJuwL+qR5/QIlvD
Yo7jdCjelJat38MZ9dE1us8xlIjQtsYF/acZZtcpYho+7ZpDCNcb+xF8KStKei+B
MMpWISsa+Zh9g7lPYTnG/i1dSMMT100XCEw8o4rBoQKBgQDnptz8acp7DB2wJH4L
c0xuw8IlrSl3BGUEj8H+RyFlpH3+//i6/fE9MrtF8b4FSYUp5AG4NVFGcRbwJVGW
jeL13YwIKMdXjmx8fDIylCgBB1tzBS9T/0ws3HS8avxhKvjgoXIZm6D3XDcBslrH
c9/LojT8YGI1wx7jWI2qKj8yeQKBgQDcn+kQ1QjzgIz6bAVWY3t1jr5uHHyaS+5G
ihY/mx4Mn3DURgPXZHz/HrN9rZkax0zuq9wuIlqgZ2KI37iCF49M4aZxC788LyDo
Hp0Cak3wt3g0Tj6J7SJiQe8h/6VBS4R5dRD2vhEc3xPAOf7WIFdlLYBOOvE/LmOt
N6ChkfgGhQKBgQDSiDqLRPJ7BjXtIh1T9sPeXxeR+mCXBG1yydx7ZtYZdHf2S1kZ
STX4cqT1GpGiaIEX41sUuZBWPu2j76bI98bvwRxFRhp1nsFGGfHdOf1pgfBBBtNO
udXXZ7zIiUs6XD24mcIDOAgBB9QOPLR4VP1uKsuRG1/mkKD/6jlGEANDsQKBgQDC
AoEygxQnBVFz2c/rwvnLS+Zb8AMGsGTtdPrRnjeThBX1JUi1fbGJq1bN2v27Fa2q
aEjr7NvjGGcG1C1tgQhL5Fa4LEtTwmHenSUW/aJiXwR+gpvuMDC/VRnTvPp2a9En
+XEcedGUoPq+XIGjjLctyxB8Osrw83tF1JgV3MXN/QKBgQC83B54rYDd4QmVH5nL
WLw834fgr+Z1hA6UqJIaahlD/bDwzbbJEv0pHCBxe01ywQFivqWBdVbuoy9YSeLS
KKEklzh+L0SorrYoBA5F63qx0zy05bba0ASplgDUEUNZn7oIFi7x5pVsNNaNxZpR
bQGM8UrNQvWQ+tutRmp7PM6VuQ==
-----END PRIVATE KEY-----"#;
