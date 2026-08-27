//! Fake RDP server that completes CredSSP as the target: X.224 accept, TLS, then an
//! sspi `CredSspServer` in Kerberos or NTLM mode.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::x224::X224;
use ironrdp_tokio::{FramedWrite as _, TokioFramed};
use tokio::net::{TcpListener, TcpStream};

use super::credssp::TsRequestHint;
use super::mock_kdc::send_kdc_tcp;
use super::rdp::record_cookie;
use super::tls::{install_crypto_provider, server_public_key, tls_acceptor};
use super::{KERBEROS_TARGET_USER, REALM, SERVICE_HOST, TARGET_PASSWORD, TARGET_USER, TERMSRV_KEY};

#[derive(Clone)]
enum MockRdpMode {
    Kerberos { kdc_url: Option<String> },
    Ntlm,
}

pub struct MockRdp {
    pub port: u16,
    credssp_ok: Arc<AtomicBool>,
    finished_account: Arc<Mutex<Option<String>>>,
    cookies: Arc<Mutex<Vec<String>>>,
}

impl MockRdp {
    pub async fn start_kerberos(kdc_url: String) -> anyhow::Result<Self> {
        Self::start(MockRdpMode::Kerberos { kdc_url: Some(kdc_url) }).await
    }

    pub async fn start_ntlm() -> anyhow::Result<Self> {
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
                                kdc_url.as_deref(),
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

    pub fn credssp_ok(&self) -> bool {
        self.credssp_ok.load(Ordering::SeqCst)
    }

    pub fn finished_account(&self) -> Option<String> {
        self.finished_account.lock().expect("finished account mutex").clone()
    }

    pub fn cookies(&self) -> Vec<String> {
        self.cookies.lock().expect("cookie mutex").clone()
    }

    pub async fn wait_credssp(&self) -> anyhow::Result<()> {
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
    kdc_url: Option<&str>,
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
            kdc_url: kdc_url
                .map(|url| url.parse())
                .transpose()
                .context("parse mock KDC URL")?,
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
