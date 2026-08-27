//! Loopback Kerberos KDCs: a real one backed by the `kdc` crate (the same crate the Gateway
//! embeds for its synthetic KDC) and a refusing one for fail-closed coverage.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use ironrdp_connector::sspi;
use picky_krb::data_types::PrincipalName;
use picky_krb::messages::{AsRep, AsReq, KdcProxyMessage, KrbError, TgsRep, TgsReq};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::{KRBTGT_KEY, REALM, SERVICE_HOST, TARGET_PASSWORD, TERMSRV_KEY};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedKdcReq {
    As { cname: String, realm: String },
    Tgs { sname: Vec<String>, realm: String },
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedKdcReply {
    AsRep,
    TgsRep,
    KrbError,
    Other,
}

pub struct MockKdc {
    port: u16,
    exchanges: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<ObservedKdcReq>>>,
}

impl MockKdc {
    pub async fn start() -> anyhow::Result<Self> {
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

    pub fn url(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }

    pub fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<ObservedKdcReq> {
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

pub(crate) fn observe_kdc_req(body: &[u8]) -> ObservedKdcReq {
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

pub(crate) fn observe_kdc_reply(body: &[u8]) -> ObservedKdcReply {
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

pub async fn send_kdc_tcp(request: &sspi::generator::NetworkRequest) -> anyhow::Result<Vec<u8>> {
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

/// Accepts TCP and never answers, so ticket fetching hangs until the caller gives up.
pub struct RefusingKdc {
    port: u16,
    accepted: Arc<AtomicUsize>,
}

impl RefusingKdc {
    pub async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind refusing KDC")?;
        let port = listener.local_addr()?.port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_task = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let Ok((_stream, _)) = listener.accept().await else {
                    break;
                };
                accepted_task.fetch_add(1, Ordering::SeqCst);
            }
        });
        Ok(Self { port, accepted })
    }

    pub fn url(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
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
