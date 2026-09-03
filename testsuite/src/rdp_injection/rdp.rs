//! Minimal RDP protocol pieces: the client's opening bytes and loopback targets.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use ironrdp_pdu::nego::{ConnectionRequest, NegoRequestData, RequestFlags, SecurityProtocol};
use ironrdp_pdu::x224::X224;
use ironrdp_tokio::TokioFramed;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};

use super::CLIENT_COOKIE;

pub fn encode_pcb(association_token: &str) -> anyhow::Result<Vec<u8>> {
    let pcb = ironrdp_pdu::pcb::PreconnectionBlob {
        version: ironrdp_pdu::pcb::PcbVersion::V2,
        id: 0,
        v2_payload: Some(association_token.to_owned()),
    };
    ironrdp_core::encode_vec(&pcb).context("encode preconnection blob")
}

pub fn encode_connection_request(cookie: &str) -> anyhow::Result<Vec<u8>> {
    let pdu = X224(ConnectionRequest {
        nego_data: Some(NegoRequestData::cookie(cookie.to_owned())),
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX | SecurityProtocol::SSL,
    });
    ironrdp_core::encode_vec(&pdu).context("encode X.224 connection request")
}

pub fn encode_hybrid_cr() -> anyhow::Result<Vec<u8>> {
    let pdu = X224(ConnectionRequest {
        nego_data: Some(NegoRequestData::cookie(CLIENT_COOKIE.to_owned())),
        flags: RequestFlags::empty(),
        protocol: SecurityProtocol::HYBRID | SecurityProtocol::SSL,
    });
    ironrdp_core::encode_vec(&pdu).context("encode hybrid CR")
}

pub fn decode_x224_cookie(payload: &[u8]) -> Option<String> {
    let cr: X224<ConnectionRequest> = ironrdp_core::decode(payload).ok()?;
    match cr.0.nego_data {
        Some(NegoRequestData::Cookie(cookie)) => Some(cookie.0),
        _ => None,
    }
}

pub(crate) fn record_cookie(cr: &X224<ConnectionRequest>, cookies: &Mutex<Vec<String>>) {
    if let Some(NegoRequestData::Cookie(cookie)) = &cr.0.nego_data {
        cookies.lock().expect("cookie mutex").push(cookie.0.clone());
    }
}

pub async fn connect_rdp_client(gateway_tcp: u16, association_token: &str) -> anyhow::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", gateway_tcp))
        .await
        .context("connect to gateway TCP")?;
    stream
        .write_all(&encode_pcb(association_token)?)
        .await
        .context("write preconnection blob")?;
    stream
        .write_all(&encode_connection_request(CLIENT_COOKIE)?)
        .await
        .context("write connection request")?;
    stream.flush().await.context("flush RDP client")?;
    Ok(stream)
}

/// Stands in for the destination RDP server and records the X.224 Connection Request cookie
/// the proxy forwards.
pub struct FakeRdpTarget {
    pub port: u16,
    accepted: Arc<AtomicUsize>,
    cookies: Arc<Mutex<Vec<String>>>,
}

impl FakeRdpTarget {
    pub async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind fake RDP target")?;
        let port = listener.local_addr().context("fake RDP local_addr")?.port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let cookies = Arc::new(Mutex::new(Vec::new()));
        let accepted_task = Arc::clone(&accepted);
        let cookies_task = Arc::clone(&cookies);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                accepted_task.fetch_add(1, Ordering::SeqCst);
                let cookies = Arc::clone(&cookies_task);
                tokio::spawn(async move {
                    let mut framed = TokioFramed::new(stream);
                    // CredSSP cert generation can delay the rewritten X.224 CR.
                    if let Ok(Ok((_, request))) = tokio::time::timeout(Duration::from_secs(30), framed.read_pdu()).await
                        && let Some(cookie) = decode_x224_cookie(&request)
                    {
                        cookies.lock().expect("cookie mutex").push(cookie);
                    }
                    // Keep the accepted socket open so the proxy can finish writing the CR.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });

        Ok(Self {
            port,
            accepted,
            cookies,
        })
    }

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    pub async fn wait_cookies(&self, count: usize) -> anyhow::Result<Vec<String>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            {
                let cookies = self.cookies.lock().expect("cookie mutex");
                if cookies.len() >= count {
                    return Ok(cookies.clone());
                }
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
    accepted: Arc<AtomicUsize>,
}

impl FakeClosedTarget {
    pub async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.context("bind closed target")?;
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

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}
