//! Loopback Kerberos KDCs: a real one backed by the `kdc` crate (the same crate the Gateway
//! embeds for its synthetic KDC) and a refusing one for fail-closed coverage.

use anyhow::Context as _;
use ironrdp_connector::sspi;
use picky_krb::data_types::PrincipalName;
use picky_krb::messages::{AsRep, AsReq, KdcProxyMessage, KrbError, TgsRep, TgsReq};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::event::{Event, ObservedKdcReply, ObservedKdcReq, emit, report_error};
use crate::fixture::{KRBTGT_KEY, REALM, SERVICE_HOST, TARGET_PASSWORD, TERMSRV_KEY};

pub(crate) async fn run_kdc() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await.context("bind mock KDC")?;
    let port = listener.local_addr().context("mock KDC local_addr")?.port();
    let config = kdc_config();
    emit(&Event::Listening { port });

    loop {
        let (stream, _) = listener.accept().await.context("accept on mock KDC")?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_kdc_exchange(stream, &config).await {
                report_error("mock KDC exchange failed", &error);
            }
        });
    }
}

/// Accepts TCP and closes it at once, so ticket fetching fails.
pub(crate) async fn run_refusing_kdc() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await.context("bind refusing KDC")?;
    let port = listener.local_addr().context("refusing KDC local_addr")?.port();
    emit(&Event::Listening { port });

    loop {
        let (_stream, _) = listener.accept().await.context("accept on refusing KDC")?;
        emit(&Event::Accepted);
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

async fn serve_kdc_exchange(mut stream: TcpStream, config: &kdc::config::KerberosServer) -> anyhow::Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("read KDC length")?;
    let len = usize::try_from(u32::from_be_bytes(len_buf)).context("KDC length")?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.context("read KDC body")?;

    emit(&Event::KdcRequest {
        request: observe_kdc_req(&body),
    });

    let mut raw = Vec::with_capacity(4 + len);
    raw.extend_from_slice(&len_buf);
    raw.extend_from_slice(&body);

    let request = KdcProxyMessage::from_raw_kerb_message(&raw).context("wrap KDC TCP payload")?;
    let reply = kdc::handle_kdc_proxy_message(request, config, SERVICE_HOST).context("handle KDC message")?;
    // Reported before the reply goes out, so the count is visible before the requester moves on.
    emit(&Event::KdcExchangeServed);
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

pub(crate) async fn send_kdc_tcp(request: &sspi::generator::NetworkRequest) -> anyhow::Result<Vec<u8>> {
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
