//! Client-side CredSSP against the Gateway: X.224 negotiation, TLS, then an sspi
//! `CredSspClient` whose KDC traffic is resolved over TCP or through `/jet/KdcProxy`.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context as _;
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_pdu::nego::{ConnectionConfirm, SecurityProtocol};
use ironrdp_pdu::x224::X224;
use ironrdp_tokio::{FramedWrite as _, TokioFramed};
use picky_krb::messages::KdcProxyMessage;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

use super::mock_kdc::{ObservedKdcReply, ObservedKdcReq, observe_kdc_reply, observe_kdc_req, send_kdc_tcp};
use super::rdp::{encode_hybrid_cr, encode_pcb};
use super::tls::{dangerous_tls_connector, peer_public_key};
use super::{PROXY_PASSWORD, PROXY_USER, SERVICE_HOST};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

pub async fn connect_ntlm_client(
    gateway_tcp: u16,
    association_jwt: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_ntlm_client_inner(gateway_tcp, association_jwt),
    )
    .await
    .context("timed out connecting NTLM client to Gateway")?
}

async fn connect_ntlm_client_inner(
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

pub async fn complete_ntlm_credssp(tls: tokio_rustls::client::TlsStream<TcpStream>) -> anyhow::Result<()> {
    complete_client_credssp(tls, PROXY_USER, None, false, None, None).await
}

pub async fn complete_raw_ntlm_credssp(tls: tokio_rustls::client::TlsStream<TcpStream>) -> anyhow::Result<()> {
    complete_client_credssp(tls, PROXY_USER, None, true, None, None).await
}

pub async fn complete_client_credssp(
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    username: &str,
    kdc_proxy_url: Option<&str>,
    raw_ntlm: bool,
    proxy_replies: Option<&Mutex<Vec<ObservedKdcReply>>>,
    proxy_requests: Option<&Mutex<Vec<ObservedKdcReq>>>,
) -> anyhow::Result<()> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        complete_client_credssp_inner(tls, username, kdc_proxy_url, raw_ntlm, proxy_replies, proxy_requests),
    )
    .await
    .context("timed out completing client CredSSP")?
}

async fn complete_client_credssp_inner(
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    username: &str,
    kdc_proxy_url: Option<&str>,
    raw_ntlm: bool,
    proxy_replies: Option<&Mutex<Vec<ObservedKdcReply>>>,
    proxy_requests: Option<&Mutex<Vec<ObservedKdcReq>>>,
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
            resolve_sspi_client(&mut generator, proxy_replies, proxy_requests).await?
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
    proxy_requests: Option<&Mutex<Vec<ObservedKdcReq>>>,
) -> anyhow::Result<sspi::credssp::ClientState> {
    let mut state = generator.start();
    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let reply = match request.url.scheme() {
                    "tcp" | "udp" => send_kdc_tcp(&request).await?,
                    "http" | "https" => send_kdc_http(&request, proxy_replies, proxy_requests).await?,
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
    proxy_requests: Option<&Mutex<Vec<ObservedKdcReq>>>,
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
    if let Ok(message) = KdcProxyMessage::from_raw(&request.data)
        && let Some(log) = proxy_requests
    {
        let kerb = message.kerb_message.0.0.get(4..).unwrap_or(&message.kerb_message.0.0);
        log.lock().expect("proxy request mutex").push(observe_kdc_req(kerb));
    }

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .context("read KDC proxy status")?;
    anyhow::ensure!(
        status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200"),
        "KDC proxy HTTP status was {status_line:?}"
    );

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

#[derive(Debug)]
pub(crate) struct TsRequestHint;

impl ironrdp_pdu::PduHint for TsRequestHint {
    fn find_size(&self, bytes: &[u8]) -> ironrdp_core::DecodeResult<Option<(bool, usize)>> {
        match sspi::credssp::TsRequest::read_length(bytes) {
            Ok(length) => Ok(Some((true, length))),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(ironrdp_core::other_err!("TsRequestHint", source: error)),
        }
    }
}
