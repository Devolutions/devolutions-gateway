//! RDP client roles against the Gateway TCP listener: the preconnection blob carrying the
//! association token, the X.224 Connection Request, then optionally TLS and an sspi
//! `CredSspClient` whose KDC traffic goes over TCP or through `/jet/KdcProxy`.

use std::time::Duration;

use anyhow::Context as _;
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_pdu::nego::{
    ConnectionConfirm, ConnectionRequest as X224ConnectionRequest, NegoRequestData, RequestFlags, SecurityProtocol,
};
use ironrdp_pdu::x224::X224;
use ironrdp_tokio::{FramedWrite as _, TokioFramed};
use picky_krb::messages::KdcProxyMessage;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

use crate::event::{Event, emit};
use crate::fixture::{CLIENT_COOKIE, PROXY_KERBEROS_USER, PROXY_PASSWORD, PROXY_USER, SERVICE_HOST};
use crate::kdc::{observe_kdc_reply, observe_kdc_req, send_kdc_tcp};
use crate::tls::{dangerous_tls_connector, peer_public_key};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) enum ConnectionRequest {
    /// Offers SSL, HYBRID and HYBRID_EX, like a regular client.
    Full,
    /// Offers SSL and HYBRID only.
    Hybrid,
}

pub(crate) enum Auth {
    /// SPNEGO restricted to NTLM, as the proxy user.
    Ntlm,
    /// Bare NTLM: Gateway NTLM injection uses `ServerMode::Ntlm`, which rejects SPNEGO.
    RawNtlm,
    /// SPNEGO restricted to Kerberos, as the Kerberos proxy user, with tickets from `kdc_proxy_url`.
    Kerberos { kdc_proxy_url: String },
}

/// Sends the opening bytes of an RDP connection, then keeps the socket open until killed.
pub(crate) async fn send_connection_request(
    gateway_port: u16,
    association_token: &str,
    request: ConnectionRequest,
) -> anyhow::Result<()> {
    let request = match request {
        ConnectionRequest::Full => {
            encode_connection_request(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX | SecurityProtocol::SSL)?
        }
        ConnectionRequest::Hybrid => encode_connection_request(SecurityProtocol::HYBRID | SecurityProtocol::SSL)?,
    };
    let mut stream = TcpStream::connect(("127.0.0.1", gateway_port))
        .await
        .context("connect to gateway TCP")?;
    stream
        .write_all(&encode_pcb(association_token)?)
        .await
        .context("write preconnection blob")?;
    stream.write_all(&request).await.context("write connection request")?;
    stream.flush().await.context("flush RDP client")?;
    emit(&Event::ConnectionRequestSent);

    std::future::pending::<()>().await;
    Ok(())
}

/// Connects to Gateway and completes CredSSP as the proxy user; exits non-zero when CredSSP fails.
pub(crate) async fn run_credssp(gateway_port: u16, association_token: &str, auth: Auth) -> anyhow::Result<()> {
    let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connect_tls(gateway_port, association_token))
        .await
        .context("timed out connecting to Gateway")??;
    emit(&Event::TlsConnected);
    tokio::time::timeout(HANDSHAKE_TIMEOUT, complete_credssp(tls, auth))
        .await
        .context("timed out completing client CredSSP")?
}

fn encode_pcb(association_token: &str) -> anyhow::Result<Vec<u8>> {
    let pcb = ironrdp_pdu::pcb::PreconnectionBlob {
        version: ironrdp_pdu::pcb::PcbVersion::V2,
        id: 0,
        v2_payload: Some(association_token.to_owned()),
    };
    ironrdp_core::encode_vec(&pcb).context("encode preconnection blob")
}

fn encode_connection_request(protocol: SecurityProtocol) -> anyhow::Result<Vec<u8>> {
    let pdu = X224(X224ConnectionRequest {
        nego_data: Some(NegoRequestData::cookie(CLIENT_COOKIE.to_owned())),
        flags: RequestFlags::empty(),
        protocol,
    });
    ironrdp_core::encode_vec(&pdu).context("encode X.224 connection request")
}

async fn connect_tls(
    gateway_port: u16,
    association_token: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut stream = TcpStream::connect(("127.0.0.1", gateway_port))
        .await
        .context("connect gateway TCP")?;
    stream
        .write_all(&encode_pcb(association_token)?)
        .await
        .context("write PCB")?;
    stream
        .write_all(&encode_connection_request(
            SecurityProtocol::HYBRID | SecurityProtocol::SSL,
        )?)
        .await
        .context("write X.224 CR")?;
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

async fn complete_credssp(tls: tokio_rustls::client::TlsStream<TcpStream>, auth: Auth) -> anyhow::Result<()> {
    use sspi::credssp::{ClientMode, ClientState, CredSspClient, CredSspMode, TsRequest};
    use sspi::ntlm::NtlmConfig;

    let public_key = peer_public_key(&tls)?;
    let mut framed = TokioFramed::new(tls);
    let (username, client_mode) = match auth {
        Auth::Ntlm => (
            PROXY_USER,
            ClientMode::Negotiate(sspi::NegotiateConfig::new(
                Box::new(NtlmConfig {
                    client_computer_name: Some("cred-injection-e2e".to_owned()),
                }),
                Some("ntlm,!kerberos,!pku2u".to_owned()),
                "cred-injection-e2e".to_owned(),
            )),
        ),
        Auth::RawNtlm => (
            PROXY_USER,
            ClientMode::Ntlm(NtlmConfig {
                client_computer_name: Some("cred-injection-e2e".to_owned()),
            }),
        ),
        Auth::Kerberos { kdc_proxy_url } => (
            PROXY_KERBEROS_USER,
            ClientMode::Negotiate(sspi::NegotiateConfig::new(
                Box::new(sspi::KerberosConfig {
                    kdc_url: Some(kdc_proxy_url.parse().context("parse KDC proxy URL")?),
                    client_computer_name: "cred-injection-e2e".to_owned(),
                }),
                Some("kerberos,!ntlm".to_owned()),
                "cred-injection-e2e".to_owned(),
            )),
        ),
    };
    let identity = sspi::AuthIdentity {
        username: sspi::Username::parse(username).context("parse client username")?,
        password: PROXY_PASSWORD.to_owned().into(),
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
            resolve_sspi_client(&mut generator).await?
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
) -> anyhow::Result<sspi::credssp::ClientState> {
    let mut state = generator.start();
    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let reply = match request.url.scheme() {
                    "tcp" | "udp" => send_kdc_tcp(&request).await?,
                    "http" | "https" => send_kdc_http(&request).await?,
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

async fn send_kdc_http(request: &sspi::generator::NetworkRequest) -> anyhow::Result<Vec<u8>> {
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
    if let Ok(message) = KdcProxyMessage::from_raw(&request.data) {
        let kerb = message.kerb_message.0.0.get(4..).unwrap_or(&message.kerb_message.0.0);
        emit(&Event::KdcProxyRequest {
            request: observe_kdc_req(kerb),
        });
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
    if let Ok(message) = KdcProxyMessage::from_raw(&buf) {
        emit(&Event::KdcProxyReply {
            reply: observe_kdc_reply(&message.kerb_message.0.0),
        });
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
