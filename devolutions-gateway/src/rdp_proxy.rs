use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::config::Conf;
use crate::credential::{AppCredentialMapping, ArcCredentialEntry};
use crate::proxy::Proxy;
use crate::session::{DisconnectInterest, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;

use anyhow::Context as _;
use ironrdp_pdu::{mcs, nego, x224};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use typed_builder::TypedBuilder;

#[derive(TypedBuilder)]
pub struct RdpProxy<C, S> {
    conf: Arc<Conf>,
    session_info: SessionInfo,
    client_stream: C,
    client_addr: SocketAddr,
    server_stream: S,
    server_addr: SocketAddr,
    credential_entry: ArcCredentialEntry,
    client_stream_leftover_bytes: bytes::BytesMut,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    server_dns_name: String,
    disconnect_interest: Option<DisconnectInterest>,
}

impl<A, B> RdpProxy<A, B>
where
    A: AsyncWrite + AsyncRead + Unpin + Send + Sync,
    B: AsyncWrite + AsyncRead + Unpin + Send + Sync,
{
    pub async fn run(self) -> anyhow::Result<()> {
        handle(self).await
    }
}

#[instrument("rdp_proxy", skip_all, fields(session_id = proxy.session_info.id.to_string(), target = proxy.server_addr.to_string()))]
async fn handle<C, S>(proxy: RdpProxy<C, S>) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    let RdpProxy {
        conf,
        session_info,
        client_stream,
        client_addr,
        server_stream,
        server_addr,
        credential_entry,
        client_stream_leftover_bytes,
        sessions,
        subscriber_tx,
        server_dns_name,
        disconnect_interest,
    } = proxy;

    let tls_conf = conf
        .tls
        .as_ref()
        .context("TLS configuration required for credential injection feature")?;

    let credential_mapping = credential_entry.mapping.as_ref().context("no credential mapping")?;

    // -- Retrieve the Gateway TLS public key that must be used for client-proxy CredSSP later on -- //

    let gateway_public_key_handle = tokio::spawn(get_cached_gateway_public_key(
        conf.hostname.clone(),
        tls_conf.acceptor.clone(),
    ));

    // -- Dual handshake with the client and the server until the TLS security upgrade -- //

    let mut client_framed = ironrdp_tokio::TokioFramed::new_with_leftover(client_stream, client_stream_leftover_bytes);
    let mut server_framed = ironrdp_tokio::TokioFramed::new(server_stream);

    let handshake_result =
        dual_handshake_until_tls_upgrade(&mut client_framed, &mut server_framed, credential_mapping).await?;

    let client_stream = client_framed.into_inner_no_leftover();
    let server_stream = server_framed.into_inner_no_leftover();

    // -- Perform the TLS upgrading for both the client and the server, effectively acting as a man-in-the-middle -- //

    let client_tls_upgrade_fut = tls_conf.acceptor.accept(client_stream);
    let server_tls_upgrade_fut = crate::tls::connect(server_dns_name.clone(), server_stream);

    let (client_stream, server_stream) = tokio::join!(client_tls_upgrade_fut, server_tls_upgrade_fut);

    let client_stream = client_stream.context("TLS upgrade with client failed")?;
    let server_stream = server_stream.context("TLS upgrade with server failed")?;

    let server_public_key =
        extract_tls_server_public_key(&server_stream).context("extract target server TLS public key")?;
    let gateway_public_key = gateway_public_key_handle.await??;

    // -- Perform the CredSSP authentication with the client (acting as a server) and the server (acting as a client) -- //

    let mut client_framed = ironrdp_tokio::TokioFramed::new(client_stream);
    let mut server_framed = ironrdp_tokio::TokioFramed::new(server_stream);

    let client_credssp_fut = perform_credssp_with_client(
        &mut client_framed,
        client_addr.ip(),
        gateway_public_key,
        handshake_result.client_security_protocol,
        &credential_mapping.proxy,
    );

    let server_credssp_fut = perform_credssp_with_server(
        &mut server_framed,
        server_dns_name,
        server_public_key,
        handshake_result.server_security_protocol,
        &credential_mapping.target,
    );

    let (client_credssp_res, server_credssp_res) = tokio::join!(client_credssp_fut, server_credssp_fut);
    client_credssp_res.context("CredSSP with client")?;
    server_credssp_res.context("CredSSP with server")?;

    // -- Intercept the Connect Confirm PDU, to override the server_security_protocol field -- //

    intercept_connect_confirm(
        &mut client_framed,
        &mut server_framed,
        handshake_result.server_security_protocol,
    )
    .await?;

    let (mut client_stream, client_leftover) = client_framed.into_inner();
    let (mut server_stream, server_leftover) = server_framed.into_inner();

    // -- At this point, proceed to the usual two-way forwarding -- //

    info!("RDP-TLS forwarding (credential injection)");

    client_stream
        .write_all(&server_leftover)
        .await
        .context("write server leftover to client")?;

    server_stream
        .write_all(&client_leftover)
        .await
        .context("write client leftover to server")?;

    Proxy::builder()
        .conf(conf)
        .session_info(session_info)
        .address_a(client_addr)
        .transport_a(client_stream)
        .address_b(server_addr)
        .transport_b(server_stream)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .disconnect_interest(disconnect_interest)
        .build()
        .select_dissector_and_forward()
        .await
        .context("RDP-TLS traffic proxying failed")?;

    Ok(())
}

#[derive(Debug)]
struct HandshakeResult {
    client_security_protocol: nego::SecurityProtocol,
    server_security_protocol: nego::SecurityProtocol,
}

#[instrument(level = "debug", ret, skip_all)]
async fn intercept_connect_confirm<C, S>(
    client_framed: &mut ironrdp_tokio::TokioFramed<C>,
    server_framed: &mut ironrdp_tokio::TokioFramed<S>,
    server_security_protocol: nego::SecurityProtocol,
) -> anyhow::Result<()>
where
    C: AsyncWrite + AsyncRead + Unpin + Send + Sync,
    S: AsyncWrite + AsyncRead + Unpin + Send + Sync,
{
    let (_, received_frame) = client_framed
        .read_pdu()
        .await
        .context("read MCS Connect Initial from client")?;
    let received_connect_initial: x224::X224<x224::X224Data<'_>> =
        ironrdp_core::decode(&received_frame).context("decode PDU from client")?;
    let mut received_connect_initial: mcs::ConnectInitial =
        ironrdp_core::decode(&received_connect_initial.0.data).context("decode Connect Initial PDU")?;
    trace!(message = ?received_connect_initial, "Received Connect Initial PDU from client");

    received_connect_initial
        .conference_create_request
        .gcc_blocks
        .core
        .optional_data
        .server_selected_protocol = Some(server_security_protocol);
    trace!(message = ?received_connect_initial, "Send Connection Request PDU to server");
    let x224_msg_buf = ironrdp_core::encode_vec(&received_connect_initial)?;
    let pdu = x224::X224Data {
        data: std::borrow::Cow::Owned(x224_msg_buf),
    };
    send_pdu(server_framed, &x224::X224(pdu))
        .await
        .context("send connection request to server")?;

    Ok(())
}

#[instrument(name = "dual_handshake", level = "debug", ret, skip_all)]
async fn dual_handshake_until_tls_upgrade<C, S>(
    client_framed: &mut ironrdp_tokio::TokioFramed<C>,
    server_framed: &mut ironrdp_tokio::TokioFramed<S>,
    mapping: &AppCredentialMapping,
) -> anyhow::Result<HandshakeResult>
where
    C: AsyncWrite + AsyncRead + Unpin + Send + Sync,
    S: AsyncWrite + AsyncRead + Unpin + Send + Sync,
{
    let (_, received_frame) = client_framed.read_pdu().await.context("read PDU from client")?;
    let received_connection_request: x224::X224<nego::ConnectionRequest> =
        ironrdp_core::decode(&received_frame).context("decode PDU from client")?;
    trace!(message = ?received_connection_request, "Received Connection Request PDU from client");

    // Choose the security protocol to use with the client.
    let client_security_protocol = if received_connection_request
        .0
        .protocol
        .contains(nego::SecurityProtocol::HYBRID_EX)
    {
        nego::SecurityProtocol::HYBRID_EX
    } else if received_connection_request
        .0
        .protocol
        .contains(nego::SecurityProtocol::HYBRID)
    {
        nego::SecurityProtocol::HYBRID
    } else {
        anyhow::bail!(
            "client does not support CredSSP (received {})",
            received_connection_request.0.protocol
        )
    };

    let connection_request_to_send = nego::ConnectionRequest {
        nego_data: match &mapping.target {
            crate::credential::AppCredential::UsernamePassword { username, .. } => {
                Some(nego::NegoRequestData::cookie(username.to_owned()))
            }
        },
        flags: received_connection_request.0.flags,
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
        // The spec is stating that `PROTOCOL_SSL` "SHOULD" also be set when using `PROTOCOL_HYBRID`.
        // > PROTOCOL_HYBRID (0x00000002)
        // > Credential Security Support Provider protocol (CredSSP) (section 5.4.5.2).
        // > If this flag is set, then the PROTOCOL_SSL (0x00000001) flag SHOULD also be set
        // > because Transport Layer Security (TLS) is a subset of CredSSP.
        // Crucially, it’s not strictly required (not "MUST"). However, in practice, we cannot set PROTOCOL_HYBRID without PROTOCOL_SSL.
        // Otherwise, the `mstsc.exe` will fail right after the CredSSP phase with the "An authentication error has occurred (0x609)" error.
        // A similar case: https://serverfault.com/a/720161.
        protocol: nego::SecurityProtocol::SSL | nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX,
    };
    trace!(?connection_request_to_send, "Send Connection Request PDU to server");
    send_pdu(server_framed, &x224::X224(connection_request_to_send))
        .await
        .context("send connection request to server")?;

    let (_, received_frame) = server_framed.read_pdu().await.context("read PDU from server")?;
    let received_connection_confirm: x224::X224<nego::ConnectionConfirm> =
        ironrdp_core::decode(&received_frame).context("decode PDU from server")?;
    trace!(message = ?received_connection_confirm, "Received Connection Confirm PDU from server");

    let (connection_confirm_to_send, handshake_result) = match &received_connection_confirm.0 {
        nego::ConnectionConfirm::Response {
            flags,
            protocol: server_security_protocol,
        } => {
            debug!(?server_security_protocol, ?flags, "Server confirmed connection");

            let result = if !server_security_protocol
                .intersects(nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX)
            {
                Err(anyhow::anyhow!(
                    "server selected security protocol {server_security_protocol}, which is not supported for credential injection"
                ))
            } else {
                Ok(HandshakeResult {
                    client_security_protocol,
                    server_security_protocol: *server_security_protocol,
                })
            };

            (
                x224::X224(nego::ConnectionConfirm::Response {
                    flags: *flags,
                    protocol: client_security_protocol,
                }),
                result,
            )
        }
        nego::ConnectionConfirm::Failure { code } => (
            x224::X224(received_connection_confirm.0.clone()),
            Err(anyhow::anyhow!("RDP session initiation failed with code {code}")),
        ),
    };

    trace!(?connection_confirm_to_send, "Send Connection Request PDU to client");
    send_pdu(client_framed, &connection_confirm_to_send)
        .await
        .context("send connection confirm to client")?;

    handshake_result
}

#[instrument(name = "server_credssp", level = "debug", ret, skip_all)]
async fn perform_credssp_with_server<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    server_name: String,
    server_public_key: Vec<u8>,
    security_protocol: nego::SecurityProtocol,
    credentials: &crate::credential::AppCredential,
) -> anyhow::Result<()>
where
    S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
{
    use ironrdp_tokio::FramedWrite as _;

    let credentials = match credentials {
        crate::credential::AppCredential::UsernamePassword { username, password } => {
            ironrdp_connector::Credentials::UsernamePassword {
                username: username.clone(),
                password: password.expose_secret().to_owned(),
            }
        }
    };

    let (mut sequence, mut ts_request) = ironrdp_connector::credssp::CredsspSequence::init(
        credentials,
        None,
        security_protocol,
        ironrdp_connector::ServerName::new(server_name),
        server_public_key,
        None,
    )?;

    let mut buf = ironrdp_pdu::WriteBuf::new();

    loop {
        let mut generator = sequence.process_ts_request(ts_request);
        let client_state = generator.resolve_to_result().context("sspi generator resolve")?;
        drop(generator);

        buf.clear();
        let written = sequence.handle_process_result(client_state, &mut buf)?;

        if let Some(response_len) = written.size() {
            let response = &buf[..response_len];
            framed
                .write_all(response)
                .await
                .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
        }

        let Some(next_pdu_hint) = sequence.next_pdu_hint() else {
            break;
        };

        let pdu = framed.read_by_hint(next_pdu_hint).await.context("read frame by hint")?;

        if let Some(next_request) = sequence.decode_server_message(&pdu)? {
            ts_request = next_request;
        } else {
            break;
        }
    }

    Ok(())
}

#[instrument(name = "client_credssp", level = "debug", ret, skip_all)]
async fn perform_credssp_with_client<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    client_addr: IpAddr,
    gateway_public_key: Vec<u8>,
    security_protocol: nego::SecurityProtocol,
    credentials: &crate::credential::AppCredential,
) -> anyhow::Result<()>
where
    S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
{
    use ironrdp_connector::sspi::credssp::EarlyUserAuthResult;
    use ironrdp_tokio::FramedWrite as _;

    let mut buf = ironrdp_pdu::WriteBuf::new();

    // Are we supposed to use the actual computer name of the client?
    // But this does not seem to matter so far, so we stringify the IP address of the client instead.
    let client_computer_name = ironrdp_connector::ServerName::new(client_addr.to_string());

    let result = credssp_loop(framed, &mut buf, client_computer_name, gateway_public_key, credentials).await;

    if security_protocol.intersects(nego::SecurityProtocol::HYBRID_EX) {
        trace!(?result, "HYBRID_EX");

        let result = if result.is_ok() {
            EarlyUserAuthResult::Success
        } else {
            EarlyUserAuthResult::AccessDenied
        };

        buf.clear();
        result.to_buffer(&mut buf).context("write early user auth result")?;
        let response = &buf[..result.buffer_len()];
        framed.write_all(response).await.context("write_all")?;
    }

    return result;

    async fn credssp_loop<S>(
        framed: &mut ironrdp_tokio::Framed<S>,
        buf: &mut ironrdp_pdu::WriteBuf,
        client_computer_name: ironrdp_connector::ServerName,
        public_key: Vec<u8>,
        credentials: &crate::credential::AppCredential,
    ) -> anyhow::Result<()>
    where
        S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
    {
        let crate::credential::AppCredential::UsernamePassword { username, password } = credentials;

        let username = ironrdp_connector::sspi::Username::parse(username).context("invalid username")?;

        let identity = ironrdp_connector::sspi::AuthIdentity {
            username,
            password: password.expose_secret().to_owned().into(),
        };

        let mut sequence =
            ironrdp_acceptor::credssp::CredsspSequence::init(&identity, client_computer_name, public_key, None)?;

        loop {
            let Some(next_pdu_hint) = sequence.next_pdu_hint()? else {
                break;
            };

            let pdu = framed
                .read_by_hint(next_pdu_hint)
                .await
                .map_err(|e| ironrdp_connector::custom_err!("read frame by hint", e))?;

            let Some(ts_request) = sequence.decode_client_message(&pdu)? else {
                break;
            };

            let result = sequence.process_ts_request(ts_request);
            buf.clear();
            let written = sequence.handle_process_result(result, buf)?;

            if let Some(response_len) = written.size() {
                let response = &buf[..response_len];
                framed
                    .write_all(response)
                    .await
                    .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
            }
        }

        Ok(())
    }
}

async fn get_cached_gateway_public_key(
    hostname: String,
    acceptor: tokio_rustls::TlsAcceptor,
) -> anyhow::Result<Vec<u8>> {
    const LIFETIME_SECS: i64 = 300;

    static CACHE: tokio::sync::Mutex<Cache> = tokio::sync::Mutex::const_new(Cache {
        key: Vec::new(),
        update_timestamp: 0,
    });

    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    let mut guard = CACHE.lock().await;

    if now < guard.update_timestamp + LIFETIME_SECS {
        return Ok(guard.key.clone());
    }

    let key = retrieve_gateway_public_key(hostname, acceptor).await?;

    *guard = Cache {
        key: key.clone(),
        update_timestamp: now,
    };

    return Ok(key);

    struct Cache {
        key: Vec<u8>,
        update_timestamp: i64,
    }
}

async fn retrieve_gateway_public_key(hostname: String, acceptor: tokio_rustls::TlsAcceptor) -> anyhow::Result<Vec<u8>> {
    let (client_side, server_side) = tokio::io::duplex(4096);

    let connect_fut = crate::tls::connect(hostname, client_side);
    let accept_fut = acceptor.accept(server_side);

    let (connect_res, _) = tokio::join!(connect_fut, accept_fut);

    let tls_stream = connect_res.context("connect")?;

    let public_key =
        extract_tls_server_public_key(&tls_stream).context("extract Devolutions Gateway TLS public key")?;

    Ok(public_key)
}

fn extract_tls_server_public_key(tls_stream: &impl GetPeerCert) -> anyhow::Result<Vec<u8>> {
    use x509_cert::der::Decode as _;

    let cert = tls_stream.get_peer_certificate().context("certificate is missing")?;

    let cert = x509_cert::Certificate::from_der(cert).context("parse X509 certificate")?;

    let server_public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("subject public key BIT STRING is not aligned")?
        .to_owned();

    Ok(server_public_key)
}

trait GetPeerCert {
    fn get_peer_certificate(&self) -> Option<&tokio_rustls::rustls::pki_types::CertificateDer<'static>>;
}

impl<S> GetPeerCert for tokio_rustls::client::TlsStream<S> {
    fn get_peer_certificate(&self) -> Option<&tokio_rustls::rustls::pki_types::CertificateDer<'static>> {
        self.get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
    }
}

impl<S> GetPeerCert for tokio_rustls::server::TlsStream<S> {
    fn get_peer_certificate(&self) -> Option<&tokio_rustls::rustls::pki_types::CertificateDer<'static>> {
        self.get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
    }
}

async fn send_pdu<S, P>(framed: &mut ironrdp_tokio::TokioFramed<S>, pdu: &P) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin + Send + Sync,
    P: ironrdp_core::Encode,
{
    use ironrdp_tokio::FramedWrite as _;

    let payload = ironrdp_core::encode_vec(pdu).context("failed to encode PDU")?;
    framed.write_all(&payload).await.context("failed to write PDU")?;
    Ok(())
}
