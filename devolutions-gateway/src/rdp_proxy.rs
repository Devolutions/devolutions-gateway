use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context as _;
use ironrdp_acceptor::credssp::CredsspProcessGenerator as CredsspServerProcessGenerator;
use ironrdp_connector::credssp::CredsspProcessGenerator as CredsspClientProcessGenerator;
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::{GeneratorState, NetworkRequest};
use ironrdp_pdu::{mcs, nego, x224};
use secrecy::ExposeSecret as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use typed_builder::TypedBuilder;
use uuid::Uuid;

use crate::api::kdc_proxy::send_krb_message;
use crate::config::Conf;
use crate::credential::AppCredential;
use crate::credential_injection_kdc::{
    CredentialInjectionClientAcceptorProtocol, CredentialInjectionKdc, CredentialInjectionKdcInterception,
};
use crate::proxy::Proxy;
use crate::session::{DisconnectInterest, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::target_addr::TargetAddr;

#[derive(TypedBuilder)]
pub struct RdpProxy<C, S> {
    conf: Arc<Conf>,
    session_info: SessionInfo,
    client_stream: C,
    client_addr: SocketAddr,
    server_stream: S,
    server_addr: SocketAddr,
    credential_injection_kdc: CredentialInjectionKdc,
    client_stream_leftover_bytes: bytes::BytesMut,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    server_dns_name: String,
    disconnect_interest: Option<DisconnectInterest>,
    #[builder(default)]
    agent_tunnel_handle: Option<Arc<agent_tunnel::AgentTunnelHandle>>,
    /// `jet_agent_id` from the parent association token, if any. When set, the routing
    /// pipeline must route via that agent (or fail) — never silently fall back to
    /// another agent or to direct connect. See [`send_krb_message`].
    #[builder(default)]
    explicit_agent_id: Option<Uuid>,
}

impl<A, B> RdpProxy<A, B>
where
    A: AsyncWrite + AsyncRead + Unpin + Send,
    B: AsyncWrite + AsyncRead + Unpin + Send,
{
    pub async fn run(self) -> anyhow::Result<()> {
        handle(self).await
    }
}

#[instrument("rdp_proxy", skip_all, fields(session_id = proxy.session_info.id.to_string(), target = proxy.server_addr.to_string()))]
async fn handle<C, S>(proxy: RdpProxy<C, S>) -> anyhow::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let RdpProxy {
        conf,
        session_info,
        client_stream,
        client_addr,
        server_stream,
        server_addr,
        credential_injection_kdc,
        client_stream_leftover_bytes,
        sessions,
        subscriber_tx,
        server_dns_name,
        disconnect_interest,
        agent_tunnel_handle,
        explicit_agent_id,
    } = proxy;

    // session_id used for KDC-via-tunnel correlation (see send_krb_message).
    let session_id = session_info.id;

    let tls_conf = conf.credssp_tls.get().context("CredSSP TLS configuration")?;
    let gateway_hostname = conf.hostname.clone();

    // -- Retrieve the Gateway TLS public key that must be used for client-proxy CredSSP later on -- //

    let gateway_cert_chain_handle = tokio::spawn(crate::tls::get_cert_chain_for_acceptor_cached(
        gateway_hostname.clone(),
        tls_conf.acceptor.clone(),
    ));

    // -- Dual handshake with the client and the server until the TLS security upgrade -- //

    let mut client_framed =
        ironrdp_tokio::MovableTokioFramed::new_with_leftover(client_stream, client_stream_leftover_bytes);
    let mut server_framed = ironrdp_tokio::MovableTokioFramed::new(server_stream);

    let handshake_result = dual_handshake_until_tls_upgrade(
        &mut client_framed,
        &mut server_framed,
        credential_injection_kdc.target_credential(),
    )
    .await?;

    let client_stream = client_framed.into_inner_no_leftover();
    let server_stream = server_framed.into_inner_no_leftover();

    // -- Perform the TLS upgrading for both the client and the server, effectively acting as a man-in-the-middle -- //

    let client_tls_upgrade_fut = tls_conf.acceptor.accept(client_stream);
    let server_tls_upgrade_fut = crate::tls::dangerous_connect(server_dns_name.clone(), server_stream);

    let (client_stream, server_stream) = tokio::join!(client_tls_upgrade_fut, server_tls_upgrade_fut);

    let client_stream = client_stream.context("TLS upgrade with client failed")?;
    let server_stream = server_stream.context("TLS upgrade with server failed")?;

    let server_public_key =
        crate::tls::extract_stream_peer_public_key(&server_stream).context("extract target server TLS public key")?;

    let gateway_cert_chain = gateway_cert_chain_handle.await??;
    let gateway_public_key = crate::tls::extract_public_key(gateway_cert_chain.first().context("no leaf")?)
        .context("extract Gateway public key")?;

    // -- Perform the CredSSP authentication with the client (acting as a server) and the server (acting as a client) -- //

    let mut client_framed = ironrdp_tokio::MovableTokioFramed::new(client_stream);
    let mut server_framed = ironrdp_tokio::MovableTokioFramed::new(server_stream);

    let krb_server_config = credential_injection_kerberos_server_config(&conf, client_addr, &credential_injection_kdc)?;

    let client_credssp_fut = perform_credssp_as_server(
        &mut client_framed,
        client_addr.ip(),
        gateway_public_key,
        handshake_result.client_security_protocol,
        credential_injection_kdc.proxy_credential(),
        krb_server_config,
        &credential_injection_kdc,
        agent_tunnel_handle.as_deref(),
        session_id,
        explicit_agent_id,
    );

    let krb_client_config = if conf.debug.enable_unstable
        && let Some(crate::config::dto::KerberosConfig {
            kerberos_server: _,
            kdc_url,
        }) = conf.debug.kerberos.as_ref()
    {
        Some(ironrdp_connector::credssp::KerberosConfig {
            kdc_proxy_url: kdc_url.clone(),
            hostname: Some(gateway_hostname.clone()),
        })
    } else {
        None
    };

    let server_credssp_fut = perform_credssp_as_client(
        &mut server_framed,
        server_dns_name,
        server_public_key,
        handshake_result.server_security_protocol,
        credential_injection_kdc.target_credential(),
        krb_client_config,
        agent_tunnel_handle.as_deref(),
        session_id,
        explicit_agent_id,
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
pub(crate) async fn intercept_connect_confirm<C, S>(
    client_framed: &mut ironrdp_tokio::MovableTokioFramed<C>,
    server_framed: &mut ironrdp_tokio::MovableTokioFramed<S>,
    server_security_protocol: nego::SecurityProtocol,
) -> anyhow::Result<()>
where
    C: AsyncWrite + AsyncRead + Unpin + Send,
    S: AsyncWrite + AsyncRead + Unpin + Send,
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

    let mut gcc_blocks = received_connect_initial.conference_create_request.into_gcc_blocks();
    gcc_blocks.core.optional_data.server_selected_protocol = Some(server_security_protocol);
    // Update the conference request with modified gcc_blocks.
    received_connect_initial.conference_create_request = ironrdp_pdu::gcc::ConferenceCreateRequest::new(gcc_blocks)?;
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
    client_framed: &mut ironrdp_tokio::MovableTokioFramed<C>,
    server_framed: &mut ironrdp_tokio::MovableTokioFramed<S>,
    target_credential: &AppCredential,
) -> anyhow::Result<HandshakeResult>
where
    C: AsyncWrite + AsyncRead + Unpin + Send,
    S: AsyncWrite + AsyncRead + Unpin + Send,
{
    let (_, received_frame) = client_framed.read_pdu().await.context("read PDU from client")?;
    let received_connection_request: x224::X224<nego::ConnectionRequest> =
        ironrdp_core::decode(&received_frame).context("decode PDU from client")?;
    trace!(message = ?received_connection_request, "Received Connection Request PDU from client");

    // Choose the security protocol to use with the client.
    let received_connection_request_protocol = received_connection_request.0.protocol;
    let client_security_protocol = if received_connection_request_protocol.contains(nego::SecurityProtocol::HYBRID_EX) {
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
        nego_data: match target_credential {
            AppCredential::UsernamePassword { username, .. } => {
                Some(nego::NegoRequestData::cookie(username.to_owned()))
            }
        },
        flags: received_connection_request.0.flags,
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
        //
        // The spec states that `PROTOCOL_SSL` "SHOULD" also be set when using `PROTOCOL_HYBRID`:
        //
        // > PROTOCOL_HYBRID (0x00000002)
        // > Credential Security Support Provider protocol (CredSSP) (section 5.4.5.2).
        // > If this flag is set, then the PROTOCOL_SSL (0x00000001) flag SHOULD also be set
        // > because Transport Layer Security (TLS) is a subset of CredSSP.
        //
        // However, in practice `mstsc` is picky about these flags: it expects the
        // SupportedProtocol bits in the ConnectionRequestPDU that reach the target
        // server to match what the client originally sent. If the proxy modifies
        // them (for example, forcing HYBRID | HYBRID_EX and/or clearing SSL),
        // the connection can fail with an authentication error (Code: 0x609).
        //
        // We therefore *do not* synthesize a new protocol bitmask here anymore.
        // Instead, we forward the client's SupportedProtocol flags as-is and
        // enforce our policy by validating them: if HYBRID / HYBRID_EX are not
        // present (i.e. NLA is not negotiated), we fail the connection rather
        // than trying to "fix" the flags ourselves.
        //
        // See also: https://serverfault.com/a/720161
        protocol: received_connection_request_protocol,
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

pub(crate) fn credential_injection_kerberos_server_config(
    conf: &Conf,
    client_addr: SocketAddr,
    credential_injection_kdc: &CredentialInjectionKdc,
) -> anyhow::Result<Option<sspi::KerberosServerConfig>> {
    if !conf.debug.enable_unstable || conf.debug.kerberos.is_none() {
        return Ok(None);
    }

    match credential_injection_kdc.client_acceptor_protocol()? {
        CredentialInjectionClientAcceptorProtocol::Kerberos => {
            credential_injection_kdc.server_kerberos_config(client_addr).map(Some)
        }
        CredentialInjectionClientAcceptorProtocol::Ntlm => {
            debug!(
                jti = %credential_injection_kdc.jti(),
                "Credential-injection Kerberos acceptor disabled for NTLM target credential"
            );
            Ok(None)
        }
    }
}

#[expect(clippy::too_many_arguments)]
#[instrument(name = "server_credssp", level = "debug", ret, skip_all)]
pub(crate) async fn perform_credssp_as_client<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    server_name: String,
    server_public_key: Vec<u8>,
    security_protocol: nego::SecurityProtocol,
    credentials: &AppCredential,
    kerberos_config: Option<ironrdp_connector::credssp::KerberosConfig>,
    agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
    session_id: Uuid,
    explicit_agent_id: Option<Uuid>,
) -> anyhow::Result<()>
where
    S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
{
    use ironrdp_tokio::FramedWrite as _;

    // Decrypt password into short-lived buffer.
    let (username, decrypted_password) = credentials
        .decrypt_password()
        .context("failed to decrypt credentials")?;

    let credentials = ironrdp_connector::Credentials::UsernamePassword {
        username,
        password: decrypted_password.expose_secret().to_owned(),
    };
    // decrypted_password drops here, zeroizing its buffer; note: a copy of the plaintext
    // remains in `credentials` above, which is a regular String (downstream API limitation).

    let (mut sequence, mut ts_request) = ironrdp_connector::credssp::CredsspSequence::init(
        credentials,
        None,
        security_protocol,
        ironrdp_connector::ServerName::new(server_name.clone()),
        server_public_key,
        kerberos_config,
    )?;

    let mut buf = ironrdp_pdu::WriteBuf::new();

    loop {
        let client_state = {
            let mut generator = sequence.process_ts_request(ts_request);
            resolve_client_generator(&mut generator, agent_tunnel_handle, session_id, explicit_agent_id).await?
        }; // drop generator

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

async fn resolve_server_generator(
    generator: &mut CredsspServerProcessGenerator<'_>,
    credential_injection_kdc: &CredentialInjectionKdc,
    agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
    session_id: Uuid,
    explicit_agent_id: Option<Uuid>,
) -> Result<sspi::credssp::ServerState, sspi::credssp::ServerError> {
    let mut state = generator.start();

    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let response = match credential_injection_kdc.intercept_network_request(&request) {
                    Ok(CredentialInjectionKdcInterception::Intercepted(response)) => Ok(response),
                    Ok(CredentialInjectionKdcInterception::NotInjectionRequest) => {
                        send_network_request(&request, agent_tunnel_handle, session_id, explicit_agent_id).await
                    }
                    Ok(CredentialInjectionKdcInterception::NotInjectionRealm(mismatch)) => Err(anyhow::anyhow!(
                        "kdc request realm does not match credential-injection session realm: {mismatch}"
                    )),
                    Err(error) => Err(error),
                }
                .map_err(|err| sspi::credssp::ServerError {
                    ts_request: None,
                    error: sspi::Error::new(sspi::ErrorKind::InternalError, err),
                })?;

                state = generator.resume(Ok(response));
            }
            GeneratorState::Completed(client_state) => {
                break client_state;
            }
        }
    }
}

async fn resolve_client_generator(
    generator: &mut CredsspClientProcessGenerator<'_>,
    agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
    session_id: Uuid,
    explicit_agent_id: Option<Uuid>,
) -> anyhow::Result<sspi::credssp::ClientState> {
    let mut state = generator.start();

    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let response =
                    send_network_request(&request, agent_tunnel_handle, session_id, explicit_agent_id).await?;
                state = generator.resume(Ok(response));
            }
            GeneratorState::Completed(client_state) => {
                break Ok(client_state.map_err(|e| {
                    ironrdp_connector::ConnectorError::new("CredSSP", ironrdp_connector::ConnectorErrorKind::Credssp(e))
                })?);
            }
        };
    }
}

#[expect(clippy::too_many_arguments)]
#[instrument(name = "client_credssp", level = "debug", ret, skip_all)]
pub(crate) async fn perform_credssp_as_server<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    client_addr: IpAddr,
    gateway_public_key: Vec<u8>,
    security_protocol: nego::SecurityProtocol,
    credentials: &AppCredential,
    kerberos_server_config: Option<sspi::KerberosServerConfig>,
    credential_injection_kdc: &CredentialInjectionKdc,
    agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
    session_id: Uuid,
    explicit_agent_id: Option<Uuid>,
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

    let result = credssp_loop(
        framed,
        &mut buf,
        client_computer_name,
        gateway_public_key,
        credentials,
        kerberos_server_config,
        credential_injection_kdc,
        agent_tunnel_handle,
        session_id,
        explicit_agent_id,
    )
    .await;

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

    #[expect(clippy::too_many_arguments)]
    async fn credssp_loop<S>(
        framed: &mut ironrdp_tokio::Framed<S>,
        buf: &mut ironrdp_pdu::WriteBuf,
        client_computer_name: ironrdp_connector::ServerName,
        public_key: Vec<u8>,
        credentials: &AppCredential,
        kerberos_server_config: Option<sspi::KerberosServerConfig>,
        credential_injection_kdc: &CredentialInjectionKdc,
        agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
        session_id: Uuid,
        explicit_agent_id: Option<Uuid>,
    ) -> anyhow::Result<()>
    where
        S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
    {
        // Decrypt password into short-lived buffer.
        let (username, decrypted_password) = credentials
            .decrypt_password()
            .context("failed to decrypt credentials")?;

        let username = sspi::Username::parse(&username).context("invalid username")?;

        let identity = sspi::AuthIdentity {
            username,
            password: decrypted_password.expose_secret().to_owned().into(),
        };
        // decrypted_password drops here, zeroizing its buffer; note: a copy of the plaintext
        // remains in `identity` above (downstream API limitation).

        let mut sequence = ironrdp_acceptor::credssp::CredsspSequence::init(
            &identity,
            client_computer_name,
            public_key,
            kerberos_server_config,
        )?;

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

            let result = {
                let mut generator = sequence.process_ts_request(ts_request);
                resolve_server_generator(
                    &mut generator,
                    credential_injection_kdc,
                    agent_tunnel_handle,
                    session_id,
                    explicit_agent_id,
                )
                .await
            }; // drop generator

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

async fn send_pdu<S, P>(framed: &mut ironrdp_tokio::MovableTokioFramed<S>, pdu: &P) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin + Send,
    P: ironrdp_core::Encode,
{
    use ironrdp_tokio::FramedWrite as _;

    let payload = ironrdp_core::encode_vec(pdu).context("failed to encode PDU")?;
    framed.write_all(&payload).await.context("failed to write PDU")?;
    Ok(())
}

/// Generic Kerberos network-request dispatcher.
///
/// Only handles real-network schemes (`tcp` / `udp`); credential-injection loopback requests
/// are intercepted by [`CredentialInjectionKdc`] before reaching this function.
///
/// TODO(sspi-rs#664): when sspi-rs ships a pluggable KDC dispatcher API, the URL trick for
/// credential injection goes away entirely and this helper can be inlined back into the
/// CredSSP loops.
async fn send_network_request(
    request: &NetworkRequest,
    agent_tunnel_handle: Option<&agent_tunnel::AgentTunnelHandle>,
    session_id: Uuid,
    explicit_agent_id: Option<Uuid>,
) -> anyhow::Result<Vec<u8>> {
    match request.url.scheme() {
        "tcp" | "udp" => {
            let target_addr = TargetAddr::parse(request.url.as_str(), Some(88))?;

            send_krb_message(
                &target_addr,
                &request.data,
                agent_tunnel_handle,
                session_id,
                explicit_agent_id,
            )
            .await
            .map_err(|err| anyhow::anyhow!("failed to send KDC message: {err}"))
        }
        unsupported => anyhow::bail!("unsupported KDC request scheme: {unsupported}"),
    }
}
