use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use ironrdp_pdu::{nego, x224};
use tokio::io::{AsyncRead, AsyncWrite};
use typed_builder::TypedBuilder;

mod credssp;

use credssp::CredsspSession;
pub(crate) use credssp::{
    PreparedCredssp, intercept_connect_confirm, perform_credssp_as_client, perform_credssp_as_server,
};

use crate::config::Conf;
use crate::credential::AppCredential;
use crate::credential_injection::CredentialInjection;
use crate::kdc_connector::KdcConnector;
use crate::session::{DisconnectInterest, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;

/// RDP proxy for credential-injection sessions.
///
/// The main path only orchestrates handshake and TLS upgrade. CredSSP MITM and the subsequent
/// forward live in [`CredsspSession`] / [`PreparedCredssp`].
#[derive(TypedBuilder)]
pub struct RdpProxy<C, S> {
    conf: Arc<Conf>,
    session_info: SessionInfo,
    client_stream: C,
    client_addr: SocketAddr,
    server_stream: S,
    server_addr: SocketAddr,
    credential_injection: CredentialInjection,
    client_stream_leftover_bytes: bytes::BytesMut,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    server_dns_name: String,
    disconnect_interest: Option<DisconnectInterest>,
    kdc_connector: KdcConnector,
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
        credential_injection,
        client_stream_leftover_bytes,
        sessions,
        subscriber_tx,
        server_dns_name,
        disconnect_interest,
        kdc_connector,
    } = proxy;

    let session = CredsspSession::builder()
        .conf(conf)
        .session_info(session_info)
        .client_addr(client_addr)
        .server_addr(server_addr)
        .credential_injection(credential_injection)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .server_dns_name(server_dns_name.clone())
        .disconnect_interest(disconnect_interest)
        .kdc_connector(kdc_connector)
        .build();

    let tls_conf = session.conf().credssp_tls.get().context("CredSSP TLS configuration")?;
    let gateway_hostname = session.conf().hostname.clone();

    // -- Retrieve the Gateway TLS public key that must be used for client-proxy CredSSP later on -- //

    let gateway_cert_chain_handle = tokio::spawn(crate::tls::get_cert_chain_for_acceptor_cached(
        gateway_hostname.clone(),
        tls_conf.acceptor.clone(),
    ));

    // -- Dual handshake with the client and the server until the TLS security upgrade -- //

    let mut client_framed =
        ironrdp_tokio::MovableTokioFramed::new_with_leftover(client_stream, client_stream_leftover_bytes);
    let mut server_framed = ironrdp_tokio::MovableTokioFramed::new(server_stream);

    let handshake_result =
        dual_handshake_until_tls_upgrade(&mut client_framed, &mut server_framed, session.target_credential()).await?;

    let client_stream = client_framed.into_inner_no_leftover();
    let server_stream = server_framed.into_inner_no_leftover();

    // -- Perform the TLS upgrading for both the client and the server, effectively acting as a man-in-the-middle -- //

    let client_tls_upgrade_fut = tls_conf.acceptor.accept(client_stream);
    let server_tls_upgrade_fut = crate::tls::dangerous_connect(session.server_dns_name().to_owned(), server_stream);

    let (client_stream, server_stream) = tokio::join!(client_tls_upgrade_fut, server_tls_upgrade_fut);

    let client_stream = client_stream.context("TLS upgrade with client failed")?;
    let server_stream = server_stream.context("TLS upgrade with server failed")?;

    let server_public_key =
        crate::tls::extract_stream_peer_public_key(&server_stream).context("extract target server TLS public key")?;

    let gateway_cert_chain = gateway_cert_chain_handle.await??;
    let gateway_public_key = crate::tls::extract_public_key(gateway_cert_chain.first().context("no leaf")?)
        .context("extract Gateway public key")?;

    let prepared = PreparedCredssp::builder()
        .client_stream(client_stream)
        .server_stream(server_stream)
        .gateway_public_key(gateway_public_key)
        .server_public_key(server_public_key)
        .client_security_protocol(handshake_result.client_security_protocol)
        .server_security_protocol(handshake_result.server_security_protocol)
        .build();

    // CredSSP MITM + Connect Confirm intercept + bidirectional forward: owned by CredsspSession.
    session.run(prepared).await
}

#[derive(Debug)]
struct HandshakeResult {
    client_security_protocol: nego::SecurityProtocol,
    server_security_protocol: nego::SecurityProtocol,
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

pub(super) async fn send_pdu<S, P>(framed: &mut ironrdp_tokio::MovableTokioFramed<S>, pdu: &P) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin + Send,
    P: ironrdp_core::Encode,
{
    use ironrdp_tokio::FramedWrite as _;

    let payload = ironrdp_core::encode_vec(pdu).context("failed to encode PDU")?;
    framed.write_all(&payload).await.context("failed to write PDU")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // Protocol selection is owned by CredentialInjection (from_provisioned + register_if_kerberos).
    // See credential_injection tests for Kerberos-vs-NTLM decision coverage.
}
