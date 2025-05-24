use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::config::Conf;
use crate::credential::ArcCredentialEntry;
use crate::proxy::Proxy;
use crate::session::{SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;

use anyhow::Context as _;
use ironrdp_pdu::{nego, x224};
use tap::Pipe;
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

#[instrument("rdp_proxy", skip_all, fields(session_id = proxy.session_info.association_id.to_string(), target = proxy.server_addr.to_string()))]
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
    } = proxy;

    let tls_conf = conf
        .tls
        .as_ref()
        .context("TLS configuration required for credential injection feature")?;

    let credential_mapping = credential_entry.mapping.as_ref().context("no credential mapping")?;

    // -- Retrieve the Gateway TLS public key that must be used for client-proxy CredSSP later on -- //

    let gateway_public_key_handle = tokio::spawn(retrieve_gateway_public_key(
        conf.hostname.clone(),
        tls_conf.acceptor.clone(),
    ));

    // -- Two-way forwarding between the client and the server until the TLS security upgrade -- //

    let mut client_framed = ironrdp_tokio::TokioFramed::new_with_leftover(client_stream, client_stream_leftover_bytes);
    let mut server_framed = ironrdp_tokio::TokioFramed::new(server_stream);

    let selected_security_protocol = forward_until_tls_upgrade(&mut client_framed, &mut server_framed).await?;

    let client_stream = client_framed.into_inner_no_leftover();
    let server_stream = server_framed.into_inner_no_leftover();

    // -- Perform the TLS upgrading for both the client and the server, effectively acting as a man-in-the-middle -- //

    let client_tls_upgrade_fut = tls_conf.acceptor.accept(client_stream);
    let server_tls_upgrade_fut = ironrdp_tls::upgrade(server_stream, &server_dns_name);

    let (client_stream, server_stream) = tokio::join!(client_tls_upgrade_fut, server_tls_upgrade_fut);

    let client_stream = client_stream.context("TLS upgrade with client failed")?;
    let (server_stream, server_public_key) = server_stream.context("TLS upgrade with server failed")?;
    let gateway_public_key = gateway_public_key_handle.await??;

    // -- Perform the CredSSP authentication with the client (acting as a server) and the server (acting as a client) -- //

    let mut client_framed = ironrdp_tokio::TokioFramed::new(client_stream);
    let mut server_framed = ironrdp_tokio::TokioFramed::new(server_stream);

    let client_credssp_fut = perform_credssp_with_client(
        &mut client_framed,
        client_addr.ip(),
        gateway_public_key,
        selected_security_protocol,
        &credential_mapping.proxy,
    );

    let server_credssp_fut = perform_credssp_with_server(
        &mut server_framed,
        server_dns_name,
        server_public_key,
        selected_security_protocol,
        &credential_mapping.target,
    );

    let (client_credssp_res, server_credssp_res) = tokio::join!(client_credssp_fut, server_credssp_fut);
    client_credssp_res.context("CredSSP with client")?;
    server_credssp_res.context("CredSSP with server")?;

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
        .build()
        .select_dissector_and_forward()
        .await
        .context("RDP-TLS traffic proxying failed")?;

    Ok(())
}

async fn forward_until_tls_upgrade<C, S>(
    client_framed: &mut ironrdp_tokio::TokioFramed<C>,
    server_framed: &mut ironrdp_tokio::TokioFramed<S>,
) -> anyhow::Result<nego::SecurityProtocol>
where
    C: AsyncWrite + AsyncRead + Unpin + Send + Sync,
    S: AsyncWrite + AsyncRead + Unpin + Send + Sync,
{
    use ironrdp_tokio::FramedWrite as _;

    let connection_confirm = loop {
        tokio::select! {
            res = client_framed.read_pdu() => {
                let (_action, bytes) = res.context("failed to read PDU from client")?;
                server_framed.write_all(&bytes).await.context("failed to forward payload to server")?;
            }
            res = server_framed.read_pdu() => {
                let (_action, bytes) = res.context("failed to read PDU from server")?;
                client_framed.write_all(&bytes).await.context("failed to forward payload to client")?;

                // Once we reach the Connection Confirm PDU, we break out of the loop.
                // The next step is to verify the selected security protocol.
                if let Ok(connection_confirm) = ironrdp_core::decode::<x224::X224<nego::ConnectionConfirm>>(&bytes) {
                    break connection_confirm;
                }
            }
        }
    };

    trace!(message = ?connection_confirm, "Received Connection Confirm PDU from server");

    let (flags, selected_protocol) = match connection_confirm.0 {
        nego::ConnectionConfirm::Response { flags, protocol } => (flags, protocol),
        nego::ConnectionConfirm::Failure { code } => {
            anyhow::bail!("RDP session initiation failed with code {code}");
        }
    };

    trace!(?selected_protocol, ?flags, "Server confirmed connection");

    if !selected_protocol.intersects(nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX) {
        anyhow::bail!(
            "server selected security protocol {selected_protocol}, which is not supported for credential injection"
        );
    }

    Ok(selected_protocol)
}

// TODO: support for Kerberos and domain-joined.

async fn perform_credssp_with_server<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    server_name: String,
    server_public_key: Vec<u8>,
    selected_protocol: nego::SecurityProtocol,
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
        selected_protocol,
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
            trace!(response_len, "Send response");
            framed
                .write_all(response)
                .await
                .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
        }

        let Some(next_pdu_hint) = sequence.next_pdu_hint() else {
            break;
        };

        debug!(
            hint = ?next_pdu_hint,
            "Wait for PDU"
        );

        let pdu = framed.read_by_hint(next_pdu_hint).await.context("read frame by hint")?;

        trace!(length = pdu.len(), "PDU received");

        if let Some(next_request) = sequence.decode_server_message(&pdu)? {
            ts_request = next_request;
        } else {
            break;
        }
    }

    Ok(())
}

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

        let username = ironrdp_connector::sspi::Username::new(username, None).context("invalid username")?;

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

            debug!(
                hint = ?next_pdu_hint,
                "Wait for PDU"
            );

            let pdu = framed
                .read_by_hint(next_pdu_hint)
                .await
                .map_err(|e| ironrdp_connector::custom_err!("read frame by hint", e))?;

            trace!(length = pdu.len(), "PDU received");

            let Some(ts_request) = sequence.decode_client_message(&pdu)? else {
                break;
            };

            let result = sequence.process_ts_request(ts_request);
            buf.clear();
            let written = sequence.handle_process_result(result, buf)?;

            if let Some(response_len) = written.size() {
                let response = &buf[..response_len];
                trace!(response_len, "Send response");
                framed
                    .write_all(response)
                    .await
                    .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
            }
        }
        Ok(())
    }
}

// FIXME: In fact, we should probably negotiate the security protocol with the client separately from the server.
// The actual security layer is handled by us, not by the server.

fn extract_tls_server_public_key(cert: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io;

    use x509_cert::der::Decode as _;

    let cert = x509_cert::Certificate::from_der(cert).map_err(io::Error::other)?;

    let server_public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| io::Error::other("subject public key BIT STRING is not aligned"))?
        .to_owned();

    Ok(server_public_key)
}

// TODO/PERF: cache/service to keep the gateway public key somewhere without performing a fake connection each time.

async fn retrieve_gateway_public_key(hostname: String, acceptor: tokio_rustls::TlsAcceptor) -> anyhow::Result<Vec<u8>> {
    let (client_side, server_side) = tokio::io::duplex(4096);

    let connect_fut = crate::tls::connect(hostname, client_side);
    let accept_fut = acceptor.accept(server_side);

    let (connect_res, _) = tokio::join!(connect_fut, accept_fut);

    let tls_stream = connect_res.context("connect")?;

    let cert = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("certificate is missing")?;

    let public_key = extract_tls_server_public_key(cert)?;

    Ok(public_key)
}
