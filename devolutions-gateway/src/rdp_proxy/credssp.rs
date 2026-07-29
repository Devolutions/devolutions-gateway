use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use ironrdp_acceptor::credssp::CredsspProcessGenerator as CredsspServerProcessGenerator;
use ironrdp_connector::credssp::CredsspProcessGenerator as CredsspClientProcessGenerator;
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_pdu::{mcs, nego, x224};
use secrecy::ExposeSecret as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use typed_builder::TypedBuilder;

use super::send_pdu;
use crate::config::Conf;
use crate::credential::AppCredential;
use crate::credential_injection::{CredentialInjection, SyntheticKdcInterception};
use crate::kdc_connector::KdcConnector;
use crate::proxy::Proxy;
use crate::session::{DisconnectInterest, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;

#[derive(TypedBuilder)]
pub(crate) struct CredsspSession {
    conf: Arc<Conf>,
    session_info: SessionInfo,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    credential_injection: CredentialInjection,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    server_dns_name: String,
    disconnect_interest: Option<DisconnectInterest>,
    kdc_connector: KdcConnector,
}

#[derive(TypedBuilder)]
pub(crate) struct PreparedCredssp<C, S> {
    client_stream: C,
    server_stream: S,
    gateway_public_key: Vec<u8>,
    server_public_key: Vec<u8>,
    client_security_protocol: nego::SecurityProtocol,
    server_security_protocol: nego::SecurityProtocol,
}

impl CredsspSession {
    pub(super) fn conf(&self) -> &Conf {
        &self.conf
    }

    pub(super) fn server_dns_name(&self) -> &str {
        &self.server_dns_name
    }

    pub(super) fn target_credential(&self) -> &AppCredential {
        self.credential_injection.target_credential()
    }

    pub(crate) async fn run<C, S>(self, prepared: PreparedCredssp<C, S>) -> anyhow::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let Self {
            conf,
            session_info,
            client_addr,
            server_addr,
            credential_injection,
            sessions,
            subscriber_tx,
            server_dns_name,
            disconnect_interest,
            kdc_connector,
        } = self;
        let PreparedCredssp {
            client_stream,
            server_stream,
            gateway_public_key,
            server_public_key,
            client_security_protocol,
            server_security_protocol,
        } = prepared;

        let mut client_framed = ironrdp_tokio::MovableTokioFramed::new(client_stream);
        let mut server_framed = ironrdp_tokio::MovableTokioFramed::new(server_stream);

        let (server_kerberos_config, client_kerberos_config) = credential_injection
            .kerberos_configs(client_addr, &conf.hostname)?
            .unzip();

        let client_credssp_fut = perform_credssp_as_server(
            &mut client_framed,
            client_addr.ip(),
            gateway_public_key,
            client_security_protocol,
            credential_injection.proxy_credential(),
            server_kerberos_config,
            &credential_injection,
            &kdc_connector,
        );

        let server_credssp_fut = perform_credssp_as_client(
            &mut server_framed,
            server_dns_name,
            server_public_key,
            server_security_protocol,
            credential_injection.target_credential(),
            client_kerberos_config,
            &kdc_connector,
        );

        let (client_credssp_res, server_credssp_res) = tokio::join!(client_credssp_fut, server_credssp_fut);
        client_credssp_res.context("CredSSP with client")?;
        server_credssp_res.context("CredSSP with server")?;

        intercept_connect_confirm(&mut client_framed, &mut server_framed, server_security_protocol).await?;

        let (mut client_stream, client_leftover) = client_framed.into_inner();
        let (mut server_stream, server_leftover) = server_framed.into_inner();

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
            .context("RDP-TLS traffic proxying failed")
    }
}

#[instrument(level = "debug", ret, skip_all)]
async fn intercept_connect_confirm<C, S>(
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

#[instrument(name = "server_credssp", level = "debug", ret, skip_all)]
async fn perform_credssp_as_client<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    server_name: String,
    server_public_key: Vec<u8>,
    security_protocol: nego::SecurityProtocol,
    credentials: &AppCredential,
    kerberos_config: Option<ironrdp_connector::credssp::KerberosConfig>,
    kdc_connector: &KdcConnector,
) -> anyhow::Result<()>
where
    S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
{
    use ironrdp_tokio::FramedWrite as _;

    let (username, decrypted_password) = credentials
        .decrypt_password()
        .context("failed to decrypt credentials")?;

    let credentials = ironrdp_connector::Credentials::UsernamePassword {
        username,
        password: decrypted_password.expose_secret().to_owned(),
    };

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
            resolve_client_generator(&mut generator, kdc_connector).await?
        };

        buf.clear();
        let written = sequence.handle_process_result(client_state, &mut buf)?;

        if let Some(response_len) = written.size() {
            let response = &buf[..response_len];
            framed
                .write_all(response)
                .await
                .map_err(|error| ironrdp_connector::custom_err!("write all", error))?;
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
    credential_injection: &CredentialInjection,
    kdc_connector: &KdcConnector,
) -> Result<sspi::credssp::ServerState, sspi::credssp::ServerError> {
    let mut state = generator.start();

    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let response = match credential_injection.intercept_network_request(&request) {
                    Ok(SyntheticKdcInterception::Intercepted(response)) => Ok(response),
                    Ok(SyntheticKdcInterception::NotInjectionRealm(mismatch)) => Err(anyhow::anyhow!(
                        "kdc request realm does not match credential-injection session realm: {mismatch}"
                    )),
                    Ok(SyntheticKdcInterception::NotInjectionRequest) => {
                        kdc_connector.send_network_request(&request).await
                    }
                    Err(error) => Err(error),
                }
                .map_err(|error| sspi::credssp::ServerError {
                    ts_request: None,
                    error: sspi::Error::new(sspi::ErrorKind::InternalError, error),
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
    kdc_connector: &KdcConnector,
) -> anyhow::Result<sspi::credssp::ClientState> {
    let mut state = generator.start();

    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let response = kdc_connector.send_network_request(&request).await?;
                state = generator.resume(Ok(response));
            }
            GeneratorState::Completed(client_state) => {
                break Ok(client_state.map_err(|error| {
                    ironrdp_connector::ConnectorError::new(
                        "CredSSP",
                        ironrdp_connector::ConnectorErrorKind::Credssp(error),
                    )
                })?);
            }
        };
    }
}

#[expect(clippy::too_many_arguments)]
#[instrument(name = "client_credssp", level = "debug", ret, skip_all)]
async fn perform_credssp_as_server<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    client_addr: std::net::IpAddr,
    gateway_public_key: Vec<u8>,
    security_protocol: nego::SecurityProtocol,
    credentials: &AppCredential,
    kerberos_server_config: Option<sspi::KerberosServerConfig>,
    credential_injection: &CredentialInjection,
    kdc_connector: &KdcConnector,
) -> anyhow::Result<()>
where
    S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
{
    use ironrdp_connector::sspi::credssp::EarlyUserAuthResult;
    use ironrdp_tokio::FramedWrite as _;

    let mut buf = ironrdp_pdu::WriteBuf::new();
    let client_computer_name = ironrdp_connector::ServerName::new(client_addr.to_string());

    let result = credssp_loop(
        framed,
        &mut buf,
        client_computer_name,
        gateway_public_key,
        credentials,
        kerberos_server_config,
        credential_injection,
        kdc_connector,
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

    result
}

#[expect(clippy::too_many_arguments)]
async fn credssp_loop<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    buf: &mut ironrdp_pdu::WriteBuf,
    client_computer_name: ironrdp_connector::ServerName,
    public_key: Vec<u8>,
    credentials: &AppCredential,
    kerberos_server_config: Option<sspi::KerberosServerConfig>,
    credential_injection: &CredentialInjection,
    kdc_connector: &KdcConnector,
) -> anyhow::Result<()>
where
    S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
{
    use ironrdp_tokio::FramedWrite as _;

    let (username, decrypted_password) = credentials
        .decrypt_password()
        .context("failed to decrypt credentials")?;

    let username = sspi::Username::parse(&username).context("invalid username")?;

    let identity = sspi::AuthIdentity {
        username,
        password: decrypted_password.expose_secret().to_owned().into(),
    };

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
            .map_err(|error| ironrdp_connector::custom_err!("read frame by hint", error))?;

        let Some(ts_request) = sequence.decode_client_message(&pdu)? else {
            break;
        };

        let result = {
            let mut generator = sequence.process_ts_request(ts_request);
            resolve_server_generator(&mut generator, credential_injection, kdc_connector).await
        };

        buf.clear();
        let written = sequence.handle_process_result(result, buf)?;

        if let Some(response_len) = written.size() {
            let response = &buf[..response_len];
            framed
                .write_all(response)
                .await
                .map_err(|error| ironrdp_connector::custom_err!("write all", error))?;
        }
    }

    Ok(())
}
