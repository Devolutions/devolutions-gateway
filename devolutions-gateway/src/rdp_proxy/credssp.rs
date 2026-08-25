//! CredSSP MITM for proxy-based RDP credential injection.
//!
//! Enclosed here so [`super::RdpProxy`] only orchestrates handshake and TLS upgrade.
//! The dual CredSSP legs, Kerberos config derivation, Connect Confirm intercept, and the
//! post-auth forward all live in [`CredsspSession::run`].

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
use crate::credential_injection::{CredentialInjection, CredentialInjectionKdc, CredentialInjectionKdcInterception};
use crate::kdc_connector::KdcConnector;
use crate::proxy::Proxy;
use crate::session::{DisconnectInterest, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;

/// Long-lived inputs for the CredSSP MITM + forward phase.
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

/// Streams and keys collected after TLS upgrade, ready for CredSSP.
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

    /// Run both CredSSP legs, fix Connect Confirm, then forward RDP-TLS.
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

        let client_credssp_fut = perform_credssp_as_server(
            &mut client_framed,
            client_addr,
            gateway_public_key,
            client_security_protocol,
            &credential_injection,
            &kdc_connector,
        );

        let server_credssp_fut = perform_credssp_as_client(
            &mut server_framed,
            server_dns_name,
            server_public_key,
            server_security_protocol,
            &credential_injection,
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
            .context("RDP-TLS traffic proxying failed")?;

        Ok(())
    }
}

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

fn server_kerberos_setup(
    client_addr: SocketAddr,
    injection: &CredentialInjection,
) -> anyhow::Result<(Option<sspi::KerberosServerConfig>, Option<&CredentialInjectionKdc>)> {
    let Some(kerberos) = injection.as_kerberos() else {
        return Ok((None, None));
    };
    let synthetic = kerberos.synthetic_kdc();
    Ok((Some(synthetic.server_kerberos_config(client_addr)?), Some(synthetic)))
}

fn client_kerberos_config(
    injection: &CredentialInjection,
) -> anyhow::Result<Option<ironrdp_connector::credssp::KerberosConfig>> {
    let Some(kerberos) = injection.as_kerberos() else {
        return Ok(None);
    };
    // Target-leg Kerberos uses the same session destination as the synthetic KDC (association
    // `dst_hst`). conf.hostname is Gateway identity only and is not the RDP destination.
    Ok(Some(ironrdp_connector::credssp::KerberosConfig {
        kdc_proxy_url: Some(kerberos.target_kdc().clone()),
        hostname: kerberos.synthetic_kdc().target_hostname().to_owned(),
    }))
}

#[instrument(name = "server_credssp", level = "debug", ret, skip_all)]
async fn perform_credssp_as_client<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    server_name: String,
    server_public_key: Vec<u8>,
    security_protocol: nego::SecurityProtocol,
    injection: &CredentialInjection,
    kdc_connector: &KdcConnector,
) -> anyhow::Result<()>
where
    S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
{
    use ironrdp_tokio::FramedWrite as _;

    let credentials = injection.target_credential();
    let kerberos_config = client_kerberos_config(injection)?;

    let (username, decrypted_password) = credentials
        .decrypt_password()
        .context("failed to decrypt credentials")?;

    // TODO: Pass a zeroizing password type once ironrdp-connector accepts one, so this temporary
    // plaintext allocation is cleared before release.
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
    credential_injection_kdc: Option<&CredentialInjectionKdc>,
    kdc_connector: &KdcConnector,
) -> Result<sspi::credssp::ServerState, sspi::credssp::ServerError> {
    let mut state = generator.start();

    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let kdc = credential_injection_kdc.ok_or_else(|| sspi::credssp::ServerError {
                    ts_request: None,
                    error: sspi::Error::new(
                        sspi::ErrorKind::InternalError,
                        "Kerberos CredSSP generator requires a synthetic KDC",
                    ),
                })?;
                let response = match kdc.intercept_network_request(&request) {
                    Ok(CredentialInjectionKdcInterception::Intercepted(response)) => Ok(response),
                    Ok(CredentialInjectionKdcInterception::NotInjectionRequest) => {
                        kdc_connector.send_network_request(&request).await
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
                break Ok(client_state.map_err(|e| {
                    ironrdp_connector::ConnectorError::new("CredSSP", ironrdp_connector::ConnectorErrorKind::Credssp(e))
                })?);
            }
        };
    }
}

#[instrument(name = "client_credssp", level = "debug", ret, skip_all)]
async fn perform_credssp_as_server<S>(
    framed: &mut ironrdp_tokio::Framed<S>,
    client_addr: SocketAddr,
    gateway_public_key: Vec<u8>,
    security_protocol: nego::SecurityProtocol,
    injection: &CredentialInjection,
    kdc_connector: &KdcConnector,
) -> anyhow::Result<()>
where
    S: ironrdp_tokio::FramedRead + ironrdp_tokio::FramedWrite,
{
    use ironrdp_connector::sspi::credssp::EarlyUserAuthResult;
    use ironrdp_tokio::FramedWrite as _;

    let mut buf = ironrdp_pdu::WriteBuf::new();

    // Are we supposed to use the actual computer name of the client?
    // But this does not seem to matter so far, so we stringify the IP address of the client instead.
    let client_computer_name = ironrdp_connector::ServerName::new(client_addr.ip().to_string());

    let (kerberos_server_config, synthetic_kdc) = server_kerberos_setup(client_addr, injection)?;
    let credentials = injection.proxy_credential();

    let result = credssp_loop(
        framed,
        &mut buf,
        client_computer_name,
        gateway_public_key,
        credentials,
        kerberos_server_config,
        synthetic_kdc,
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

    return result;

    #[expect(
        clippy::too_many_arguments,
        reason = "CredSSP loop needs framed IO, identity, optional synthetic KDC, and KdcConnector together"
    )]
    async fn credssp_loop<S>(
        framed: &mut ironrdp_tokio::Framed<S>,
        buf: &mut ironrdp_pdu::WriteBuf,
        client_computer_name: ironrdp_connector::ServerName,
        public_key: Vec<u8>,
        credentials: &AppCredential,
        kerberos_server_config: Option<sspi::KerberosServerConfig>,
        credential_injection_kdc: Option<&CredentialInjectionKdc>,
        kdc_connector: &KdcConnector,
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
                resolve_server_generator(&mut generator, credential_injection_kdc, kdc_connector).await
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

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use uuid::Uuid;

    use super::*;
    use crate::credential::{CleartextAppCredential, CleartextAppCredentialMapping};
    use crate::credential_injection::{CredentialInjection, SyntheticKdcRegistry};
    use crate::provisioning::ProvisioningStore;
    use crate::target_connection_options::TargetConnectionOptions;

    fn association_token(jti: Uuid) -> String {
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(r#"{"alg":"RS256"}"#);
        let payload = engine.encode(
            serde_json::to_vec(&serde_json::json!({
                "jti": jti,
                "dst_hst": "target.example:3389",
                "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 3600
            }))
            .expect("payload serializes"),
        );
        let signature = engine.encode(b"signature");
        format!("{header}.{payload}.{signature}")
    }

    fn kerberos_injection() -> CredentialInjection {
        let jti = Uuid::new_v4();
        let store = ProvisioningStore::new();
        store
            .insert_credentials(
                association_token(jti),
                Some(CleartextAppCredentialMapping {
                    proxy: CleartextAppCredential::UsernamePassword {
                        username: "proxy@example.invalid".to_owned(),
                        password: SecretString::from("pwd"),
                    },
                    target: CleartextAppCredential::UsernamePassword {
                        username: "administrator@example.invalid".to_owned(),
                        password: SecretString::from("pwd"),
                    },
                }),
                time::Duration::minutes(5),
            )
            .expect("credentials");
        let options = TargetConnectionOptions::new(Some("tcp://dc.example.com:88")).expect("kdc");
        store.insert_connection_options(jti, options, time::Duration::minutes(5));
        let entry = store.take(jti).expect("entry");
        CredentialInjection::from_provisioned(jti, entry, true)
            .expect("prepared")
            .register_if_kerberos(&SyntheticKdcRegistry::new(), 1)
    }

    #[test]
    fn client_kerberos_config_uses_provisioned_target_kdc_url_and_dst_hst() {
        let injection = kerberos_injection();
        let config = client_kerberos_config(&injection)
            .expect("config builds")
            .expect("kerberos client leg");

        assert_eq!(
            config.kdc_proxy_url.as_ref().map(url::Url::as_str),
            Some("tcp://dc.example.com:88"),
            "CredSSP kdc_proxy_url must be the provisioned krb_kdc",
        );
        assert_eq!(
            config.hostname, "target.example",
            "target-leg Kerberos hostname is association dst_hst, not conf.hostname",
        );
    }

    #[test]
    fn client_kerberos_config_is_none_for_ntlm() {
        let jti = Uuid::new_v4();
        let store = ProvisioningStore::new();
        store
            .insert_credentials(
                association_token(jti),
                Some(CleartextAppCredentialMapping {
                    proxy: CleartextAppCredential::UsernamePassword {
                        username: "proxy@example.invalid".to_owned(),
                        password: SecretString::from("pwd"),
                    },
                    target: CleartextAppCredential::UsernamePassword {
                        username: "Administrator".to_owned(),
                        password: SecretString::from("pwd"),
                    },
                }),
                time::Duration::minutes(5),
            )
            .expect("credentials");
        let entry = store.take(jti).expect("entry");
        let injection = CredentialInjection::from_provisioned(jti, entry, true)
            .expect("ntlm prepared")
            .register_if_kerberos(&SyntheticKdcRegistry::new(), 1);

        let config = client_kerberos_config(&injection).expect("ntlm ok");
        assert!(config.is_none());
    }
}
