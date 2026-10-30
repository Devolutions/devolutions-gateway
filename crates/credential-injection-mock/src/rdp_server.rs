//! Fake RDP server that completes CredSSP as the target: X.224 accept, TLS, then an
//! sspi `CredSspServer` in Kerberos or NTLM mode.

use std::time::Duration;

use anyhow::Context as _;
use ironrdp_connector::sspi;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::x224::X224;
use ironrdp_tokio::{FramedWrite as _, TokioFramed};
use tokio::net::TcpStream;

use crate::client::TsRequestHint;
use crate::event::{Event, emit, report_error};
use crate::fixture::{KERBEROS_TARGET_USER, REALM, SERVICE_HOST, TARGET_PASSWORD, TARGET_USER, TERMSRV_KEY};
use crate::kdc::send_kdc_tcp;
use crate::rdp_target::{LocalhostListener, emit_cookie};
use crate::tls::{server_public_key, tls_acceptor};

#[derive(Clone)]
pub(crate) enum Auth {
    Kerberos { kdc_url: String },
    Ntlm,
}

pub(crate) async fn run(auth: Auth) -> anyhow::Result<()> {
    let listener = LocalhostListener::bind().await.context("bind mock RDP")?;
    let acceptor = tls_acceptor()?;
    let public_key = server_public_key()?;
    emit(&Event::Listening { port: listener.port()? });

    loop {
        let (stream, peer) = listener.accept().await.context("accept on mock RDP")?;
        let acceptor = acceptor.clone();
        let public_key = public_key.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let result = match &auth {
                Auth::Kerberos { kdc_url } => accept_kerberos_rdp(stream, peer, acceptor, public_key, kdc_url).await,
                Auth::Ntlm => accept_ntlm_rdp(stream, peer, acceptor, public_key).await,
            };
            if let Err(error) = result {
                report_error("mock RDP CredSSP failed", &error);
            }
        });
    }
}

async fn accept_kerberos_rdp(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    public_key: Vec<u8>,
    kdc_url: &str,
) -> anyhow::Result<()> {
    let mut framed = TokioFramed::new(stream);
    let (_, request) = framed.read_pdu().await.context("read X.224 CR")?;
    let cr: X224<ConnectionRequest> = ironrdp_core::decode(&request).context("decode X.224 CR")?;
    emit_cookie(&cr);

    let confirm = X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::HYBRID,
    });
    framed
        .write_all(&ironrdp_core::encode_vec(&confirm).context("encode X.224 CC")?)
        .await
        .context("write X.224 CC")?;

    let tcp = framed.into_inner_no_leftover();
    let tls = acceptor.accept(tcp).await.context("TLS accept")?;
    let mut framed = TokioFramed::new(tls);

    let identity = sspi::AuthIdentity {
        username: sspi::Username::parse(KERBEROS_TARGET_USER).context("parse target username")?,
        password: TARGET_PASSWORD.to_owned().into(),
    };
    let kerberos_config = sspi::KerberosServerConfig {
        kerberos_config: sspi::KerberosConfig {
            kdc_url: Some(kdc_url.parse().context("parse mock KDC URL")?),
            client_computer_name: peer.to_string(),
        },
        server_properties: sspi::kerberos::ServerProperties::new(
            &["TERMSRV", SERVICE_HOST],
            Some(sspi::CredentialsBuffers::AuthIdentity(
                sspi::AuthIdentityBuffers::from_utf8(identity.username.account_name(), REALM, TARGET_PASSWORD),
            )),
            Duration::from_secs(300),
            Some(sspi::Secret::new(TERMSRV_KEY.to_vec())),
        )
        .context("Kerberos server properties")?,
    };

    let mut server = sspi::credssp::CredSspServer::new(
        public_key,
        IdentityProxy(identity),
        sspi::credssp::ServerMode::Negotiate(sspi::NegotiateConfig::new(
            Box::new(kerberos_config),
            Some("kerberos,!ntlm".to_owned()),
            peer.to_string(),
        )),
    )
    .context("init Kerberos-only CredSSP server")?;

    let hint = TsRequestHint;
    let mut buf = ironrdp_pdu::WriteBuf::new();
    for _ in 0..6 {
        let pdu = framed.read_by_hint(&hint).await.context("read CredSSP TSRequest")?;
        let ts_request = sspi::credssp::TsRequest::from_buffer(&pdu).context("decode CredSSP")?;
        let result = {
            let mut generator = server.process(ts_request);
            resolve_sspi_server(&mut generator)
                .await
                .map_err(|error| anyhow::anyhow!("mock RDP CredSSP: {error:?}"))?
        };
        match result {
            sspi::credssp::ServerState::ReplyNeeded(outbound) => {
                buf.clear();
                let length = usize::from(outbound.buffer_len());
                outbound
                    .encode_ts_request(buf.unfilled_to(length))
                    .context("encode server TSRequest")?;
                buf.advance(length);
                framed.write_all(&buf[..length]).await.context("write CredSSP")?;
            }
            sspi::credssp::ServerState::Finished(identity) => {
                emit(&Event::CredsspFinished {
                    account: identity.username.account_name(),
                });
                return Ok(());
            }
        }
    }
    anyhow::bail!("mock RDP CredSSP exceeded 6 round trips")
}

async fn accept_ntlm_rdp(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    public_key: Vec<u8>,
) -> anyhow::Result<()> {
    let mut framed = TokioFramed::new(stream);
    let (_, request) = framed.read_pdu().await.context("read X.224 CR")?;
    let cr: X224<ConnectionRequest> = ironrdp_core::decode(&request).context("decode X.224 CR")?;
    emit_cookie(&cr);

    let confirm = X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::HYBRID,
    });
    framed
        .write_all(&ironrdp_core::encode_vec(&confirm).context("encode X.224 CC")?)
        .await
        .context("write X.224 CC")?;

    let tcp = framed.into_inner_no_leftover();
    let tls = acceptor.accept(tcp).await.context("TLS accept")?;
    let mut framed = TokioFramed::new(tls);

    let identity = sspi::AuthIdentity {
        username: sspi::Username::parse(TARGET_USER).context("parse NTLM target username")?,
        password: TARGET_PASSWORD.to_owned().into(),
    };
    let mut server = sspi::credssp::CredSspServer::new(
        public_key,
        IdentityProxy(identity),
        sspi::credssp::ServerMode::Ntlm(sspi::ntlm::NtlmConfig {
            client_computer_name: Some(peer.to_string()),
        }),
    )
    .context("init NTLM CredSSP server")?;

    let hint = TsRequestHint;
    let mut buf = ironrdp_pdu::WriteBuf::new();
    for _ in 0..6 {
        let pdu = framed.read_by_hint(&hint).await.context("read CredSSP TSRequest")?;
        let ts_request = sspi::credssp::TsRequest::from_buffer(&pdu).context("decode CredSSP")?;
        let result = {
            let mut generator = server.process(ts_request);
            resolve_sspi_server(&mut generator)
                .await
                .map_err(|error| anyhow::anyhow!("mock RDP NTLM CredSSP: {error:?}"))?
        };
        match result {
            sspi::credssp::ServerState::ReplyNeeded(outbound) => {
                buf.clear();
                let length = usize::from(outbound.buffer_len());
                outbound
                    .encode_ts_request(buf.unfilled_to(length))
                    .context("encode server TSRequest")?;
                buf.advance(length);
                framed.write_all(&buf[..length]).await.context("write CredSSP")?;
            }
            sspi::credssp::ServerState::Finished(identity) => {
                emit(&Event::CredsspFinished {
                    account: identity.username.account_name(),
                });
                return Ok(());
            }
        }
    }
    anyhow::bail!("mock RDP NTLM CredSSP exceeded 6 round trips")
}

async fn resolve_sspi_server(
    generator: &mut sspi::generator::Generator<
        '_,
        sspi::generator::NetworkRequest,
        sspi::Result<Vec<u8>>,
        Result<sspi::credssp::ServerState, sspi::credssp::ServerError>,
    >,
) -> Result<sspi::credssp::ServerState, sspi::credssp::ServerError> {
    let mut state = generator.start();
    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let reply = send_kdc_tcp(&request)
                    .await
                    .map_err(|error| sspi::credssp::ServerError {
                        ts_request: None,
                        error: sspi::Error::new(sspi::ErrorKind::NoAuthenticatingAuthority, error),
                    })?;
                state = generator.resume(Ok(reply));
            }
            GeneratorState::Completed(result) => break result,
        }
    }
}

struct IdentityProxy(sspi::AuthIdentity);

impl sspi::credssp::CredentialsProxy for IdentityProxy {
    type AuthenticationData = sspi::AuthIdentity;

    fn auth_data_by_user(&mut self, username: &sspi::Username) -> std::io::Result<Self::AuthenticationData> {
        if username.account_name() != self.0.username.account_name() {
            return Err(std::io::Error::other("invalid username"));
        }
        let mut data = self.0.clone();
        data.username = username.clone();
        Ok(data)
    }

    fn auth_data(&mut self) -> Result<Vec<Self::AuthenticationData>, std::io::Error> {
        Ok(vec![self.0.clone()])
    }
}
