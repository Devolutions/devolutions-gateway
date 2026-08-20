use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use ironrdp_pdu::nego;
use ironrdp_rdcleanpath::RDCleanPathPdu;
use ironrdp_rdcleanpath::der::asn1::OctetString;
use tap::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tracing::field;

/// MS-RDPEPS upper bound for transmitting the complete Preconnection Blob after TCP connect.
const PCB_TRANSMIT_DEADLINE: Duration = Duration::from_secs(10);

use crate::config::Conf;
use crate::credential_injection::{CredentialInjection, SyntheticKdcRegistry};
use crate::provisioning::{MappingStatus, ProvisioningStore};
use crate::proxy::Proxy;
use crate::recording::ActiveRecordings;
use crate::session::{ConnectionModeDetails, DisconnectInterest, DisconnectedInfo, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::target_addr::TargetAddr;
use crate::token::{AssociationTokenClaims, CurrentJrl, TokenCache, TokenError};
use crate::upstream::{self, ConnectedUpstream, UpstreamLeg};

#[derive(Debug, Error)]
enum AuthorizationError {
    #[error("token not allowed")]
    Forbidden,
    #[error("token missing from request")]
    Unauthorized,
    #[error("bad token")]
    BadToken(#[from] TokenError),
}

fn authorize(
    source_addr: SocketAddr,
    token: &str,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    active_recordings: &ActiveRecordings,
    disconnected_info: Option<DisconnectedInfo>,
) -> Result<AssociationTokenClaims, AuthorizationError> {
    use crate::token::AccessTokenClaims;

    if let AccessTokenClaims::Association(claims) = crate::middleware::auth::authenticate(
        source_addr,
        token,
        conf,
        token_cache,
        jrl,
        active_recordings,
        disconnected_info,
    )? {
        Ok(claims)
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

async fn send_clean_path_response(
    stream: &mut (dyn AsyncWrite + Unpin + Send),
    rd_clean_path_rsp: &RDCleanPathPdu,
) -> anyhow::Result<()> {
    let rd_clean_path_rsp = rd_clean_path_rsp.to_der().context("RDCleanPath DER conversion")?;

    stream.write_all(&rd_clean_path_rsp).await?;
    stream.flush().await?;

    Ok(())
}

async fn read_cleanpath_pdu(mut stream: impl AsyncRead + Unpin + Send) -> io::Result<RDCleanPathPdu> {
    let mut buf = bytes::BytesMut::new();

    // TODO: check if there is code to be reused from ironrdp code base for that
    loop {
        if let ironrdp_rdcleanpath::DetectionResult::Detected { total_length, .. } = RDCleanPathPdu::detect(&buf) {
            match buf.len().cmp(&total_length) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => break,
                std::cmp::Ordering::Greater => {
                    return Err(io::Error::other("no leftover is expected when reading cleanpath PDU"));
                }
            }
        }

        let n = stream.read_buf(&mut buf).await?;

        if n == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "EOF when reading RDCleanPathPdu",
            ));
        }
    }

    let rdcleanpath = RDCleanPathPdu::from_der(&buf)
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("bad RDCleanPathPdu: {e}")))?;

    Ok(rdcleanpath)
}

async fn read_x224_response(mut stream: impl AsyncRead + Unpin + Send) -> anyhow::Result<Vec<u8>> {
    const INITIAL_SIZE: usize = 19; // X224 Connection Confirm PDU size is 19 bytes, but…
    const MAX_READ_SIZE: usize = 512; // just in case, we allow this buffer to grow and receive more data

    let mut buf = vec![0; INITIAL_SIZE];
    let mut filled_end = 0;

    // TODO: check if there is code to be reused from ironrdp code base for that
    loop {
        if let Some(info) = ironrdp_pdu::find_size(&buf[..filled_end]).context("find PDU size")? {
            match filled_end.cmp(&info.length) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    buf.truncate(filled_end);
                    return Ok(buf);
                }
                std::cmp::Ordering::Greater => {
                    anyhow::bail!("received too much");
                }
            }
        }

        // Resize buffer if more space is necessary
        if filled_end == buf.len() {
            if buf.len() >= MAX_READ_SIZE {
                anyhow::bail!("X224 response too large (max allowed: {})", MAX_READ_SIZE);
            }

            buf.resize(MAX_READ_SIZE, 0);
        }

        let n = stream.read(&mut buf[filled_end..]).await.context("stream read")?;

        if n == 0 {
            anyhow::bail!("EOF when reading RDCleanPathPdu");
        }

        filled_end += n;
    }
}

#[derive(Debug, Error)]
enum CleanPathError {
    #[error("bad request")]
    BadRequest(#[source] anyhow::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
    #[error("TLS handshake with server {target_server} ({server_addr}) failed")]
    TlsHandshake {
        source: io::Error,
        target_server: TargetAddr,
        server_addr: SocketAddr,
    },
    #[error("authorization error")]
    Authorization(#[from] AuthorizationError),
    #[error("generic IO error")]
    Io(#[from] io::Error),
}

// Upstream transport (TCP or agent-tunnel) comes from `crate::upstream::UpstreamLeg`,
// which is also used by fwd.rs and generic_client.rs.

struct CleanPathAuth {
    claims: AssociationTokenClaims,
}

/// Validate the RDCleanPath PDU token and authorize the session.
/// Pure validation — no connections established.
async fn authorize_cleanpath(
    cleanpath_pdu: &RDCleanPathPdu,
    client_addr: SocketAddr,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    active_recordings: &ActiveRecordings,
    sessions: &SessionMessageSender,
) -> Result<CleanPathAuth, CleanPathError> {
    let token = cleanpath_pdu
        .proxy_auth
        .as_deref()
        .ok_or(CleanPathError::Authorization(AuthorizationError::Unauthorized))?;

    let disconnected_info = if let Ok(session_id) = crate::token::extract_session_id(token) {
        sessions.get_disconnected_info(session_id).await.ok().flatten()
    } else {
        None
    };

    trace!("Authorizing session");

    let claims = authorize(
        client_addr,
        token,
        conf,
        token_cache,
        jrl,
        active_recordings,
        disconnected_info,
    )?;

    let crate::token::ConnectionMode::Fwd { ref targets, .. } = claims.jet_cm else {
        return anyhow::Error::msg("unexpected connection mode")
            .pipe(CleanPathError::BadRequest)
            .pipe(Err);
    };

    let span = tracing::Span::current();
    span.record("session_id", claims.jet_aid.to_string());

    // Sanity check destination in PDU vs token.
    match cleanpath_pdu.destination.as_deref() {
        Some(destination) => match TargetAddr::parse(destination, 3389) {
            Ok(destination) if !destination.eq(targets.first()) => {
                warn!(%destination, "Destination in RDCleanPath PDU does not match destination in token");
            }
            Ok(_) => {}
            Err(error) => {
                warn!(%error, "Invalid destination field in RDCleanPath PDU");
            }
        },
        None => warn!("RDCleanPath PDU is missing the destination field"),
    }

    Ok(CleanPathAuth { claims })
}

struct ConnectedRdpServer {
    tls_stream: tokio_rustls::client::TlsStream<UpstreamLeg>,
    server_addr: SocketAddr,
    selected_target: TargetAddr,
    x224_rsp: Option<Vec<u8>>,
}

/// Explicit VMConnect request: no X.224 and a non-empty Unicode PCB V2 payload.
///
/// Matches IronRDP `RDCleanPathMessage::VmConnectRequest` / `new_vmconnect_request`.
fn is_vmconnect_request(cleanpath_pdu: &RDCleanPathPdu) -> bool {
    cleanpath_pdu.x224_connection_pdu.is_none()
        && cleanpath_pdu
            .preconnection_blob
            .as_ref()
            .is_some_and(|pcb| !pcb.trim().is_empty())
}

/// Encode the Hyper-V PCB V2 that the proxy writes before TLS.
///
/// `payload` is the opaque Unicode string from RDCleanPath (`GUID` or `GUID;EnhancedMode=1`).
///
/// Encoded locally rather than via `ironrdp-pdu` 0.9.0: that crates.io release counts `cchPCB`
/// with `chars().count()`, which under-counts non-BMP code points (UTF-16 surrogates). IronRDP
/// master fixed this to `encode_utf16().count()` but has not published a crates.io bump yet, and
/// its MSRV is ahead of Gateway. Match the fixed wire shape here so opaque Unicode payloads stay
/// well-formed.
fn encode_vmconnect_pcb_v2(payload: String) -> anyhow::Result<Vec<u8>> {
    // PCB V2 layout (little-endian):
    // cbSize u32 | flags u32 | version u32 | id u32 | cchPCB u16 | wszPCB UTF-16LE + NUL
    const FIXED_PART_SIZE: usize =
        4 /* cbSize */ + 4 /* flags */ + 4 /* version */ + 4 /* id */;
    const VERSION_V2: u32 = 2;

    let utf16: Vec<u16> = payload.encode_utf16().chain(core::iter::once(0)).collect();
    let cch_pcb = u16::try_from(utf16.len()).context("VMConnect PCB payload too long")?;
    let utf16_byte_len = utf16.len().checked_mul(2).context("VMConnect PCB payload too long")?;
    let total_size = FIXED_PART_SIZE
        .checked_add(2 /* cchPCB */)
        .and_then(|n| n.checked_add(utf16_byte_len))
        .context("VMConnect PCB payload too long")?;
    let cb_size = u32::try_from(total_size).context("VMConnect PCB payload too long")?;

    let mut out = Vec::with_capacity(total_size);
    out.extend_from_slice(&cb_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&VERSION_V2.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // id
    out.extend_from_slice(&cch_pcb.to_le_bytes());
    for unit in utf16 {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    debug_assert_eq!(out.len(), total_size);
    Ok(out)
}

/// Cert-chain-only success response after VMConnect PCB + TLS (no X.224).
///
/// Wire-compatible with IronRDP `RDCleanPathMessage::VmConnectResponse`.
fn build_vmconnect_response(
    server_addr: String,
    x509_chain: impl IntoIterator<Item = Vec<u8>>,
) -> anyhow::Result<RDCleanPathPdu> {
    Ok(RDCleanPathPdu {
        version: ironrdp_rdcleanpath::VERSION_1,
        server_cert_chain: Some(
            x509_chain
                .into_iter()
                .map(OctetString::new)
                .collect::<Result<_, _>>()
                .context("build VMConnect RDCleanPath cert chain")?,
        ),
        server_addr: Some(server_addr),
        ..RDCleanPathPdu::default()
    })
}

/// Establish a connection to the RDP server and perform the requested front sequence.
///
/// The routing pipeline (explicit agent → subnet/domain match → direct) is shared with
/// the WebSocket forwarders in [`crate::upstream`]; here we just do the RDP-specific
/// ordinary PCB + X224 + TLS or VMConnect PCB + TLS upgrade on top of whatever leg that returns.
///
/// VMConnect is detected from the existing VERSION_1 fields: X.224 absent and a non-empty
/// `preconnection_blob` (Unicode PCB V2 payload). No IronRDP message-helper dependency.
async fn connect_rdp_server(
    claims: &AssociationTokenClaims,
    cleanpath_pdu: RDCleanPathPdu,
    agent_tunnel_handle: Option<&Arc<agent_tunnel::AgentTunnelHandle>>,
) -> Result<ConnectedRdpServer, CleanPathError> {
    let crate::token::ConnectionMode::Fwd { ref targets, .. } = claims.jet_cm else {
        return anyhow::Error::msg("unexpected connection mode")
            .pipe(CleanPathError::BadRequest)
            .pipe(Err);
    };

    trace!(?targets, "Connecting to destination server");

    let ConnectedUpstream {
        leg: mut server_stream,
        server_addr,
        selected_target,
    } = upstream::connect_upstream(
        targets,
        claims.jet_agent_id,
        claims.jet_aid,
        agent_tunnel_handle.map(AsRef::as_ref),
    )
    .await
    .context("connect to RDP server")
    .map_err(CleanPathError::Internal)?;

    debug!(%selected_target, "Connected to destination server");
    tracing::Span::current().record("target", selected_target.to_string());

    // MS-RDPEPS: complete the PCB write within 10s of TCP connect. Bound the front write(s)
    // from this point so a stalled tunnel/target cannot hold the PCB open indefinitely.
    let front_deadline = tokio::time::Instant::now() + PCB_TRANSMIT_DEADLINE;

    let x224_rsp = if is_vmconnect_request(&cleanpath_pdu) {
        // Client sent Unicode PCB payload only; proxy encodes binary PCB V2 and skips X.224.
        let pcb_payload = cleanpath_pdu
            .preconnection_blob
            .context("VMConnect request missing preconnection_blob")
            .map_err(CleanPathError::BadRequest)?;
        let pcb = encode_vmconnect_pcb_v2(pcb_payload).map_err(CleanPathError::BadRequest)?;
        debug!(pcb_len = pcb.len(), "Writing encoded VMConnect PCB before TLS");
        tokio::time::timeout_at(front_deadline, async {
            server_stream.write_all(&pcb).await?;
            // Ensure the Hyper-V listener sees the PCB before ClientHello is queued
            // (especially on agent-tunnel legs that may buffer).
            server_stream.flush().await
        })
        .await
        .map_err(|_| {
            CleanPathError::Io(io::Error::new(
                ErrorKind::TimedOut,
                "timed out writing VMConnect preconnection blob",
            ))
        })??;
        None
    } else {
        // Ordinary: optional legacy complete PCB bytes, then X.224 CR/CC, then TLS.
        tokio::time::timeout_at(front_deadline, async {
            if let Some(pcb) = cleanpath_pdu.preconnection_blob {
                server_stream.write_all(pcb.as_bytes()).await?;
            }

            let x224_req = cleanpath_pdu
                .x224_connection_pdu
                .context("request is missing X224 connection PDU")
                .map_err(CleanPathError::BadRequest)?;
            server_stream.write_all(x224_req.as_bytes()).await?;
            server_stream.flush().await?;
            Ok::<_, CleanPathError>(())
        })
        .await
        .map_err(|_| {
            CleanPathError::Io(io::Error::new(
                ErrorKind::TimedOut,
                "timed out writing RDCleanPath front sequence",
            ))
        })??;

        trace!("Receiving X224 response");

        Some(
            read_x224_response(&mut server_stream)
                .await
                .with_context(|| format!("read X224 response from {selected_target}"))
                .map_err(CleanPathError::BadRequest)?,
        )
    };

    trace!("Establishing TLS connection with server");

    // Carry the resolved peer address in the error (and thus the top-level error log): the error
    // otherwise only has the target hostname, but the actual IP tells a wrong/split-horizon DNS
    // resolution apart from a target-side issue during the TLS handshake.
    let tls_stream = crate::tls::dangerous_connect(selected_target.host().to_owned(), server_stream)
        .await
        .map_err(|source| CleanPathError::TlsHandshake {
            source,
            target_server: selected_target.clone(),
            server_addr,
        })?;

    Ok(ConnectedRdpServer {
        tls_stream,
        server_addr,
        selected_target,
        x224_rsp,
    })
}

/// Handle RDP connection with credential injection via CredSSP MITM.
#[expect(clippy::too_many_arguments)]
async fn handle_with_credential_injection(
    mut client_stream: impl AsyncRead + AsyncWrite + Unpin + Send,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    cleanpath_pdu: RDCleanPathPdu,
    claims: AssociationTokenClaims,
    provisioning: &ProvisioningStore,
    synthetic_kdc_registry: &SyntheticKdcRegistry,
    agent_tunnel_handle: Option<Arc<agent_tunnel::AgentTunnelHandle>>,
) -> anyhow::Result<()> {
    let tls_conf = conf.credssp_tls.get().context("CredSSP TLS configuration")?;
    let gateway_hostname = conf.hostname.clone();

    let x224_req = cleanpath_pdu
        .x224_connection_pdu
        .as_ref()
        .context("request is missing X224 connection request PDU")?;
    let received_connection_request: ironrdp_pdu::x224::X224<nego::ConnectionRequest> =
        ironrdp_core::decode(x224_req.as_bytes()).context("decode X224 connection request PDU from client")?;

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

    let token = cleanpath_pdu
        .proxy_auth
        .clone()
        .context("missing token in RDCleanPath PDU")?;

    let ConnectedRdpServer {
        tls_stream: server_stream,
        server_addr,
        selected_target: destination,
        x224_rsp,
    } = connect_rdp_server(&claims, cleanpath_pdu, agent_tunnel_handle.as_ref())
        .await
        .context("RDCleanPath connection failed")?;
    let x224_rsp = x224_rsp.context("RDCleanPath credential injection requires X.224")?;

    let kerberos_enabled = crate::credential_injection::kerberos_injection_opt_in(
        conf.debug.enable_unstable,
        conf.debug.kerberos_credential_injection,
    );
    let credential_injection = CredentialInjection::checkout(
        provisioning,
        synthetic_kdc_registry,
        claims.jti,
        &token,
        kerberos_enabled,
    )?;

    let gateway_cert_chain_handle = tokio::spawn(crate::tls::get_cert_chain_for_acceptor_cached(
        gateway_hostname,
        tls_conf.acceptor.clone(),
    ));

    let x224_confirm: ironrdp_pdu::x224::X224<nego::ConnectionConfirm> =
        ironrdp_core::decode(&x224_rsp).context("decode X224 connection confirm")?;
    let server_security_protocol = match &x224_confirm.0 {
        nego::ConnectionConfirm::Response { protocol, .. } => {
            if !protocol.intersects(nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX) {
                anyhow::bail!(
                    "server selected security protocol {protocol}, which is not supported for credential injection"
                );
            }
            *protocol
        }
        nego::ConnectionConfirm::Failure { code } => {
            anyhow::bail!("RDP session initiation failed with code {code}");
        }
    };

    let server_public_key =
        crate::tls::extract_stream_peer_public_key(&server_stream).context("extract target server TLS public key")?;

    let gateway_cert_chain = gateway_cert_chain_handle.await??;
    let gateway_public_key = crate::tls::extract_public_key(gateway_cert_chain.first().context("no leaf")?)
        .context("extract Gateway public key")?;

    // Client CredSSP runs against the Gateway certificate chain.
    trace!("Sending RDCleanPath response");
    let rd_clean_path_rsp = RDCleanPathPdu::new_response(
        server_addr.to_string(),
        x224_rsp,
        gateway_cert_chain.iter().map(|cert| cert.to_vec()),
    )
    .context("couldn't build RDCleanPath response")?;
    send_clean_path_response(&mut client_stream, &rd_clean_path_rsp).await?;
    debug!("RDCleanPath response sent, starting CredSSP MITM");

    let info = SessionInfo::builder()
        .id(claims.jet_aid)
        .application_protocol(claims.jet_ap)
        .details(ConnectionModeDetails::Fwd {
            destination_host: destination.clone(),
        })
        .time_to_live(claims.jet_ttl)
        .recording_policy(claims.jet_rec)
        .filtering_policy(claims.jet_flt)
        .build();

    let disconnect_interest = DisconnectInterest::from_reconnection_policy(claims.jet_reuse);
    let kdc_connector =
        crate::kdc_connector::KdcConnector::new(claims.jet_aid, claims.jet_agent_id, agent_tunnel_handle.clone());

    let session = crate::rdp_proxy::CredsspSession::builder()
        .conf(conf)
        .session_info(info)
        .client_addr(client_addr)
        .server_addr(server_addr)
        .credential_injection(credential_injection)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .server_dns_name(destination.host().to_owned())
        .disconnect_interest(disconnect_interest)
        .kdc_connector(kdc_connector)
        .build();

    let prepared = crate::rdp_proxy::PreparedCredssp::builder()
        .client_stream(client_stream)
        .server_stream(server_stream)
        .gateway_public_key(gateway_public_key)
        .server_public_key(server_public_key)
        .client_security_protocol(client_security_protocol)
        .server_security_protocol(server_security_protocol)
        .build();

    session.run(prepared).await
}

#[expect(clippy::too_many_arguments)]
#[instrument("fwd", skip_all, fields(session_id = field::Empty, target = field::Empty))]
pub async fn handle(
    mut client_stream: impl AsyncRead + AsyncWrite + Unpin + Send,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    active_recordings: &ActiveRecordings,
    provisioning: &ProvisioningStore,
    synthetic_kdc_registry: &SyntheticKdcRegistry,
    agent_tunnel_handle: Option<Arc<agent_tunnel::AgentTunnelHandle>>,
) -> anyhow::Result<()> {
    // Special handshake of our RDP extension

    trace!("Reading RDCleanPath");

    let cleanpath_pdu = read_cleanpath_pdu(&mut client_stream)
        .await
        .context("couldn't read cleanpath PDU")?;

    let auth = match authorize_cleanpath(
        &cleanpath_pdu,
        client_addr,
        &conf,
        token_cache,
        jrl,
        active_recordings,
        &sessions,
    )
    .await
    {
        Ok(auth) => auth,
        Err(error) => {
            let response = RDCleanPathPdu::from(&error);
            send_clean_path_response(&mut client_stream, &response).await?;
            return anyhow::Error::new(error)
                .context("an error occurred when processing cleanpath PDU")
                .pipe(Err)?;
        }
    };

    let mapping_status = provisioning.mapping_status(auth.claims.jti);
    if is_vmconnect_request(&cleanpath_pdu)
        && matches!(
            mapping_status,
            MappingStatus::Available | MappingStatus::RequiredMissing
        )
    {
        let response = RDCleanPathPdu::new_http_error(400);
        send_clean_path_response(&mut client_stream, &response).await?;
        anyhow::bail!("credential injection is not supported for VMConnect RDCleanPath");
    }

    match mapping_status {
        MappingStatus::Available => {
            debug!(jti = %auth.claims.jti, "Switching to RdpProxy for credential injection (WebSocket)");
            return handle_with_credential_injection(
                client_stream,
                client_addr,
                conf,
                sessions,
                subscriber_tx,
                cleanpath_pdu,
                auth.claims,
                provisioning,
                synthetic_kdc_registry,
                agent_tunnel_handle.clone(),
            )
            .await;
        }
        MappingStatus::RequiredMissing => {
            let error = CleanPathError::BadRequest(anyhow::anyhow!(
                "credential-injection material for {} is missing or expired; re-provision to retry",
                auth.claims.jti
            ));
            let response = RDCleanPathPdu::from(&error);
            send_clean_path_response(&mut client_stream, &response).await?;
            return anyhow::Error::new(error)
                .context("an error occurred when processing cleanpath PDU")
                .pipe(Err)?;
        }
        MappingStatus::Absent => {}
    }

    trace!("Processing RDCleanPath");

    let connected = match connect_rdp_server(&auth.claims, cleanpath_pdu, agent_tunnel_handle.as_ref()).await {
        Ok(connected) => connected,
        Err(error) => {
            let response = RDCleanPathPdu::from(&error);
            send_clean_path_response(&mut client_stream, &response).await?;
            return anyhow::Error::new(error)
                .context("an error occurred when processing cleanpath PDU")
                .pipe(Err)?;
        }
    };

    let ConnectedRdpServer {
        tls_stream: server_stream,
        server_addr,
        selected_target: destination,
        x224_rsp,
    } = connected;

    // == Send success RDCleanPathPdu response ==

    let x509_chain = server_stream
        .get_ref()
        .1
        .peer_certificates()
        .context("no peer certificate found in TLS transport")?
        .iter()
        .map(|cert| cert.to_vec());

    trace!("Sending RDCleanPath response");

    // Ordinary responses include X.224 CC. VMConnect responses are cert-chain only; the client
    // runs CredSSP then X.224 on the upgraded path.
    let rdcleanpath_rsp = if let Some(x224_rsp) = x224_rsp {
        RDCleanPathPdu::new_response(server_addr.to_string(), x224_rsp, x509_chain)
            .context("build RDCleanPath response")?
    } else {
        build_vmconnect_response(server_addr.to_string(), x509_chain).context("build VMConnect RDCleanPath response")?
    };

    send_clean_path_response(&mut client_stream, &rdcleanpath_rsp).await?;

    // == Start actual RDP session ==

    let info = SessionInfo::builder()
        .id(auth.claims.jet_aid)
        .application_protocol(auth.claims.jet_ap)
        .details(ConnectionModeDetails::Fwd {
            destination_host: destination.clone(),
        })
        .time_to_live(auth.claims.jet_ttl)
        .recording_policy(auth.claims.jet_rec)
        .build();

    info!("RDP-TLS forwarding (RDCleanPath)");

    Proxy::builder()
        .conf(conf)
        .session_info(info)
        .address_a(client_addr)
        .transport_a(client_stream)
        .address_b(server_addr)
        .transport_b(server_stream)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
        .disconnect_interest(DisconnectInterest::from_reconnection_policy(auth.claims.jet_reuse))
        .build()
        .select_dissector_and_forward()
        .await
        .context("RDP-TLS traffic proxying failed")?;

    Ok(())
}

impl From<&CleanPathError> for RDCleanPathPdu {
    fn from(value: &CleanPathError) -> Self {
        match value {
            CleanPathError::BadRequest(_) => Self::new_http_error(400),
            CleanPathError::Internal(_) => Self::new_http_error(500),
            CleanPathError::TlsHandshake { source, .. } => io_to_rdcleanpath_err(source),
            CleanPathError::Io(e) => io_to_rdcleanpath_err(e),
            CleanPathError::Authorization(AuthorizationError::Forbidden) => Self::new_http_error(403),
            CleanPathError::Authorization(AuthorizationError::Unauthorized) => Self::new_http_error(401),
            CleanPathError::Authorization(AuthorizationError::BadToken(_)) => Self::new_http_error(401), // NOTE: this could be refined
        }
    }
}

fn io_to_rdcleanpath_err(err: &io::Error) -> RDCleanPathPdu {
    if let Some(tokio_rustls::rustls::Error::AlertReceived(tls_alert)) = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<tokio_rustls::rustls::Error>())
    {
        RDCleanPathPdu::new_tls_error(u8::from(*tls_alert))
    } else {
        RDCleanPathPdu::new_wsa_error(WsaError::from(err).as_u16())
    }
}

#[expect(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum WsaError {
    WSA_INVALID_HANDLE = 6,
    WSA_NOT_ENOUGH_MEMORY = 8,
    WSA_INVALID_PARAMATER = 87,
    WSA_OPERATION_ABORTED = 995,
    WSA_IO_INCOMPLETE = 996,
    WSA_IO_PENDING = 997,
    WSAEINTR = 10004,
    WSAEBADF = 10009,
    WSAEACCES = 10013,
    WSAEFAULT = 10014,
    WSAEINVAL = 10022,
    WSAEMFILE = 10024,
    WSAEWOULDBLOCK = 10035,
    WSAEINPROGRESS = 10036,
    WSAEALREADY = 10037,
    WSAENOTSOCK = 10038,
    WSAEDESTADDRREQ = 10039,
    WSAEMSGSIZE = 10040,
    WSAEPROTOTYPE = 10041,
    WSAENOPROTOOPT = 10042,
    WSAEPROTONOSUPPORT = 10043,
    WSAESOCKTNOSUPPORT = 10044,
    WSAEOPNOTSUPP = 10045,
    WSAEPFNOSUPPORT = 10046,
    WSAEAFNOSUPPORT = 10047,
    WSAEADDRINUSE = 10048,
    WSAEADDRNOTAVAIL = 10049,
    WSAENETDOWN = 10050,
    WSAENETUNREACH = 10051,
    WSAENETRESET = 10052,
    WSAECONNABORTED = 10053,
    WSAECONNRESET = 10054,
    WSAENOBUFS = 10055,
    WSAEISCONN = 10056,
    WSAENOTCONN = 10057,
    WSAESHUTDOWN = 10058,
    WSAETOOMANYREFS = 10059,
    WSAETIMEDOUT = 10060,
    WSAECONNREFUSED = 10061,
    WSAELOOP = 10062,
    WSAENAMETOOLONG = 10063,
    WSAEHOSTDOWN = 10064,
    WSAEHOSTUNREACH = 10065,
    WSAENOTEMPTY = 10066,
    WSAEPROCLIM = 10067,
    WSAEUSERS = 10068,
    WSAEDQUOT = 10069,
    WSAESTALE = 10070,
    WSAEREMOTE = 10071,
    WSASYSNOTREADY = 10091,
    WSAVERNOTSUPPORTED = 10092,
    WSANOTINITIALISED = 10093,
    WSAEDISCON = 10101,
    WSAENOMORE = 10102,
    WSAECANCELLED = 10103,
    WSAEINVALIDPROCTABLE = 10104,
    WSAEINVALIDPROVIDER = 10105,
    WSAEPROVIDERFAILEDINIT = 10106,
    WSASYSCALLFAILURE = 10107,
    WSASERVICE_NOT_FOUND = 10108,
    WSATYPE_NOT_FOUND = 10109,
    WSA_E_NO_MORE = 10110,
    WSA_E_CANCELLED = 10111,
    WSAEREFUSED = 10112,
    WSAHOST_NOT_FOUND = 11001,
    WSATRY_AGAIN = 11002,
    WSANO_RECOVERY = 11003,
    WSANO_DATA = 11004,
    WSA_QOS_RECEIVERS = 11005,
    WSA_QOS_SENDERS = 11006,
    WSA_QOS_NO_SENDERS = 11007,
    WSA_QOS_NO_RECEIVERS = 11008,
    WSA_QOS_REQUEST_CONFIRMED = 11009,
    WSA_QOS_ADMISSION_FAILURE = 11010,
    WSA_QOS_POLICY_FAILURE = 11011,
    WSA_QOS_BAD_STYLE = 11012,
    WSA_QOS_BAD_OBJECT = 11013,
    WSA_QOS_TRAFFIC_CTRL_ERROR = 11014,
    WSA_QOS_GENERIC_ERROR = 11015,
    WSA_QOS_ESERVICETYPE = 11016,
    WSA_QOS_EFLOWSPEC = 11017,
    WSA_QOS_EPROVSPECBUF = 11018,
    WSA_QOS_EFILTERSTYLE = 11019,
    WSA_QOS_EFILTERTYPE = 11020,
    WSA_QOS_EFILTERCOUNT = 11021,
    WSA_QOS_EOBJLENGTH = 11022,
    WSA_QOS_EFLOWCOUNT = 11023,
    WSA_QOS_EUNKOWNPSOBJ = 11024,
    WSA_QOS_EPOLICYOBJ = 11025,
    WSA_QOS_EFLOWDESC = 11026,
    WSA_QOS_EPSFLOWSPEC = 11027,
    WSA_QOS_EPSFILTERSPEC = 11028,
    WSA_QOS_ESDMODEOBJ = 11029,
    WSA_QOS_ESHAPERATEOBJ = 11030,
    WSA_QOS_RESERVED_PETYPE = 11031,
}

impl WsaError {
    pub(crate) fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<&io::Error> for WsaError {
    fn from(err: &io::Error) -> Self {
        match err.kind() {
            ErrorKind::OutOfMemory => WsaError::WSA_NOT_ENOUGH_MEMORY,
            ErrorKind::Interrupted => WsaError::WSAEINTR,
            ErrorKind::PermissionDenied => WsaError::WSAEACCES,
            ErrorKind::InvalidInput => WsaError::WSAEINVAL,
            ErrorKind::WouldBlock => WsaError::WSAEWOULDBLOCK,
            ErrorKind::Unsupported => WsaError::WSAEOPNOTSUPP,
            ErrorKind::AddrInUse => WsaError::WSAEADDRINUSE,
            ErrorKind::BrokenPipe => WsaError::WSAENETRESET,
            ErrorKind::ConnectionAborted => WsaError::WSAECONNABORTED,
            ErrorKind::ConnectionReset => WsaError::WSAECONNRESET,
            ErrorKind::NotConnected => WsaError::WSAENOTCONN,
            ErrorKind::TimedOut => WsaError::WSAETIMEDOUT,
            ErrorKind::ConnectionRefused => WsaError::WSAECONNREFUSED,
            // TODO: Currently unstable: https://github.com/rust-lang/rust/pull/106375#issuecomment-1371870620
            // Stabilized soon: https://github.com/rust-lang/rust/pull/106375
            // See also: https://github.com/rust-lang/rust/pull/106375#issuecomment-1371870620
            // ErrorKind::NetworkDown => WsaError::WSAENETDOWN,
            // ErrorKind::NetworkUnreachable => WsaError::WSAENETUNREACH,
            // ErrorKind::FilesystemLoop => WsaError::WSAELOOP,
            // ErrorKind::InvalidFilename => WsaError::WSAENAMETOOLONG,
            // ErrorKind::HostUnreachable => WsaError::WSAEHOSTUNREACH,
            // ErrorKind::DirectoryNotEmpty => WsaError::WSAENOTEMPTY,
            // ErrorKind::FilesystemQuotaExceeded => WsaError::WSAEDQUOT,
            // ErrorKind::StaleNetworkFileHandle => WsaError::WSAESTALE,
            _ => WsaError::WSA_QOS_GENERIC_ERROR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_x224() -> OctetString {
        OctetString::new(vec![0x03, 0x00, 0x00, 0x13]).expect("static X.224 bytes")
    }

    #[test]
    fn detects_vmconnect_when_pcb_payload_present_without_x224() {
        let pdu = RDCleanPathPdu {
            version: ironrdp_rdcleanpath::VERSION_1,
            destination: Some("10.10.0.3:2179".to_owned()),
            proxy_auth: Some("token".to_owned()),
            preconnection_blob: Some("21c82e1f-2368-43d5-9cb6-a7c99c449bba;EnhancedMode=1".to_owned()),
            ..RDCleanPathPdu::default()
        };
        assert!(is_vmconnect_request(&pdu));
    }

    #[test]
    fn ordinary_request_with_x224_is_not_vmconnect() {
        let pdu = RDCleanPathPdu {
            version: ironrdp_rdcleanpath::VERSION_1,
            destination: Some("10.10.0.3:3389".to_owned()),
            proxy_auth: Some("token".to_owned()),
            preconnection_blob: Some("legacy-pcb-bytes".to_owned()),
            x224_connection_pdu: Some(empty_x224()),
            ..RDCleanPathPdu::default()
        };
        assert!(!is_vmconnect_request(&pdu));
    }

    #[test]
    fn empty_or_whitespace_pcb_without_x224_is_not_vmconnect() {
        for pcb in [None, Some(String::new()), Some("   ".to_owned())] {
            let pdu = RDCleanPathPdu {
                version: ironrdp_rdcleanpath::VERSION_1,
                destination: Some("10.10.0.3:2179".to_owned()),
                proxy_auth: Some("token".to_owned()),
                preconnection_blob: pcb,
                ..RDCleanPathPdu::default()
            };
            assert!(!is_vmconnect_request(&pdu));
        }
    }

    #[test]
    fn encodes_enhanced_pcb_v2_matching_lab_size() {
        // Lab GUID with EnhancedMode; IronRDP observed 122-byte PCB on the wire.
        let payload = "21c82e1f-2368-43d5-9cb6-a7c99c449bba;EnhancedMode=1".to_owned();
        let bytes = encode_vmconnect_pcb_v2(payload.clone()).expect("encode");
        assert_eq!(bytes.len(), 122);

        let decoded: ironrdp_pdu::pcb::PreconnectionBlob = ironrdp_core::decode(&bytes).expect("decode round-trip");
        assert_eq!(decoded.id, 0);
        assert_eq!(decoded.version, ironrdp_pdu::pcb::PcbVersion::V2);
        assert_eq!(decoded.v2_payload.as_deref(), Some(payload.as_str()));
    }

    #[test]
    fn encodes_basic_pcb_v2_matching_lab_size() {
        let payload = "21c82e1f-2368-43d5-9cb6-a7c99c449bba".to_owned();
        let bytes = encode_vmconnect_pcb_v2(payload).expect("encode");
        assert_eq!(bytes.len(), 92);
    }

    #[test]
    fn encodes_non_bmp_payload_with_utf16_code_unit_cch() {
        // U+1F600 needs a UTF-16 surrogate pair (2 code units, 1 scalar).
        // crates.io ironrdp-pdu 0.9.0 would set cchPCB = chars+NUL = 5; correct is 6.
        let payload = "vm-\u{1F600}".to_owned();
        assert_eq!(payload.chars().count(), 4);
        assert_eq!(payload.encode_utf16().count(), 5);

        let bytes = encode_vmconnect_pcb_v2(payload.clone()).expect("encode");
        let cch = u16::from_le_bytes([bytes[16], bytes[17]]);
        assert_eq!(cch, 6, "cchPCB must count UTF-16 code units including NUL");
        assert_eq!(bytes.len(), 16 + 2 + usize::from(cch) * 2);

        let decoded: ironrdp_pdu::pcb::PreconnectionBlob = ironrdp_core::decode(&bytes).expect("decode round-trip");
        assert_eq!(decoded.v2_payload.as_deref(), Some(payload.as_str()));
    }

    #[test]
    fn vmconnect_response_has_cert_chain_without_x224() {
        let rsp = build_vmconnect_response("10.10.0.3:2179".to_owned(), [vec![0xDE, 0xAD], vec![0xBE, 0xEF]])
            .expect("build response");

        assert_eq!(rsp.version, ironrdp_rdcleanpath::VERSION_1);
        assert_eq!(rsp.server_addr.as_deref(), Some("10.10.0.3:2179"));
        assert!(rsp.x224_connection_pdu.is_none());
        assert_eq!(rsp.server_cert_chain.as_ref().map(|c| c.len()).unwrap_or(0), 2);
        assert!(rsp.error.is_none());
    }
}
