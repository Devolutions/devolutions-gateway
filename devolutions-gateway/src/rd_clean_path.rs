use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::credential::CredentialStoreHandle;
use crate::proxy::Proxy;
use crate::recording::ActiveRecordings;
use crate::session::{ConnectionModeDetails, DisconnectInterest, DisconnectedInfo, SessionInfo, SessionMessageSender};
use crate::subscriber::SubscriberSender;
use crate::target_addr::TargetAddr;
use crate::token::{AssociationTokenClaims, CurrentJrl, TokenCache, TokenError};

use anyhow::Context as _;
use ironrdp_pdu::nego;
use ironrdp_rdcleanpath::RDCleanPathPdu;
use tap::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tracing::field;

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
    let rd_clean_path_rsp = rd_clean_path_rsp
        .to_der()
        .map_err(|e| anyhow::anyhow!("RDCleanPath DER conversion failure: {e}"))?;

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
    #[error("TLS handshake with server {target_server} failed")]
    TlsHandshake {
        source: io::Error,
        target_server: TargetAddr,
    },
    #[error("authorization error")]
    Authorization(#[from] AuthorizationError),
    #[error("generic IO error")]
    Io(#[from] io::Error),
}

struct CleanPathResult {
    claims: AssociationTokenClaims,
    destination: TargetAddr,
    server_addr: SocketAddr,
    server_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    x224_rsp: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
async fn process_cleanpath(
    cleanpath_pdu: RDCleanPathPdu,
    client_addr: SocketAddr,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    active_recordings: &ActiveRecordings,
    sessions: &SessionMessageSender,
    _credential_store: &CredentialStoreHandle,
) -> Result<CleanPathResult, CleanPathError> {
    use crate::utils;

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

    // Sanity check
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

    trace!(?targets, "Connecting to destination server");

    let ((mut server_stream, server_addr), selected_target) = utils::successive_try(targets, utils::tcp_connect)
        .await
        .context("couldn’t connect to RDP server")?;

    debug!(%selected_target, "Connected to destination server");
    span.record("target", selected_target.to_string());

    // Send preconnection blob if applicable
    if let Some(pcb) = cleanpath_pdu.preconnection_blob {
        server_stream.write_all(pcb.as_bytes()).await?;
    }

    // Send X224 connection request
    let x224_req = cleanpath_pdu
        .x224_connection_pdu
        .context("request is missing X224 connection PDU")
        .map_err(CleanPathError::BadRequest)?;
    server_stream.write_all(x224_req.as_bytes()).await?;

    // Receive server X224 connection response

    trace!("Receiving X224 response");

    let x224_rsp = read_x224_response(&mut server_stream)
        .await
        .with_context(|| format!("read X224 response from {selected_target}"))
        .map_err(CleanPathError::BadRequest)?;

    trace!("Establishing TLS connection with server");

    // Establish TLS connection with server

    let server_stream = crate::tls::dangerous_connect(selected_target.host().to_owned(), server_stream)
        .await
        .map_err(|source| CleanPathError::TlsHandshake {
            source,
            target_server: selected_target.to_owned(),
        })?;

    Ok(CleanPathResult {
        destination: selected_target.to_owned(),
        claims,
        server_addr,
        server_stream,
        x224_rsp,
    })
}

/// Handle RDP connection with credential injection via CredSSP MITM
#[allow(clippy::too_many_arguments)]
async fn handle_with_credential_injection(
    mut client_stream: impl AsyncRead + AsyncWrite + Unpin + Send + Sync,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    active_recordings: &ActiveRecordings,
    cleanpath_pdu: RDCleanPathPdu,
    token: String,
    _credential_entry: crate::credential::ArcCredentialEntry,
) -> anyhow::Result<()> {
    // Authorize the token
    let claims = authorize(client_addr, &token, &conf, token_cache, jrl, active_recordings, None)
        .map_err(|e| anyhow::anyhow!("authorization failed: {}", e))?;

    let crate::token::ConnectionMode::Fwd { targets: _ } = claims.jet_cm else {
        anyhow::bail!("unexpected connection mode");
    };

    let span = tracing::Span::current();
    span.record("session_id", claims.jet_aid.to_string());

    info!("Credential injection: performing CredSSP MITM");

    // Run normal RDCleanPath flow (this will handle server-side TLS and get certs)
    let CleanPathResult {
        destination,
        server_addr,
        server_stream,
        x224_rsp,
        ..
    } = process_cleanpath(
        cleanpath_pdu,
        client_addr,
        &conf,
        token_cache,
        jrl,
        active_recordings,
        &sessions,
        &CredentialStoreHandle::new(), // Dummy, not used in process_cleanpath
    )
    .await
    .map_err(|e| anyhow::anyhow!("RDCleanPath processing failed: {}", e))?;

    // Extract server security protocol from X224 response (before x224_rsp is moved)
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

    // Send RDCleanPath response to client (includes server certs)
    let x509_chain = server_stream
        .get_ref()
        .1
        .peer_certificates()
        .context("no peer certificate found in TLS transport")?
        .iter()
        .map(|cert| cert.to_vec());

    trace!("Sending RDCleanPath response");

    let rdcleanpath_rsp = RDCleanPathPdu::new_response(server_addr.to_string(), x224_rsp, x509_chain)
        .map_err(|e| anyhow::anyhow!("couldn't build RDCleanPath response: {e}"))?;

    send_clean_path_response(&mut client_stream, &rdcleanpath_rsp).await?;

    info!("RDCleanPath response sent, now performing CredSSP MITM");

    // Verify TLS is configured
    conf.tls.as_ref().context("TLS required for credential injection")?;

    // Get credential mapping
    let credential_mapping = _credential_entry.mapping.as_ref().context("no credential mapping")?;

    // Extract server public key from TLS stream
    let server_public_key =
        crate::rdp_proxy::extract_tls_server_public_key(&server_stream).context("extract server TLS public key")?;

    // Wrap streams in TokioFramed for CredSSP
    let mut client_framed = ironrdp_tokio::TokioFramed::new(client_stream);
    let mut server_framed = ironrdp_tokio::TokioFramed::new(server_stream);

    // Use HYBRID_EX for client (web clients typically use this)
    let client_security_protocol = nego::SecurityProtocol::HYBRID_EX;

    // Perform CredSSP MITM (in parallel)
    // Note: Client expects server's public key (since we sent server certs in RDCleanPath response)
    let client_credssp_fut = crate::rdp_proxy::perform_credssp_with_client(
        &mut client_framed,
        client_addr.ip(),
        server_public_key.clone(),
        client_security_protocol,
        &credential_mapping.proxy,
    );

    let server_credssp_fut = crate::rdp_proxy::perform_credssp_with_server(
        &mut server_framed,
        destination.host().to_owned(),
        server_public_key,
        server_security_protocol,
        &credential_mapping.target,
    );

    let (client_res, server_res) = tokio::join!(client_credssp_fut, server_credssp_fut);
    client_res.context("CredSSP with client failed")?;
    server_res.context("CredSSP with server failed")?;

    info!("CredSSP MITM completed successfully");

    // Extract streams and any leftover bytes
    let (mut client_stream, client_leftover) = client_framed.into_inner();
    let (mut server_stream, server_leftover) = server_framed.into_inner();

    // Forward any leftover bytes
    if !server_leftover.is_empty() {
        client_stream
            .write_all(&server_leftover)
            .await
            .context("write server leftover to client")?;
    }
    if !client_leftover.is_empty() {
        server_stream
            .write_all(&client_leftover)
            .await
            .context("write client leftover to server")?;
    }

    info!("RDP-TLS forwarding (credential injection)");

    // Build SessionInfo for forwarding
    let session_info = SessionInfo::builder()
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

    // Plain forwarding for now
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
        .context("proxy failed")
}

#[allow(clippy::too_many_arguments)]
#[instrument("fwd", skip_all, fields(session_id = field::Empty, target = field::Empty))]
pub async fn handle(
    mut client_stream: impl AsyncRead + AsyncWrite + Unpin + Send + Sync,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    sessions: SessionMessageSender,
    subscriber_tx: SubscriberSender,
    active_recordings: &ActiveRecordings,
    credential_store: &CredentialStoreHandle,
) -> anyhow::Result<()> {
    // Special handshake of our RDP extension

    trace!("Reading RDCleanPath");

    let cleanpath_pdu = read_cleanpath_pdu(&mut client_stream)
        .await
        .context("couldn't read clean cleanpath PDU")?;

    // Early credential detection: check if we should use RdpProxy instead
    let token = cleanpath_pdu
        .proxy_auth
        .clone()
        .ok_or_else(|| anyhow::anyhow!("missing token in RDCleanPath PDU"))?;

    if let Some(entry) = crate::token::extract_jti(&token)
        .ok()
        .and_then(|token_id| credential_store.get(token_id))
        .filter(|entry| entry.mapping.is_some())
    {
        // Credentials found! Switch to RdpProxy for credential injection
        info!("Switching to RdpProxy for credential injection (WebSocket)");

        return handle_with_credential_injection(
            client_stream,
            client_addr,
            conf,
            token_cache,
            jrl,
            sessions,
            subscriber_tx,
            active_recordings,
            cleanpath_pdu,
            token,
            entry,
        )
        .await;
    }

    trace!("Processing RDCleanPath");

    let CleanPathResult {
        claims,
        destination,
        server_addr,
        server_stream,
        x224_rsp,
    } = match process_cleanpath(
        cleanpath_pdu,
        client_addr,
        &conf,
        token_cache,
        jrl,
        active_recordings,
        &sessions,
        credential_store,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            let response = RDCleanPathPdu::from(&error);
            send_clean_path_response(&mut client_stream, &response).await?;
            return anyhow::Error::new(error)
                .context("an error occurred when processing cleanpath PDU")
                .pipe(Err)?;
        }
    };

    // Send success RDCleanPathPdu response

    let x509_chain = server_stream
        .get_ref()
        .1
        .peer_certificates()
        .context("no peer certificate found in TLS transport")?
        .iter()
        .map(|cert| cert.to_vec());

    trace!("Sending RDCleanPath response");

    let rdcleanpath_rsp = RDCleanPathPdu::new_response(server_addr.to_string(), x224_rsp, x509_chain)
        .map_err(|e| anyhow::anyhow!("couldn’t build RDCleanPath response: {e}"))?;

    send_clean_path_response(&mut client_stream, &rdcleanpath_rsp).await?;

    // Start actual RDP session

    let info = SessionInfo::builder()
        .id(claims.jet_aid)
        .application_protocol(claims.jet_ap)
        .details(ConnectionModeDetails::Fwd {
            destination_host: destination.clone(),
        })
        .time_to_live(claims.jet_ttl)
        .recording_policy(claims.jet_rec)
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
        .disconnect_interest(DisconnectInterest::from_reconnection_policy(claims.jet_reuse))
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
            CleanPathError::TlsHandshake {
                source,
                target_server: _,
            } => io_to_rdcleanpath_err(source),
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

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[allow(dead_code)]
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
