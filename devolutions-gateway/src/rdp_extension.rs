use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Conf;
use crate::proxy::Proxy;
use crate::session::{ConnectionModeDetails, SessionInfo, SessionManagerHandle};
use crate::subscriber::SubscriberSender;
use crate::token::{AssociationTokenClaims, CurrentJrl, TokenCache, TokenError};
use crate::utils::TargetAddr;

use anyhow::Context as _;
use ironrdp_devolutions_gateway::RDCleanPathPdu;
use tap::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::rustls::client::ClientConfig as TlsClientConfig;

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
    client_addr: SocketAddr,
    token: &str,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> Result<AssociationTokenClaims, AuthorizationError> {
    use crate::token::AccessTokenClaims;

    if let AccessTokenClaims::Association(claims) =
        crate::http::middlewares::auth::authenticate(client_addr, token, conf, token_cache, jrl)?
    {
        Ok(claims)
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

async fn send_clean_path_response(
    stream: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    rd_clean_path_rsp: &RDCleanPathPdu,
) -> anyhow::Result<()> {
    let rd_clean_path_rsp = rd_clean_path_rsp
        .to_der()
        .map_err(|e| anyhow::anyhow!("RDCleanPath DER conversion failure: {e}"))?;

    stream.write_all(&rd_clean_path_rsp).await?;
    stream.flush().await?;

    Ok(())
}

async fn read_cleanpath_pdu(stream: &mut (dyn AsyncRead + Unpin + Send)) -> io::Result<RDCleanPathPdu> {
    let mut buf = bytes::BytesMut::new();

    // TODO: check if there is code to be reused from ironrdp code base for that
    let cleanpath_pdu = loop {
        if let Some(pdu) = RDCleanPathPdu::decode(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad RDCleanPathPdu: {e}")))?
        {
            break pdu;
        }

        let mut read_bytes = [0u8; 1024];
        let len = stream.read(&mut read_bytes[..]).await?;
        buf.extend_from_slice(&read_bytes[..len]);

        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF when reading RDCleanPathPdu",
            ));
        }
    };

    // Sanity check: make sure there is no leftover
    if !buf.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "no leftover is expected after reading cleanpath PDU",
        ));
    }

    Ok(cleanpath_pdu)
}

#[derive(Debug, Error)]
enum CleanPathError {
    #[error("bad request")]
    BadRequest(#[source] anyhow::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
    #[error("Couldn’t perform TLS handshake")]
    TlsHandshake(#[source] io::Error),
    #[error("authorization error")]
    Authorization(#[from] AuthorizationError),
    #[error("Generic IO error")]
    Io(#[from] io::Error),
}

struct CleanPathResult {
    claims: AssociationTokenClaims,
    destination: TargetAddr,
    server_addr: SocketAddr,
    server_transport: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    x224_rsp: Vec<u8>,
}

#[instrument(skip_all)]
async fn process_cleanpath(
    cleanpath_pdu: RDCleanPathPdu,
    client_addr: SocketAddr,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> Result<CleanPathResult, CleanPathError> {
    use crate::utils;
    use tokio::io::AsyncReadExt as _;
    use tokio_util::codec::Decoder as _;

    let Some(token) = cleanpath_pdu.proxy_auth.as_deref() else {
        return Err(CleanPathError::Authorization(AuthorizationError::Unauthorized));
    };

    trace!("Authorizing session");

    let claims = authorize(client_addr, token, conf, token_cache, jrl)?;

    let crate::token::ConnectionMode::Fwd { ref targets, .. } = claims.jet_cm else {
        return anyhow::Error::msg("unexpected connection mode")
            .pipe(CleanPathError::BadRequest)
            .pipe(Err);
    };

    trace!("Connecting to destination server");

    let (mut server_transport, destination) = utils::successive_try(targets, utils::tcp_stream_connect)
        .await
        .context("couldn’t connect to RDP server")?;

    // Send preconnection blob if applicable
    if let Some(pcb) = cleanpath_pdu.preconnection_blob {
        server_transport.write_all(pcb.as_bytes()).await?;
    }

    // Send X224 connection request
    let x224_req = cleanpath_pdu
        .x224_connection_pdu
        .context("request is missing X224 connection PDU")
        .map_err(CleanPathError::BadRequest)?;
    server_transport.write_all(x224_req.as_bytes()).await?;

    // Receive server X224 connection response
    let mut buf = bytes::BytesMut::new();
    let mut decoder = crate::transport::x224::NegotiationWithServerTransport;

    trace!("Receiving X224 response");

    // TODO: check if there is code to be reused from ironrdp code base for that
    let x224_rsp = loop {
        let len = server_transport.read_buf(&mut buf).await?;

        if len == 0 {
            if let Some(frame) = decoder.decode_eof(&mut buf)? {
                break frame;
            }
        } else if let Some(frame) = decoder.decode(&mut buf)? {
            break frame;
        }
    };

    let mut x224_rsp_buf = Vec::new();
    ironrdp::PduParsing::to_buffer(&x224_rsp, &mut x224_rsp_buf)
        .context("failed to reencode x224 response from server")?;

    let server_addr = server_transport
        .peer_addr()
        .context("couldn’t get server peer address")?;

    trace!("Establishing TLS connection with server");

    let mut server_transport = {
        // Establish TLS connection with server

        let dns_name = destination
            .host()
            .try_into()
            .context("Invalid DNS name in selected target")?;

        // TODO: optimize client config creation
        //
        // rustls doc says:
        //
        // > Making one of these can be expensive, and should be once per process rather than once per connection.
        //
        // source: https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html
        //
        // In our case, this doesn’t work, so I’m creating a new ClientConfig from scratch each time (slow).
        // rustls issue: https://github.com/rustls/rustls/issues/1186
        let tls_client_config = TlsClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(std::sync::Arc::new(
                crate::utils::danger_transport::NoCertificateVerification,
            ))
            .with_no_client_auth()
            .pipe(Arc::new);

        tokio_rustls::TlsConnector::from(tls_client_config)
            .connect(dns_name, server_transport)
            .await
            .map_err(CleanPathError::TlsHandshake)?
    };

    // https://docs.rs/tokio-rustls/latest/tokio_rustls/#why-do-i-need-to-call-poll_flush
    server_transport.flush().await?;

    Ok(CleanPathResult {
        destination: destination.to_owned(),
        claims,
        server_addr,
        server_transport,
        x224_rsp: x224_rsp_buf,
    })
}

#[instrument(skip_all)]
pub async fn handle(
    mut stream: impl AsyncRead + AsyncWrite + Unpin + Send,
    client_addr: SocketAddr,
    conf: Arc<Conf>,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    sessions: SessionManagerHandle,
    subscriber_tx: SubscriberSender,
) -> anyhow::Result<()> {
    // Special handshake of our RDP extension

    trace!("Reading RDCleanPath");

    let cleanpath_pdu = read_cleanpath_pdu(&mut stream)
        .await
        .context("couldn’t read clean cleanpath PDU")?;

    trace!("Processing RDCleanPath");

    let CleanPathResult {
        claims,
        destination,
        server_addr,
        server_transport,
        x224_rsp,
    } = match process_cleanpath(cleanpath_pdu, client_addr, &conf, token_cache, jrl).await {
        Ok(result) => result,
        Err(error) => {
            let response = RDCleanPathPdu::from(&error);
            send_clean_path_response(&mut stream, &response).await?;
            return anyhow::Error::new(error)
                .context("an error occurred when processing cleanpath PDU")
                .pipe(Err)?;
        }
    };

    // Send success RDCleanPathPdu response

    let x509_chain = server_transport
        .get_ref()
        .1
        .peer_certificates()
        .context("no peer certificate found in TLS transport")?
        .iter()
        .map(|cert| cert.0.clone());

    trace!("Sending RDCleanPath response");

    let rd_clean_path_rsp = RDCleanPathPdu::new_response(server_addr.to_string(), x224_rsp, x509_chain)
        .map_err(|e| anyhow::anyhow!("Couldn’t build RDCleanPath response: {e}"))?;
    send_clean_path_response(&mut stream, &rd_clean_path_rsp).await?;

    // Start actual RDP session

    let info = SessionInfo::new(
        claims.jet_aid,
        claims.jet_ap,
        ConnectionModeDetails::Fwd {
            destination_host: destination.clone(),
        },
    )
    .with_ttl(claims.jet_ttl);

    trace!("Start RDP-TLS session");

    Proxy::builder()
        .conf(conf)
        .session_info(info)
        .address_a(client_addr)
        .transport_a(stream)
        .address_b(server_addr)
        .transport_b(server_transport)
        .sessions(sessions)
        .subscriber_tx(subscriber_tx)
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
            CleanPathError::TlsHandshake(e) => io_to_rdcleanpath_err(e),
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
        RDCleanPathPdu::new_tls_error(tls_alert.get_u8())
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
    pub fn as_u16(self) -> u16 {
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
