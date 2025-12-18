use std::io;
use std::net::SocketAddr;

use axum::Router;
use axum::extract::{self, ConnectInfo, State};
use axum::http::StatusCode;
use axum::routing::post;
use picky_krb::messages::KdcProxyMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::DgwState;
use crate::http::{HttpError, HttpErrorBuilder};
use crate::target_addr::TargetAddr;
use crate::token::AccessTokenClaims;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new().route("/{token}", post(kdc_proxy)).with_state(state)
}

async fn kdc_proxy(
    State(DgwState {
        conf_handle,
        token_cache,
        jrl,
        recordings,
        ..
    }): State<DgwState>,
    extract::Path(token): extract::Path<String>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, HttpError> {
    let conf = conf_handle.get_conf();

    let claims = crate::middleware::auth::authenticate(
        source_addr,
        &token,
        &conf,
        &token_cache,
        &jrl,
        &recordings.active_recordings,
        None,
    )
    .map_err(HttpError::unauthorized().err())?;

    let AccessTokenClaims::Kdc(claims) = claims else {
        return Err(HttpError::forbidden().msg("token not allowed (expected KDC token)"));
    };

    let kdc_proxy_message = KdcProxyMessage::from_raw(&body).map_err(HttpError::bad_request().err())?;

    trace!(?kdc_proxy_message, "Received KDC message");

    debug!(
        ?kdc_proxy_message.target_domain,
        ?kdc_proxy_message.dclocator_hint,
        "KDC message",
    );

    let realm = if let Some(realm) = &kdc_proxy_message.target_domain.0 {
        realm.0.to_string()
    } else {
        return Err(HttpError::bad_request().msg("realm is missing from KDC request"));
    };

    debug!("Request is for realm (target_domain): {realm}");

    if !claims.krb_realm.eq_ignore_ascii_case(&realm) {
        if conf.debug.disable_token_validation {
            warn!(
                token_realm = %claims.krb_realm,
                request_realm = %realm,
                "**DEBUG OPTION** Allowed a KDC request towards a KDC whose Kerberos realm differs from what's inside the KDC token"
            );
        } else {
            let error_message = format!("expected: {}, got: {}", claims.krb_realm, realm);

            return Err(HttpError::bad_request()
                .with_msg("requested domain is not allowed")
                .err()(error_message));
        }
    }

    let kdc_addr = if let Some(kdc_addr) = &conf.debug.override_kdc {
        warn!("**DEBUG OPTION** KDC address has been overridden with {kdc_addr}");
        kdc_addr
    } else {
        &claims.krb_kdc
    };

    let kdc_reply_message = send_krb_message(kdc_addr, &kdc_proxy_message.kerb_message.0.0).await?;

    let kdc_reply_message = KdcProxyMessage::from_raw_kerb_message(&kdc_reply_message)
        .map_err(HttpError::internal().with_msg("couldn’t create KDC proxy reply").err())?;

    trace!(?kdc_reply_message, "Sending back KDC reply");

    kdc_reply_message.to_vec().map_err(HttpError::internal().err())
}

async fn read_kdc_reply_message(connection: &mut TcpStream) -> io::Result<Vec<u8>> {
    let len = connection.read_u32().await?;
    let mut buf = vec![0; (len + 4).try_into().expect("u32-to-usize")];
    buf[0..4].copy_from_slice(&(len.to_be_bytes()));
    connection.read_exact(&mut buf[4..]).await?;
    Ok(buf)
}

#[track_caller]
fn unable_to_reach_kdc_server_err(error: io::Error) -> HttpError {
    use io::ErrorKind;

    let builder = match error.kind() {
        ErrorKind::TimedOut => HttpErrorBuilder::new(StatusCode::GATEWAY_TIMEOUT),
        ErrorKind::ConnectionRefused => HttpError::bad_gateway(),
        ErrorKind::ConnectionAborted => HttpError::bad_gateway(),
        ErrorKind::ConnectionReset => HttpError::bad_gateway(),
        ErrorKind::BrokenPipe => HttpError::bad_gateway(),
        ErrorKind::OutOfMemory => HttpError::internal(),
        // FIXME: once stabilized use new IO error variants
        // - https://github.com/rust-lang/rust/pull/106375
        // - https://github.com/rust-lang/rust/issues/86442
        // ErrorKind::NetworkDown => HttpErrorBuilder::new(StatusCode::SERVICE_UNAVAILABLE),
        // ErrorKind::NetworkUnreachable => HttpError::bad_gateway(),
        // ErrorKind::HostUnreachable => HttpError::bad_gateway(),
        // TODO: When the above is applied, we can return an internal error in the fallback branch.
        _ => HttpError::bad_gateway(),
    };

    builder.with_msg("unable to reach KDC server").build(error)
}

/// Sends the Kerberos message to the specified KDC address.
pub async fn send_krb_message(kdc_addr: &TargetAddr, message: &[u8]) -> Result<Vec<u8>, HttpError> {
    let protocol = kdc_addr.scheme();

    debug!("Connecting to KDC server located at {kdc_addr} using protocol {protocol}...");

    if protocol == "tcp" {
        #[allow(clippy::redundant_closure)] // We get a better caller location for the error by using a closure.
        let mut connection = TcpStream::connect(kdc_addr.as_addr()).await.map_err(|e| {
            error!(%kdc_addr, "failed to connect to KDC server");
            unable_to_reach_kdc_server_err(e)
        })?;

        trace!("Connected! Forwarding KDC message...");

        connection.write_all(message).await.map_err(
            HttpError::bad_gateway()
                .with_msg("unable to send the message to the KDC server")
                .err(),
        )?;

        trace!("Reading KDC reply...");

        Ok(read_kdc_reply_message(&mut connection).await.map_err(
            HttpError::bad_gateway()
                .with_msg("unable to read KDC reply message")
                .err(),
        )?)
    } else {
        // We assume that ticket length is not bigger than 2048 bytes.
        let mut buf = [0; 2048];

        let port = portpicker::pick_unused_port().ok_or_else(|| HttpError::internal().msg("no free ports"))?;

        trace!("Binding UDP listener to 127.0.0.1:{port}...");

        let udp_socket = UdpSocket::bind(("127.0.0.1", port))
            .await
            .map_err(HttpError::internal().with_msg("unable to bind UDP socket").err())?;

        trace!("Binded! Forwarding KDC message...");

        // First 4 bytes contains message length. We don't need it for UDP.
        #[allow(clippy::redundant_closure)] // We get a better caller location for the error by using a closure.
        udp_socket
            .send_to(&message[4..], kdc_addr.as_addr())
            .await
            .map_err(|e| unable_to_reach_kdc_server_err(e))?;

        trace!("Reading KDC reply...");

        let n = udp_socket.recv(&mut buf).await.map_err(
            HttpError::bad_gateway()
                .with_msg("unable to read reply from the KDC server")
                .err(),
        )?;

        let mut reply_buf = Vec::new();
        reply_buf.extend_from_slice(&u32::try_from(n).expect("n not too big").to_be_bytes());
        reply_buf.extend_from_slice(&buf[0..n]);

        Ok(reply_buf)
    }
}
