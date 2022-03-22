use crate::config::Config;
use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpErrorStatus;
use crate::token::AccessTokenClaims;
use crate::utils::resolve_target_to_socket_addr;
use picky_krb::messages::KdcProxyMessage;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::request::Request;
use saphir::response::Builder;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const ERROR_BAD_FORMAT: &str = "\x0b";

pub struct KdcProxyController {
    pub config: Arc<Config>,
}

#[controller(name = "KdcProxy")]
impl KdcProxyController {
    #[post("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Kdc"#)]
    async fn proxy_kdc_message(&self, mut req: Request) -> Result<Builder, HttpErrorStatus> {
        use focaccia::unicode_full_case_eq;

        let claims = req
            .extensions_mut()
            .remove::<AccessTokenClaims>()
            .ok_or_else(|| HttpErrorStatus::unauthorized("identity is missing (token)"))?;

        let kdc_proxy_message = KdcProxyMessage::from_raw(
            req.load_body()
                .await
                .map_err(|_| HttpErrorStatus::bad_request(ERROR_BAD_FORMAT))?
                .body(),
        )
        .map_err(|_| HttpErrorStatus::bad_request(ERROR_BAD_FORMAT))?;

        trace!("Received KDC message: {:?}", kdc_proxy_message);

        debug!(
            "KDC message: target_domain = {:?}, dclocator_hint = {:?}",
            kdc_proxy_message.target_domain, kdc_proxy_message.dclocator_hint
        );

        let realm = if let Some(realm) = &kdc_proxy_message.target_domain.0 {
            realm.0.to_string()
        } else {
            return Err(HttpErrorStatus::bad_request(ERROR_BAD_FORMAT));
        };

        debug!("Request is for realm (target_domain): {realm}");

        let claims = if let AccessTokenClaims::Kdc(claims) = claims {
            claims
        } else {
            return Err(HttpErrorStatus::forbidden("token not allowed"));
        };

        if !unicode_full_case_eq(&claims.krb_realm, &realm) {
            if self.config.debug.disable_token_validation {
                warn!("**DEBUG OPTION** Allowed a KDC request towards a KDC whose Kerberos realm differs from what's inside the KDC token");
            } else {
                return Err(HttpErrorStatus::bad_request("Requested domain is not supported"));
            }
        }

        let kdc_addr = if let Some(kdc_addr) = &self.config.debug.override_kdc {
            warn!("**DEBUG OPTION** KDC address has been overridden with {kdc_addr}");
            kdc_addr
        } else {
            &claims.krb_kdc
        };

        let protocol = kdc_addr.scheme();

        let kdc_addr = resolve_target_to_socket_addr(kdc_addr).await.map_err(|e| {
            error!("Unable to locate KDC server: {:#}", e);
            HttpErrorStatus::internal("Unable to locate KDC server")
        })?;

        trace!("Connecting to KDC server located at {kdc_addr} using protocol {protocol}...");

        let kdc_reply_message = if protocol == "tcp" {
            let mut connection = TcpStream::connect(kdc_addr).await.map_err(|e| {
                error!("{:?}", e);
                HttpErrorStatus::internal("Unable to connect to KDC server")
            })?;

            trace!("Connected! Forwarding KDC message...");

            connection
                .write_all(&kdc_proxy_message.kerb_message.0 .0)
                .await
                .map_err(|e| {
                    error!("{:?}", e);
                    HttpErrorStatus::internal("Unable to send the message to the KDC server")
                })?;

            trace!("Reading KDC reply...");

            read_kdc_reply_message(&mut connection).await.map_err(|e| {
                error!("{:?}", e);
                HttpErrorStatus::internal("Unable to read KDC reply message")
            })?
        } else {
            // we assume that ticket length is not greater than 2048
            let mut buff = [0; 2048];

            let port = portpicker::pick_unused_port().ok_or_else(|| HttpErrorStatus::internal("No free ports"))?;

            trace!("Binding UDP listener to 127.0.0.1:{port}...");

            let udp_socket = UdpSocket::bind(("127.0.0.1", port)).await.map_err(|e| {
                error!("{:?}", e);
                HttpErrorStatus::internal("Unable to send the message to the KDC server")
            })?;

            trace!("Binded! Forwarding KDC message...");

            // first 4 bytes contains message length. we don't need it for UDP
            udp_socket
                .send_to(&kdc_proxy_message.kerb_message.0 .0[4..], kdc_addr)
                .await
                .map_err(|e| {
                    error!("{:?}", e);
                    HttpErrorStatus::internal("Unable to send the message to the KDC server")
                })?;

            trace!("Reading KDC reply...");

            let n = udp_socket.recv(&mut buff).await.map_err(|e| {
                error!("{:?}", e);
                HttpErrorStatus::internal("Unable to read reply from the KDC server")
            })?;

            let mut reply_buf = Vec::new();
            reply_buf.extend_from_slice(&(n as u32).to_be_bytes());
            reply_buf.extend_from_slice(&buff[0..n]);
            reply_buf
        };

        let kdc_proxy_reply_message = KdcProxyMessage::from_raw_kerb_message(&kdc_reply_message).map_err(|e| {
            error!("{:?}", e);
            HttpErrorStatus::internal("Cannot create kdc proxy massage")
        })?;

        trace!("Sending back KDC reply: {:?}", kdc_proxy_reply_message);

        Ok(Builder::new()
            .body(kdc_proxy_reply_message.to_vec().unwrap())
            .status(200))
    }
}

async fn read_kdc_reply_message(connection: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let len = connection.read_u32().await?;
    let mut buf = vec![0; (len + 4).try_into().unwrap()];
    buf[0..4].copy_from_slice(&(len.to_be_bytes()));
    connection.read_exact(&mut buf[4..]).await?;
    Ok(buf)
}
