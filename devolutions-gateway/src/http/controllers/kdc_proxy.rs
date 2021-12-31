use crate::config::Config;
use crate::http::HttpErrorStatus;
use picky_krb::messages::KdcProxyMessage;
use saphir::controller::Controller;
use saphir::http::Method;
use saphir::macros::controller;
use saphir::request::Request;
use saphir::response::Builder;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const ERROR_BAD_FORMAT: &str = "\x0b";

pub struct KdcProxyController {
    config: Arc<Config>,
}

impl KdcProxyController {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[controller(name = "KdcProxy")]
impl KdcProxyController {
    #[post("/")]
    async fn proxy_kdc_message(&self, req: Request) -> Result<Builder, HttpErrorStatus> {
        let kdc_proxy_message = KdcProxyMessage::from_raw(
            req.load_body()
                .await
                .map_err(|_| HttpErrorStatus::bad_request(ERROR_BAD_FORMAT))?
                .body(),
        )
        .map_err(|_| HttpErrorStatus::bad_request(ERROR_BAD_FORMAT))?;

        let realm = if let Some(realm) = &kdc_proxy_message.target_domain.0 {
            realm.0.to_string()
        } else {
            return Err(HttpErrorStatus::bad_request(ERROR_BAD_FORMAT));
        };

        let kdc_proxy_config = self
            .config
            .kdc_proxy_config
            .as_ref()
            .ok_or_else(|| HttpErrorStatus::internal("KDC proxy is not configured"))?;

        if kdc_proxy_config.reaml != realm {
            return Err(HttpErrorStatus::bad_request("Requested realm is not supported"));
        }

        let scheme = kdc_proxy_config.kdc.scheme();
        let address_to_resolve = format!(
            "{}:{}",
            kdc_proxy_config.kdc.host().unwrap().to_string(),
            kdc_proxy_config.kdc.port().unwrap_or(88)
        );

        let kdc_address = if let Some(address) = lookup_kdc(&address_to_resolve) {
            address
        } else {
            slog_scope::error!("Unable to locate KDC server");
            return Err(HttpErrorStatus::internal("Unable to locate KDC server"));
        };

        let mut kdc_reply_message = Vec::new();

        if scheme == "tcp" {
            let mut connection = TcpStream::connect(kdc_address).await.map_err(|e| {
                slog_scope::error!("{:?}", e);
                HttpErrorStatus::internal("Unable to connect to KDC server")
            })?;

            connection
                .write_all(&kdc_proxy_message.kerb_message.0 .0)
                .await
                .map_err(|e| {
                    slog_scope::error!("{:?}", e);
                    HttpErrorStatus::internal("Unable to send the message to the KDC server")
                })?;

            connection.read_to_end(&mut kdc_reply_message).await.map_err(|e| {
                slog_scope::error!("{:?}", e);
                HttpErrorStatus::internal("Unable to read reply from the KDC server")
            })?;
        } else if scheme == "udp" {
            let mut buff = vec![0; 1024];

            let port = portpicker::pick_unused_port().ok_or_else(|| HttpErrorStatus::internal("No free ports"))?;
            let udp_socket = UdpSocket::bind(format!("127.0.0.1:{}", port)).await.map_err(|e| {
                slog_scope::error!("{:?}", e);
                HttpErrorStatus::internal("Unable to send the message to the KDC server")
            })?;

            // first 4 bytes contains message length. we don't need it for UDP
            udp_socket
                .send_to(&kdc_proxy_message.kerb_message.0 .0[4..], kdc_address)
                .await
                .map_err(|e| {
                    slog_scope::error!("{:?}", e);
                    HttpErrorStatus::internal("Unable to send the message to the KDC server")
                })?;

            let n = udp_socket.recv(&mut buff).await.map_err(|e| {
                slog_scope::error!("{:?}", e);
                HttpErrorStatus::internal("Unable to read reply from the KDC server")
            })?;

            kdc_reply_message.extend_from_slice(&(n as u32).to_be_bytes());
            kdc_reply_message.extend_from_slice(&buff[0..n]);
        }

        println!("{:?}", kdc_reply_message);

        let kdc_proxy_reply_message = KdcProxyMessage::from_raw_kerb_message(&kdc_reply_message).map_err(|e| {
            slog_scope::error!("{:?}", e);
            HttpErrorStatus::internal("Cannot create kdc proxy massage")
        })?;

        Ok(Builder::new()
            .body(kdc_proxy_reply_message.to_vec().unwrap())
            .status(200))
    }
}

fn lookup_kdc(url: &str) -> Option<SocketAddr> {
    url.to_socket_addrs().ok()?.next()
}
