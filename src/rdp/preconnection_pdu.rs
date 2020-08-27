use bytes::BytesMut;
use chrono::Utc;
use ironrdp::{PduBufferParsing, PreconnectionPdu, PreconnectionPduError};
use picky::jose::jwt::{Jwt, JwtDate, JwtValidator};
use slog_scope::warn;
use std::{borrow::Cow, io, sync::Arc};
use url::Url;

use crate::config::Config;

const DEFAULT_RDP_PORT: u16 = 3389;
const DEFAULT_ROUTING_HOST_SCHEME: &str = "tcp://";
const JWT_REQUIRED_JET_AP_VALUE: &str = "rdp";

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct RoutingClaims {
    dst_hst: Cow<'static, str>,
    jet_ap: Cow<'static, str>,
}

pub struct PreconnectionPduRoute {
    pub dest_host: Url,
}

pub fn resolve_route(pdu: &PreconnectionPdu, config: Arc<Config>) -> Result<PreconnectionPduRoute, io::Error> {
    if let Some(jwt_token_base64) = &pdu.payload {
        let current_timestamp = JwtDate::new(Utc::now().timestamp());

        let validator = if let Some(provisioner_key) = &config.provisioner_public_key {
            JwtValidator::strict(provisioner_key, &current_timestamp)
        } else {
            warn!("Provisioner key is not specified; Skipping signature validation");
            JwtValidator::dangerous()
                .current_date(&current_timestamp)
                .expiration_check_required()
                .not_before_check_required()
        };

        let jwt_token = Jwt::<RoutingClaims>::decode(&jwt_token_base64, &validator).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to resolve route via JWT routing token: {}", e),
            )
        })?;

        let claims = jwt_token.view_claims();

        if claims.jet_ap != JWT_REQUIRED_JET_AP_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Non-rdp jwt-based routing via preconnection PDU is not supported",
            ));
        }

        let route_url_str = if claims.dst_hst.starts_with(DEFAULT_ROUTING_HOST_SCHEME) {
            claims.dst_hst.clone().into()
        } else {
            let mut url_str = String::from(DEFAULT_ROUTING_HOST_SCHEME);
            url_str.push_str(&claims.dst_hst);
            url_str
        };

        let mut dest_host = Url::parse(&route_url_str).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse routing url in JWT token: {}", e),
            )
        })?;

        if dest_host.port().is_none() {
            dest_host.set_port(Some(DEFAULT_RDP_PORT)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid URL: Can't set default port for routing URL".to_string(),
                )
            })?;
        }

        Ok(PreconnectionPduRoute { dest_host })
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "Empty preconnection PDU"))
    }
}

pub fn decode_preconnection_pdu(buf: &mut BytesMut) -> Result<Option<PreconnectionPdu>, io::Error> {
    let mut parsing_buffer = buf.as_ref();
    match PreconnectionPdu::from_buffer_consume(&mut parsing_buffer) {
        Ok(preconnection_pdu) => {
            buf.split_at(preconnection_pdu.buffer_length());
            Ok(Some(preconnection_pdu))
        }
        Err(PreconnectionPduError::IoError(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse Preconnection PDU: {}", e),
        )),
    }
}
