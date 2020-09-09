use crate::config::Config;
use bytes::BytesMut;
use chrono::Utc;
use ironrdp::{PduBufferParsing, PreconnectionPdu, PreconnectionPduError};
use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator};
use slog_scope::warn;
use std::{io, sync::Arc};
use url::Url;

const DEFAULT_ROUTING_HOST_SCHEME: &str = "tcp://";
const DEFAULT_RDP_PORT: u16 = 3389;
const EXPECTED_JET_AP_VALUE: &str = "rdp";
const EXPECTED_JET_CM_VALUE: &str = "fwd"; // currently only "forward-only" connection mode is supported

#[derive(Deserialize, Debug, PartialEq)]
pub struct CredsClaims {
    // Proxy credentials (client <-> jet)
    prx_usr: String,
    prx_pwd: String,

    // Target credentials (jet <-> server)
    dst_usr: String,
    dst_pwd: String,
}

#[derive(Deserialize, Debug, PartialEq)]
struct RoutingClaims {
    #[serde(flatten)]
    creds: Option<CredsClaims>,

    /// Destination Host <host>:<port>
    dst_hst: String,

    /// Identity connection mode used for Jet association
    jet_cm: String,

    /// Application protocol used over Jet transport
    jet_ap: String,
}

pub struct PreconnectionPduRoute {
    pub dest_host: Url,
    pub creds: Option<CredsClaims>,
}

pub fn resolve_route(pdu: &PreconnectionPdu, config: Arc<Config>) -> Result<PreconnectionPduRoute, io::Error> {
    let jwt_token_base64 = pdu
        .payload
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty preconnection PDU"))?;

    let now = JwtDate::new_with_leeway(Utc::now().timestamp(), 30);
    let validator = JwtValidator::strict(&now);

    let jwt_token = if let Some(provisioner_key) = &config.provisioner_public_key {
        JwtSig::<RoutingClaims>::decode(&jwt_token_base64, &provisioner_key, &validator)
    } else {
        warn!("Provisioner key is not specified; Skipping signature validation");
        JwtSig::<RoutingClaims>::decode_dangerous(&jwt_token_base64, &validator)
    }
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to resolve route via JWT routing token: {}", e),
        )
    })?;

    let claims = jwt_token.claims;

    if claims.jet_ap != EXPECTED_JET_AP_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Non-RDP JWT-based routing via preconnection PDU is not supported",
        ));
    }

    if claims.jet_cm != EXPECTED_JET_CM_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "JWT-based routing via preconnection PDU only support Forward-Only communication mode",
        ));
    }

    let route_url_str = if claims.dst_hst.starts_with(DEFAULT_ROUTING_HOST_SCHEME) {
        claims.dst_hst
    } else {
        format!("{}{}", DEFAULT_ROUTING_HOST_SCHEME, claims.dst_hst)
    };

    let mut dest_host = Url::parse(&route_url_str).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse routing URL in JWT token: {}", e),
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

    Ok(PreconnectionPduRoute {
        dest_host,
        creds: claims.creds,
    })
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
            format!("Failed to parse preconnection PDU: {}", e),
        )),
    }
}
