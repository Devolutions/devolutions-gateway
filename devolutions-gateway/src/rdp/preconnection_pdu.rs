use crate::{config::Config, rdp::RdpIdentity};
use bytes::BytesMut;
use chrono::Utc;
use ironrdp::{PduBufferParsing, PreconnectionPdu, PreconnectionPduError};
use picky::jose::{
    jwe::Jwe,
    jwt::{JwtDate, JwtSig, JwtValidator},
};
use sspi::AuthIdentity;
use std::io;
use url::Url;
use uuid::Uuid;

const DEFAULT_ROUTING_HOST_SCHEME: &str = "tcp://";
const DEFAULT_RDP_PORT: u16 = 3389;

const JET_APP_RDP_TCP: &str = "rdp-tcp";
const JET_CM_RDV: &str = "rdv";

const EXPECTED_JET_AP_VALUES: [&str; 2] = ["rdp", JET_APP_RDP_TCP];
const EXPECTED_JET_CM_VALUES: [&str; 2] = ["fwd", JET_CM_RDV];

pub enum TokenRoutingMode {
    RdpTcp(Url),
    RdpTls(RdpIdentity),
    RdpTcpRendezvous(Uuid),
}

#[derive(Deserialize, Debug)]
pub struct CredsClaims {
    // Proxy credentials (client <-> jet)
    prx_usr: String,
    prx_pwd: String,

    // Target credentials (jet <-> server)
    dst_usr: String,
    dst_pwd: String,
}

#[derive(Deserialize, Debug)]
struct RoutingClaims {
    #[serde(flatten)]
    creds: Option<CredsClaims>,

    /// Destination Host <host>:<port>
    dst_hst: String,

    /// Identity connection mode used for Jet association
    #[serde(default = "get_default_jet_connection_mode")]
    jet_cm: String,

    /// Application protocol used over Jet transport
    jet_ap: String,

    /// Jet assassination ID used for RdpTcpRendezvous routing mode
    jet_aid: Option<String>,
}

pub fn is_encrypted(token: &str) -> bool {
    let num_dots = token.chars().fold(0, |acc, c| if c == '.' { acc + 1 } else { acc });
    num_dots == 4
}

pub fn resolve_routing_mode(pdu: &PreconnectionPdu, config: &Config) -> Result<TokenRoutingMode, io::Error> {
    let payload = pdu
        .payload
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty preconnection PDU"))?;

    let is_encrypted = is_encrypted(payload);

    let jwe_token; // pre-declaration because we want longer lifetime
    let signed_jwt;

    if is_encrypted {
        let encrypted_jwt = payload;

        let delegation_key = config
            .delegation_private_key
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Delegation key is missing"))?;

        jwe_token = Jwe::decode(&encrypted_jwt, &delegation_key).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to resolve route via JWT routing token: {}", e),
            )
        })?;

        signed_jwt = std::str::from_utf8(&jwe_token.payload).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to resolve route via JWT routing token: {}", e),
            )
        })?;
    } else {
        signed_jwt = payload;
    }

    let now = JwtDate::new_with_leeway(Utc::now().timestamp(), 30);
    let validator = JwtValidator::strict(&now);

    let provisioner_key = config
        .provisioner_public_key
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Provisioner key is missing"))?;

    let jwt_token = JwtSig::<RoutingClaims>::decode(signed_jwt, &provisioner_key, &validator).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to resolve route via JWT routing token: {}", e),
        )
    })?;

    let claims = jwt_token.claims;

    if EXPECTED_JET_AP_VALUES.iter().all(|&jet_app| claims.jet_ap != jet_app) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Non-RDP JWT-based routing via preconnection PDU is not supported",
        ));
    }

    if EXPECTED_JET_CM_VALUES.iter().all(|&jet_cm| claims.jet_cm != jet_cm) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "JWT-based routing via preconnection PDU only support Forward and RdpTcpRendezvous communication mode",
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

    match claims.creds {
        Some(creds) if is_encrypted => Ok(TokenRoutingMode::RdpTls(RdpIdentity {
            proxy: AuthIdentity {
                username: creds.prx_usr,
                password: creds.prx_pwd,
                domain: None,
            },
            target: AuthIdentity {
                username: creds.dst_usr,
                password: creds.dst_pwd,
                domain: None,
            },
            dest_host,
        })),
        None if (claims.jet_ap == JET_APP_RDP_TCP && claims.jet_cm == JET_CM_RDV) => {
            let jet_aid = claims.jet_aid.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "RdpTcpRendezvous token routing mode, but Jet AssociationId is missing".to_string(),
                )
            })?;

            let jet_aid = Uuid::parse_str(jet_aid.as_str()).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse Jet AssociationId: Invalid Uuid value: {}", err),
                )
            })?;

            Ok(TokenRoutingMode::RdpTcpRendezvous(jet_aid))
        }
        None => Ok(TokenRoutingMode::RdpTcp(dest_host)),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Received a non encrypted JWT containing credentials. This is bad.".to_string(),
        )),
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
            format!("Failed to parse preconnection PDU: {}", e),
        )),
    }
}

fn get_default_jet_connection_mode() -> String {
    "fwd".to_owned()
}
