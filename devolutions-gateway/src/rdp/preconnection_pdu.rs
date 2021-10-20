use std::io;

use bytes::BytesMut;
use chrono::Utc;
use ironrdp::{PduBufferParsing, PreconnectionPdu, PreconnectionPduError};
use picky::jose::jwe::Jwe;
use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator};
use sspi::AuthIdentity;
use url::Url;
use uuid::Uuid;

use jet_proto::token::JetAssociationTokenClaims;

use crate::config::Config;
use crate::rdp::RdpIdentity;
use jet_proto::token::JetConnectionMode;

const DEFAULT_ROUTING_HOST_SCHEME: &str = "tcp://";
const DEFAULT_RDP_PORT: u16 = 3389;

const JET_AP_RDP_TCP: &str = "rdp_tcp";

const EXPECTED_JET_AP_VALUES: [&str; 2] = ["rdp", JET_AP_RDP_TCP];

pub enum TokenRoutingMode {
    RdpTcp(Url),
    RdpTls(RdpIdentity),
    RdpTcpRendezvous(Uuid),
}

pub fn is_encrypted(token: &str) -> bool {
    let num_dots = token.chars().fold(0, |acc, c| if c == '.' { acc + 1 } else { acc });
    num_dots == 4
}

pub fn extract_routing_claims(pdu: &PreconnectionPdu, config: &Config) -> Result<JetAssociationTokenClaims, io::Error> {
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

    let jwt_token =
        JwtSig::<JetAssociationTokenClaims>::decode(signed_jwt, &provisioner_key, &validator).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to resolve route via JWT routing token: {}", e),
            )
        })?;

    let claims = jwt_token.claims;

    if claims.creds.is_some() && !is_encrypted {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Received a non encrypted JWT containing credentials. This is bad.",
        ));
    }

    Ok(claims)
}

pub fn resolve_routing_mode(claims: &JetAssociationTokenClaims) -> Result<TokenRoutingMode, io::Error> {
    if !EXPECTED_JET_AP_VALUES.contains(&claims.jet_ap.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Non-RDP JWT-based routing via preconnection PDU is not supported",
        ));
    }

    let dest_host = if let Some(dest_host_claim) = &claims.dst_hst {
        let route_url_str = if dest_host_claim.starts_with(DEFAULT_ROUTING_HOST_SCHEME) {
            dest_host_claim.clone()
        } else {
            format!("{}{}", DEFAULT_ROUTING_HOST_SCHEME, dest_host_claim)
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
                    "Invalid URL: couldn't set default port for routing URL".to_string(),
                )
            })?;
        }

        Some(dest_host)
    } else {
        None
    };

    match &claims.creds {
        Some(creds) => {
            let dest_host = dest_host.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "dst_hst claim is missing for RdpTls mode".to_string(),
                )
            })?;

            Ok(TokenRoutingMode::RdpTls(RdpIdentity {
                proxy: AuthIdentity {
                    username: creds.prx_usr.to_owned(),
                    password: creds.prx_pwd.to_owned(),
                    domain: None,
                },
                target: AuthIdentity {
                    username: creds.dst_usr.to_owned(),
                    password: creds.dst_pwd.to_owned(),
                    domain: None,
                },
                dest_host,
            }))
        }
        None if (claims.jet_ap == JET_AP_RDP_TCP && matches!(claims.jet_cm, JetConnectionMode::Rdv)) => {
            Ok(TokenRoutingMode::RdpTcpRendezvous(claims.jet_aid))
        }
        None => {
            let dest_host = dest_host.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "dst_hst claim is missing for RdpTcp mode")
            })?;

            Ok(TokenRoutingMode::RdpTcp(dest_host))
        }
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
