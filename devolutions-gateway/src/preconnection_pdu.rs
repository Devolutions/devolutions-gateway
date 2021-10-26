use crate::config::Config;
use crate::token::JetAssociationTokenClaims;
use bytes::BytesMut;
use chrono::Utc;
use ironrdp::{PduBufferParsing, PreconnectionPdu, PreconnectionPduError};
use picky::jose::jwe::Jwe;
use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator};
use std::io;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub fn is_encrypted(token: &str) -> bool {
    let num_dots = token.chars().fold(0, |acc, c| if c == '.' { acc + 1 } else { acc });
    num_dots == 4
}

pub fn extract_association_claims(pdu: &PreconnectionPdu, config: &Config) -> Result<JetAssociationTokenClaims, io::Error> {
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

    if claims.contains_secrets() && !is_encrypted {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Received a non encrypted JWT containing secrets. This is unacceptable, do it right!",
        ));
    }

    Ok(claims)
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

/// Returns the decoded preconnection PDU and leftover bytes
pub async fn read_preconnection_pdu(stream: &mut TcpStream) -> io::Result<(PreconnectionPdu, BytesMut)> {
    let mut buf = BytesMut::with_capacity(512);

    loop {
        stream.read_buf(&mut buf).await?;

        match decode_preconnection_pdu(&mut buf)? {
            Some(pdu) => {
                let leftover_bytes = buf.split_off(pdu.buffer_length());
                return Ok((pdu, leftover_bytes));
            }
            None => continue,
        }
    }
}
