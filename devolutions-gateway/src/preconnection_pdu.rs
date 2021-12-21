use crate::config::Config;
use crate::token::{validate_token, JetAccessTokenClaims, JetAssociationTokenClaims};
use bytes::BytesMut;
use ironrdp::{PduBufferParsing, PreconnectionPdu, PreconnectionPduError};
use std::io;
use std::net::IpAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub fn extract_association_claims(
    pdu: &PreconnectionPdu,
    source_ip: IpAddr,
    config: &Config,
) -> Result<JetAssociationTokenClaims, io::Error> {
    let payload = pdu
        .payload
        .as_deref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty preconnection PDU"))?;

    let provisioner_key = config
        .provisioner_public_key
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Provisioner key is missing"))?;

    let delegation_key = config.delegation_private_key.as_ref();

    match validate_token(payload, source_ip, provisioner_key, delegation_key)? {
        JetAccessTokenClaims::Association(claims) => Ok(claims),
        _ => Err(io::Error::new(io::ErrorKind::Other, "unexpected token type")),
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

/// Returns the decoded preconnection PDU and leftover bytes
pub async fn read_preconnection_pdu(stream: &mut TcpStream) -> io::Result<(PreconnectionPdu, BytesMut)> {
    let mut buf = BytesMut::with_capacity(512);

    loop {
        let n_read = stream.read_buf(&mut buf).await?;

        if n_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough bytes to decode preconnection PDU",
            ));
        }

        if let Some(pdu) = decode_preconnection_pdu(&mut buf)? {
            let leftover_bytes = buf.split_off(pdu.buffer_length());
            return Ok((pdu, leftover_bytes));
        }
    }
}
