use crate::config::Conf;
use crate::token::{AccessTokenClaims, CurrentJrl, JetAssociationTokenClaims, TokenCache, TokenValidator};
use anyhow::Context as _;
use bytes::{Buf, BytesMut};
use ironrdp::{PduBufferParsing, PreconnectionPdu, PreconnectionPduError};
use std::io;
use std::net::IpAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub fn extract_association_claims(
    pdu: &PreconnectionPdu,
    source_ip: IpAddr,
    config: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> anyhow::Result<JetAssociationTokenClaims> {
    let token = pdu.payload.as_deref().context("Empty preconnection PDU")?;

    if config.debug.dump_tokens {
        debug!(token, "**DEBUG OPTION**");
    }

    let delegation_key = config.delegation_private_key.as_ref();

    let claims = if config.debug.disable_token_validation {
        #[allow(deprecated)]
        crate::token::unsafe_debug::dangerous_validate_token(token, delegation_key)
    } else {
        TokenValidator::builder()
            .source_ip(source_ip)
            .provisioner_key(&config.provisioner_public_key)
            .delegation_key(delegation_key)
            .token_cache(token_cache)
            .revocation_list(jrl)
            .gw_id(config.id)
            .subkey(None)
            .build()
            .validate(token)
    }
    .context("token validation")?;

    match claims {
        AccessTokenClaims::Association(claims) => Ok(claims),
        _ => anyhow::bail!("unexpected token type"),
    }
}

pub fn decode_preconnection_pdu(buf: &[u8]) -> Result<Option<PreconnectionPdu>, io::Error> {
    match PreconnectionPdu::from_buffer(buf) {
        Ok(preconnection_pdu) => Ok(Some(preconnection_pdu)),
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
