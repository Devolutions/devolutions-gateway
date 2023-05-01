use std::io;
use std::net::IpAddr;

use anyhow::Context as _;
use bytes::BytesMut;
use ironrdp_pdu::pcb::PreconnectionBlob;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::config::Conf;
use crate::token::{AccessTokenClaims, AssociationTokenClaims, CurrentJrl, TokenCache, TokenValidator};

pub fn extract_association_claims(
    pcb: &PreconnectionBlob,
    source_ip: IpAddr,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
) -> anyhow::Result<AssociationTokenClaims> {
    let token = pcb.v2_payload.as_deref().context("V2 payload missing from RDP PCB")?;

    if conf.debug.dump_tokens {
        debug!(token, "**DEBUG OPTION**");
    }

    let delegation_key = conf.delegation_private_key.as_ref();

    let claims = if conf.debug.disable_token_validation {
        #[allow(deprecated)]
        crate::token::unsafe_debug::dangerous_validate_token(token, delegation_key)
    } else {
        TokenValidator::builder()
            .source_ip(source_ip)
            .provisioner_key(&conf.provisioner_public_key)
            .delegation_key(delegation_key)
            .token_cache(token_cache)
            .revocation_list(jrl)
            .gw_id(conf.id)
            .subkey(conf.sub_provisioner_public_key.as_ref())
            .build()
            .validate(token)
    }
    .context("token validation")?;

    match claims {
        AccessTokenClaims::Association(claims) => Ok(claims),
        _ => anyhow::bail!("unexpected token type"),
    }
}

pub fn decode_preconnection_pdu(buf: &[u8]) -> Result<Option<PreconnectionBlob>, io::Error> {
    match ironrdp_pdu::decode::<PreconnectionBlob>(buf) {
        Ok(preconnection_pdu) => Ok(Some(preconnection_pdu)),
        Err(ironrdp_pdu::Error::NotEnoughBytes { .. }) => Ok(None),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}

/// Returns the decoded preconnection PDU and leftover bytes
pub async fn read_preconnection_pdu(stream: &mut TcpStream) -> io::Result<(PreconnectionBlob, BytesMut)> {
    let mut buf = BytesMut::with_capacity(1024);

    loop {
        let n_read = stream.read_buf(&mut buf).await?;

        if n_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough bytes to decode preconnection PDU",
            ));
        }

        if let Some(pdu) = decode_preconnection_pdu(&buf)? {
            let leftover_bytes = buf.split_off(ironrdp_pdu::size(&pdu));
            return Ok((pdu, leftover_bytes));
        }
    }
}
