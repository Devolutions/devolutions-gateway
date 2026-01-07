use std::io;
use std::net::IpAddr;

use anyhow::Context as _;
use bytes::BytesMut;
use ironrdp_pdu::pcb::PreconnectionBlob;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::config::Conf;
use crate::recording::ActiveRecordings;
use crate::session::DisconnectedInfo;
use crate::token::{AccessTokenClaims, AssociationTokenClaims, CurrentJrl, TokenCache, TokenValidator};

pub fn extract_association_claims(
    token: &str,
    source_ip: IpAddr,
    conf: &Conf,
    token_cache: &TokenCache,
    jrl: &CurrentJrl,
    active_recordings: &ActiveRecordings,
    disconnected_info: Option<DisconnectedInfo>,
) -> anyhow::Result<AssociationTokenClaims> {
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
            .active_recordings(active_recordings)
            .disconnected_info(disconnected_info)
            .build()
            .validate(token)
    }
    .context("token validation")?;

    match claims {
        AccessTokenClaims::Association(claims) => Ok(claims),
        _ => anyhow::bail!("unexpected token type"),
    }
}

fn decode_pcb(buf: &[u8]) -> Result<Option<(PreconnectionBlob, usize)>, io::Error> {
    let mut cursor = ironrdp_core::ReadCursor::new(buf);

    match ironrdp_core::decode_cursor::<PreconnectionBlob>(&mut cursor) {
        Ok(pcb) => {
            let pdu_size = ironrdp_core::size(&pcb);
            let read_len = cursor.pos();

            // NOTE: sanity check (reporting the wrong number will corrupt the communication)
            if read_len != pdu_size {
                warn!(
                    read_len,
                    pdu_size, "inconsistent lengths when reading preconnection blob"
                );
            }

            Ok(Some((pcb, read_len)))
        }
        Err(e) if matches!(e.kind(), ironrdp_core::DecodeErrorKind::NotEnoughBytes { .. }) => Ok(None),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}

/// Returns the decoded preconnection PDU and leftover bytes
pub async fn read_pcb(mut stream: impl AsyncRead + AsyncWrite + Unpin) -> io::Result<(PreconnectionBlob, BytesMut)> {
    let mut buf = BytesMut::with_capacity(1024);

    loop {
        let n_read = stream.read_buf(&mut buf).await?;

        if n_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough bytes to decode preconnection PDU",
            ));
        }

        if let Some((pdu, read_len)) = decode_pcb(&buf)? {
            let leftover_bytes = buf.split_off(read_len);
            return Ok((pdu, leftover_bytes));
        }
    }
}
