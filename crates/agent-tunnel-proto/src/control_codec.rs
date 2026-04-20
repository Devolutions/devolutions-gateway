//! Wire-format encoding and decoding for [`ControlMessage`] and [`CertRenewalResult`].
//!
//! Kept separate from `control.rs` so the type definitions there can be read as
//! pure data contracts, and every byte-layout decision is collected in one place.

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use ipnetwork::Ipv4Network;

use crate::codec::{self, Decode, Encode};
use crate::control::{CertRenewalResult, ControlMessage, DomainAdvertisement, DomainName};
use crate::error::ProtoError;

// Wire format message type tags.
const TAG_ROUTE_ADVERTISE: u8 = 0x01;
const TAG_HEARTBEAT: u8 = 0x02;
const TAG_HEARTBEAT_ACK: u8 = 0x03;
const TAG_CERT_RENEWAL_REQUEST: u8 = 0x04;
const TAG_CERT_RENEWAL_RESPONSE: u8 = 0x05;

// CertRenewalResult sub-tags.
const TAG_CERT_SUCCESS: u8 = 0x00;
const TAG_CERT_ERROR: u8 = 0x01;

impl Encode for ControlMessage {
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::RouteAdvertise {
                protocol_version,
                epoch,
                subnets,
                domains,
            } => {
                buf.put_u8(TAG_ROUTE_ADVERTISE);
                buf.put_u16(*protocol_version);
                buf.put_u64(*epoch);
                encode_subnets(buf, subnets);
                encode_domains(buf, domains);
            }
            Self::Heartbeat {
                protocol_version,
                timestamp_ms,
                active_stream_count,
            } => {
                buf.put_u8(TAG_HEARTBEAT);
                buf.put_u16(*protocol_version);
                buf.put_u64(*timestamp_ms);
                buf.put_u32(*active_stream_count);
            }
            Self::HeartbeatAck {
                protocol_version,
                timestamp_ms,
            } => {
                buf.put_u8(TAG_HEARTBEAT_ACK);
                buf.put_u16(*protocol_version);
                buf.put_u64(*timestamp_ms);
            }
            Self::CertRenewalRequest {
                protocol_version,
                csr_pem,
            } => {
                buf.put_u8(TAG_CERT_RENEWAL_REQUEST);
                buf.put_u16(*protocol_version);
                codec::put_string(buf, csr_pem);
            }
            Self::CertRenewalResponse {
                protocol_version,
                result,
            } => {
                buf.put_u8(TAG_CERT_RENEWAL_RESPONSE);
                buf.put_u16(*protocol_version);
                encode_cert_renewal_result(buf, result);
            }
        }
    }
}

impl Decode for ControlMessage {
    fn decode(mut buf: Bytes) -> Result<Self, ProtoError> {
        codec::ensure_remaining(buf.remaining(), 1, "control message tag")?;
        let tag = buf.get_u8();

        match tag {
            TAG_ROUTE_ADVERTISE => {
                codec::ensure_remaining(buf.remaining(), 2 + 8, "RouteAdvertise header")?;
                let protocol_version = buf.get_u16();
                let epoch = buf.get_u64();
                let subnets = decode_subnets(&mut buf)?;
                let domains = decode_domains(&mut buf)?;
                Ok(Self::RouteAdvertise {
                    protocol_version,
                    epoch,
                    subnets,
                    domains,
                })
            }
            TAG_HEARTBEAT => {
                codec::ensure_remaining(buf.remaining(), 2 + 8 + 4, "Heartbeat")?;
                let protocol_version = buf.get_u16();
                let timestamp_ms = buf.get_u64();
                let active_stream_count = buf.get_u32();
                Ok(Self::Heartbeat {
                    protocol_version,
                    timestamp_ms,
                    active_stream_count,
                })
            }
            TAG_HEARTBEAT_ACK => {
                codec::ensure_remaining(buf.remaining(), 2 + 8, "HeartbeatAck")?;
                let protocol_version = buf.get_u16();
                let timestamp_ms = buf.get_u64();
                Ok(Self::HeartbeatAck {
                    protocol_version,
                    timestamp_ms,
                })
            }
            TAG_CERT_RENEWAL_REQUEST => {
                codec::ensure_remaining(buf.remaining(), 2, "CertRenewalRequest version")?;
                let protocol_version = buf.get_u16();
                let csr_pem = codec::get_string(&mut buf)?;
                Ok(Self::CertRenewalRequest {
                    protocol_version,
                    csr_pem,
                })
            }
            TAG_CERT_RENEWAL_RESPONSE => {
                codec::ensure_remaining(buf.remaining(), 2, "CertRenewalResponse version")?;
                let protocol_version = buf.get_u16();
                let result = decode_cert_renewal_result(&mut buf)?;
                Ok(Self::CertRenewalResponse {
                    protocol_version,
                    result,
                })
            }
            _ => Err(ProtoError::UnknownTag { tag }),
        }
    }
}

// ---------------------------------------------------------------------------
// Subnet encode/decode
// ---------------------------------------------------------------------------

// Each subnet is encoded as `[4B ipv4_octets][1B prefix]`. No family tag —
// if IPv6 is ever added, `protocol_version` bumps and the format can
// reintroduce a tag cleanly.
#[expect(
    clippy::cast_possible_truncation,
    reason = "count bounded by MAX_CONTROL_MESSAGE_SIZE"
)]
fn encode_subnets(buf: &mut BytesMut, subnets: &[Ipv4Network]) {
    buf.put_u32(subnets.len() as u32);
    for subnet in subnets {
        buf.put_slice(&subnet.ip().octets());
        buf.put_u8(subnet.prefix());
    }
}

fn decode_subnets(buf: &mut Bytes) -> Result<Vec<Ipv4Network>, ProtoError> {
    codec::ensure_remaining(buf.remaining(), 4, "subnet count")?;
    let count = buf.get_u32() as usize;
    let mut subnets = Vec::with_capacity(count);

    for _ in 0..count {
        codec::ensure_remaining(buf.remaining(), 4 + 1, "IPv4 subnet")?;
        let mut octets = [0u8; 4];
        buf.copy_to_slice(&mut octets);
        let prefix = buf.get_u8();
        let ip = std::net::Ipv4Addr::from(octets);
        let network = Ipv4Network::new(ip, prefix).map_err(|_| ProtoError::InvalidField {
            field: "subnet",
            reason: "invalid IPv4 prefix length",
        })?;
        subnets.push(network);
    }

    Ok(subnets)
}

// ---------------------------------------------------------------------------
// Domain encode/decode
// ---------------------------------------------------------------------------

#[expect(
    clippy::cast_possible_truncation,
    reason = "count bounded by MAX_CONTROL_MESSAGE_SIZE"
)]
fn encode_domains(buf: &mut BytesMut, domains: &[DomainAdvertisement]) {
    buf.put_u32(domains.len() as u32);
    for adv in domains {
        codec::put_string(buf, adv.domain.as_str());
        buf.put_u8(u8::from(adv.auto_detected));
    }
}

fn decode_domains(buf: &mut Bytes) -> Result<Vec<DomainAdvertisement>, ProtoError> {
    codec::ensure_remaining(buf.remaining(), 4, "domain count")?;
    let count = buf.get_u32() as usize;
    let mut domains = Vec::with_capacity(count);

    for _ in 0..count {
        let domain_str = codec::get_string(buf)?;
        codec::ensure_remaining(buf.remaining(), 1, "auto_detected flag")?;
        let auto_detected = buf.get_u8() != 0;
        domains.push(DomainAdvertisement {
            domain: DomainName::new(domain_str),
            auto_detected,
        });
    }

    Ok(domains)
}

// ---------------------------------------------------------------------------
// CertRenewalResult encode/decode
// ---------------------------------------------------------------------------

fn encode_cert_renewal_result(buf: &mut BytesMut, result: &CertRenewalResult) {
    match result {
        CertRenewalResult::Success {
            client_cert_pem,
            gateway_ca_cert_pem,
        } => {
            buf.put_u8(TAG_CERT_SUCCESS);
            codec::put_string(buf, client_cert_pem);
            codec::put_string(buf, gateway_ca_cert_pem);
        }
        CertRenewalResult::Error { reason } => {
            buf.put_u8(TAG_CERT_ERROR);
            codec::put_string(buf, reason);
        }
    }
}

fn decode_cert_renewal_result(buf: &mut Bytes) -> Result<CertRenewalResult, ProtoError> {
    codec::ensure_remaining(buf.remaining(), 1, "CertRenewalResult tag")?;
    let tag = buf.get_u8();
    match tag {
        TAG_CERT_SUCCESS => {
            let client_cert_pem = codec::get_string(buf)?;
            let gateway_ca_cert_pem = codec::get_string(buf)?;
            Ok(CertRenewalResult::Success {
                client_cert_pem,
                gateway_ca_cert_pem,
            })
        }
        TAG_CERT_ERROR => {
            let reason = codec::get_string(buf)?;
            Ok(CertRenewalResult::Error { reason })
        }
        _ => Err(ProtoError::UnknownTag { tag }),
    }
}
