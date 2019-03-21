#[cfg(test)]
mod tests;

use std::io;

use byteorder::{BigEndian, ReadBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::tpdu::X224TPDUType;

const MCS_BASE_CHANNEL_ID: u16 = 1001;
const MCS_RESULT_ENUM_LENGTH: u8 = 16;

#[derive(Debug)]
pub struct Fastpath {
    pub encryption_flags: u8,
    pub number_events: u8,
    pub length: u16,
}

#[derive(Debug, PartialEq)]
pub enum RdpHeaderMessage {
    ErectDomainRequest,
    AttachUserRequest,
    AttachUserId(u16),
    ChannelIdJoinRequest(u16),
    ChannelIdJoinConfirm(u16),
    SendData(SendDataContext),
    DisconnectProviderUltimatum(DisconnectUltimatumReason),
}

#[derive(Debug, PartialEq)]
pub struct SendDataContext {
    channel_id: u16,
    length: u16,
}

#[repr(u8)]
#[derive(Debug, PartialEq, FromPrimitive)]
pub enum DisconnectUltimatumReason {
    DomainDisconnected = 0,
    ProviderInitiated = 1,
    TokenPurged = 2,
    UserRequested = 3,
    ChannelPurged = 4,
}

#[repr(u8)]
#[derive(Debug, FromPrimitive)]
enum DomainMCSPDU {
    ErectDomainRequest = 1,
    DisconnectProviderUltimatum = 8,
    AttachUserRequest = 10,
    AttachUserConfirm = 11,
    ChannelJoinRequest = 14,
    ChannelJoinConfirm = 15,
    SendDataRequest = 25,
    SendDataIndication = 26,
}

pub fn parse_fastpath_header(mut stream: impl io::Read) -> io::Result<(Fastpath, u16)> {
    let header = stream.read_u8()?;

    let (length, sizeof_length) = per_read_length(&mut stream)?;
    let pdu_length = length
        .checked_sub(sizeof_length + 1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid fastpath length"))?;

    Ok((
        Fastpath {
            encryption_flags: (header & 0xC0) >> 6,
            number_events: (header & 0x3C) >> 2,
            length: pdu_length,
        },
        length,
    ))
}

pub fn parse_rdp_header(mut stream: impl io::Read, code: X224TPDUType) -> io::Result<RdpHeaderMessage> {
    if code != X224TPDUType::Data {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid X224 code, expected data",
        ));
    }

    let choice = per_read_choice(&mut stream)?;
    let mcspdu = DomainMCSPDU::from_u8(choice >> 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid domain MCSPDU"))?;
    match mcspdu {
        DomainMCSPDU::ErectDomainRequest => {
            let _sub_height = per_read_int(&mut stream)?;
            let _sub_interval = per_read_int(&mut stream)?;
            Ok(RdpHeaderMessage::ErectDomainRequest)
        }
        DomainMCSPDU::AttachUserRequest => Ok(RdpHeaderMessage::AttachUserRequest),
        DomainMCSPDU::AttachUserConfirm => {
            let _enumerated = per_read_enumerated(&mut stream, MCS_RESULT_ENUM_LENGTH)?;
            let user_id = per_read_u16(&mut stream, MCS_BASE_CHANNEL_ID)?;

            Ok(RdpHeaderMessage::AttachUserId(user_id))
        }
        DomainMCSPDU::ChannelJoinRequest => {
            let _user_id = per_read_u16(&mut stream, MCS_BASE_CHANNEL_ID)?;
            let channel_id = per_read_u16(&mut stream, 0)?;

            Ok(RdpHeaderMessage::ChannelIdJoinRequest(channel_id))
        }
        DomainMCSPDU::ChannelJoinConfirm => {
            let _result = per_read_enumerated(&mut stream, MCS_RESULT_ENUM_LENGTH)?;
            let _initiator = per_read_u16(&mut stream, MCS_BASE_CHANNEL_ID)?;
            let _requested = per_read_u16(&mut stream, 0)?;
            let channel_id = per_read_u16(&mut stream, 0)?;

            Ok(RdpHeaderMessage::ChannelIdJoinConfirm(channel_id))
        }
        DomainMCSPDU::SendDataRequest | DomainMCSPDU::SendDataIndication => {
            let _indicator = per_read_u16(&mut stream, MCS_BASE_CHANNEL_ID)?;
            let channel_id = per_read_u16(&mut stream, 0)?;
            let _data_priority_and_segmentation = stream.read_u8()?;
            let (length, _) = per_read_length(&mut stream)?;

            Ok(RdpHeaderMessage::SendData(SendDataContext { length, channel_id }))
        }
        DomainMCSPDU::DisconnectProviderUltimatum => {
            let b = stream.read_u8()?;
            let reason = DisconnectUltimatumReason::from_u8(((choice & 0x01) << 1) | (b >> 7)).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown disconnect provider ultimatum reason",
                )
            })?;
            Ok(RdpHeaderMessage::DisconnectProviderUltimatum(reason))
        }
    }
}

fn per_read_length(mut stream: impl io::Read) -> io::Result<(u16, u16)> {
    let a = stream.read_u8()?;

    if a & 0x80 != 0 {
        let b = stream.read_u8()?;
        let length = ((u16::from(a) & !0x80) << 8) + u16::from(b);
        Ok((length, 2))
    } else {
        Ok((u16::from(a), 1))
    }
}

fn per_read_choice(mut stream: impl io::Read) -> io::Result<u8> {
    stream.read_u8()
}

fn per_read_u16(mut stream: impl io::Read, min: u16) -> io::Result<u16> {
    let v = min + stream.read_u16::<BigEndian>()?;

    if v < 0xFFFF {
        Ok(v)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "invalid PER u16"))
    }
}

fn per_read_int(mut stream: impl io::Read) -> io::Result<u16> {
    let (length, _) = per_read_length(&mut stream)?;

    match length {
        0 => Ok(0),
        1 => Ok(stream.read_u8()? as u16),
        2 => stream.read_u16::<BigEndian>(),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid PER length: {}", length),
        )),
    }
}

fn per_read_enumerated(mut stream: impl io::Read, count: u8) -> io::Result<u8> {
    let enumerated = stream.read_u8()?;

    if enumerated > count - 1 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Enumerated value ({}) does not fall within expected range", enumerated),
        ))
    } else {
        Ok(enumerated)
    }
}
