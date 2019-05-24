#[cfg(test)]
mod tests;

use std::{error::Error, fmt, io};

use byteorder::ReadBytesExt;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::{per, tpdu::X224TPDUType};

const MCS_BASE_CHANNEL_ID: u16 = 1001;
const MCS_RESULT_ENUM_LENGTH: u8 = 16;

/// Implements the Fast-Path RDP message header PDU.
#[derive(Debug)]
pub struct Fastpath {
    pub encryption_flags: u8,
    pub number_events: u8,
    pub length: u16,
}

/// The kind of the RDP header message that may carry additional data.
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

/// Contains the channel ID and the length of the data. This structure is a part of the
/// [`RdpHeaderMessage`](enum.RdpHeaderMessage.html).
#[derive(Debug, PartialEq)]
pub struct SendDataContext {
    channel_id: u16,
    length: u16,
}

/// The reason of [`DisconnectProviderUltimatum`](enum.RdpHeaderMessage.html).
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

/// Parses the data received as an argument and returns a
/// [`Fastpath`](struct.Fastpath.html) structure upon success.
///
/// # Arguments
///
/// * `stream` - the type to read data from
pub fn parse_fastpath_header(mut stream: impl io::Read) -> Result<(Fastpath, u16), FastpathParsingError> {
    let header = stream.read_u8()?;

    let (length, sizeof_length) = per::read_length(&mut stream)?;
    if length < sizeof_length as u16 + 1 {
        return Err(FastpathParsingError::NullLength(sizeof_length as usize + 1));
    }

    let pdu_length = length - sizeof_length as u16 - 1;

    Ok((
        Fastpath {
            encryption_flags: (header & 0xC0) >> 6,
            number_events: (header & 0x3C) >> 2,
            length: pdu_length,
        },
        length,
    ))
}

/// Parses the data received as an argument and returns an
/// [`RdpHeaderMessage`](enum.RdpHeaderMessage.html) upon success.
///
/// # Arguments
///
/// * `stream` - the type to read data from
/// * `code` - the [X.224 message code](struct.X224TPDUType.html)
pub fn parse_rdp_header(mut stream: impl io::Read, code: X224TPDUType) -> io::Result<RdpHeaderMessage> {
    if code != X224TPDUType::Data {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid X224 code, expected data",
        ));
    }

    let choice = per::read_choice(&mut stream)?;
    let mcspdu = DomainMCSPDU::from_u8(choice >> 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid domain MCSPDU"))?;
    match mcspdu {
        DomainMCSPDU::ErectDomainRequest => {
            let _sub_height = per::read_u32(&mut stream)?;
            let _sub_interval = per::read_u32(&mut stream)?;
            Ok(RdpHeaderMessage::ErectDomainRequest)
        }
        DomainMCSPDU::AttachUserRequest => Ok(RdpHeaderMessage::AttachUserRequest),
        DomainMCSPDU::AttachUserConfirm => {
            let _enumerated = per::read_enum(&mut stream, MCS_RESULT_ENUM_LENGTH)?;
            let user_id = per::read_u16(&mut stream, MCS_BASE_CHANNEL_ID)?;

            Ok(RdpHeaderMessage::AttachUserId(user_id))
        }
        DomainMCSPDU::ChannelJoinRequest => {
            let _user_id = per::read_u16(&mut stream, MCS_BASE_CHANNEL_ID)?;
            let channel_id = per::read_u16(&mut stream, 0)?;

            Ok(RdpHeaderMessage::ChannelIdJoinRequest(channel_id))
        }
        DomainMCSPDU::ChannelJoinConfirm => {
            let _result = per::read_enum(&mut stream, MCS_RESULT_ENUM_LENGTH)?;
            let _initiator = per::read_u16(&mut stream, MCS_BASE_CHANNEL_ID)?;
            let _requested = per::read_u16(&mut stream, 0)?;
            let channel_id = per::read_u16(&mut stream, 0)?;

            Ok(RdpHeaderMessage::ChannelIdJoinConfirm(channel_id))
        }
        DomainMCSPDU::SendDataRequest | DomainMCSPDU::SendDataIndication => {
            let _indicator = per::read_u16(&mut stream, MCS_BASE_CHANNEL_ID)?;
            let channel_id = per::read_u16(&mut stream, 0)?;
            let _data_priority_and_segmentation = stream.read_u8()?;
            let (length, _) = per::read_length(&mut stream)?;

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

/// The type of a Fast-Path parsing error. Includes *length error* and *I/O error*.
#[derive(Debug)]
pub enum FastpathParsingError {
    /// Used in the length-related error during Fast-Path parsing.
    NullLength(usize),
    /// May be used in I/O related errors such as receiving empty Fast-Path packages.
    IoError(io::Error),
}

impl fmt::Display for FastpathParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FastpathParsingError::NullLength(_bytes_read) => {
                write!(f, "Received invalid Fast-Path package with 0 length")
            }
            FastpathParsingError::IoError(e) => e.fmt(f),
        }
    }
}

impl Error for FastpathParsingError {}

impl From<io::Error> for FastpathParsingError {
    fn from(e: io::Error) -> Self {
        FastpathParsingError::IoError(e)
    }
}
