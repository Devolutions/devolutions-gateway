// TODO: remove after
#![allow(dead_code)]

#[cfg(test)]
mod tests;

use std::{
    fmt,
    io::{self, prelude::*},
};

use bitflags::bitflags;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

use crate::{SecurityProtocol, Settings};

const TPKT_HEADER_LENGTH: usize = 4;

const TPDU_DATA_HEADER_LENGTH: usize = 3;
const TPDU_CONNECTION_REQUEST_HEADER_LENGTH: usize = 7;
const TPDU_CONNECTION_CONFIRM_HEADER_LENGTH: usize = 7;
const TPDU_DISCONNECT_REQUEST_HEADER_LENGTH: usize = 7;

const TPDU_DATA_LENGTH: usize = TPKT_HEADER_LENGTH + TPDU_DATA_HEADER_LENGTH;
const TPDU_CONNECTION_REQUEST_LENGTH: usize = TPKT_HEADER_LENGTH + TPDU_CONNECTION_REQUEST_HEADER_LENGTH;
const TPDU_CONNECTION_CONFIRM_LENGTH: usize = TPKT_HEADER_LENGTH + TPDU_CONNECTION_CONFIRM_HEADER_LENGTH;
const TPDU_DISCONNECT_REQUEST_LENGTH: usize = TPKT_HEADER_LENGTH + TPDU_DISCONNECT_REQUEST_HEADER_LENGTH;

const RDP_NEG_DATA_LENGTH: u16 = 8;

#[derive(Debug, PartialEq, FromPrimitive, ToPrimitive)]
enum NegotiationMessage {
    NegotiationRequest = 1,
    NegotiationResponse = 2,
    NegotiationFailure = 3,
}

#[derive(Debug, PartialEq, FromPrimitive, ToPrimitive)]
enum NegotiationFailureCodes {
    SSLRequiredByServer = 1,
    SSLNotAllowedByServer = 2,
    SSLCertNotOnServer = 3,
    InconsistentFlags = 4,
    HybridRequiredByServer = 5,
    SSLWithUserAuthRequiredByServer = 6,
}

#[derive(Debug, PartialEq, FromPrimitive, ToPrimitive)]
enum X224TPDUType {
    ConnectionRequest = 0xE0,
    ConnectionConfirm = 0xD0,
    DisconnectRequest = 0x80,
    Data = 0xF0,
    Error = 0x70,
}

bitflags! {
    /// https://msdn.microsoft.com/en-us/library/cc240500.aspx
    #[derive(Default)]
    struct NegotiationRequestFlags: u8 {
        const RestrictedAdminModeRequied = 0x01;
        const RedirectedAuthenticationModeRequied = 0x02;
        const CorrelationInfoPresent = 0x08;
    }
}

bitflags! {
    /// https://msdn.microsoft.com/en-us/library/cc240506.aspx
    #[derive(Default)]
    struct NegotiationResponseFlags: u8 {
        const ExtendedClientDataSupported = 0x01;
        const DynvcGfxProtocolSupported = 0x02;
        const RdpNegRspReserved = 0x04;
        const RestrictedAdminModeSupported = 0x08;
        const RedirectedAuthenticationModeSupported = 0x10;
    }
}

fn send_negotiation_request(transport: impl io::Write, settings: &Settings) -> io::Result<u64> {
    let length = write_tpkt_tpdu_message(transport, X224TPDUType::ConnectionRequest, 0, |buffer| {
        write!(buffer, "Cookie: mstshash={}", settings.username)?;
        buffer.write_u8('\r' as u8)?;
        buffer.write_u8('\n' as u8)?;

        if settings.security_protocol.bits() > SecurityProtocol::RDP.bits() {
            buffer.write_u8(NegotiationMessage::NegotiationRequest.to_u8().unwrap())?;
            let restricted_admin_mode_required = 0;
            buffer.write_u8(restricted_admin_mode_required)?;
            buffer.write_u16::<LittleEndian>(RDP_NEG_DATA_LENGTH)?;
            buffer.write_u32::<LittleEndian>(settings.security_protocol.bits())?;
        }

        Ok(())
    })?;

    Ok(length)
}

fn receive_nego_response(
    mut stream: impl io::Read,
) -> Result<(SecurityProtocol, NegotiationResponseFlags), NegotiationError> {
    let mut buffer = Vec::with_capacity(512);
    read_tpkt_pdu(&mut buffer, &mut stream)?;
    let mut slice = buffer.as_slice();
    let (length, code) = parse_tdpu_header(&mut slice)?;

    if code != X224TPDUType::ConnectionConfirm {
        return Err(NegotiationError::IOError(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected X224 connection confirm",
        )));
    }

    if length <= 6 {
        return Err(NegotiationError::IOError(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid negotiation response",
        )));
    }

    let neg_resp = NegotiationMessage::from_u8(slice.read_u8()?).ok_or_else(|| {
        NegotiationError::IOError(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid negotiation response code",
        ))
    })?;
    let flags = NegotiationResponseFlags::from_bits(slice.read_u8()?).ok_or_else(|| {
        NegotiationError::IOError(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid negotiation response flags",
        ))
    })?;
    let _length = slice.read_u16::<LittleEndian>()?;

    if neg_resp == NegotiationMessage::NegotiationResponse {
        let selected_protocol = SecurityProtocol::from_bits(slice.read_u32::<LittleEndian>()?).ok_or_else(|| {
            NegotiationError::IOError(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid security protocol code",
            ))
        })?;
        Ok((selected_protocol, flags))
    } else if neg_resp == NegotiationMessage::NegotiationFailure {
        let error = slice.read_u32::<LittleEndian>()?;
        Err(NegotiationError::NegotiationFailure(error))
    } else {
        Err(NegotiationError::IOError(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid negotiation response code",
        )))
    }
}

fn parse_request_cookie(mut stream: impl io::BufRead) -> io::Result<String> {
    let mut start = String::new();
    stream.by_ref().take(17).read_to_string(&mut start)?;

    if start == "Cookie: mstshash=" {
        let mut cookie = String::new();
        stream.read_line(&mut cookie)?;
        match cookie.pop() {
            Some('\n') => (),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "cookie message uncorrectly terminated",
                ));
            }
        }
        cookie.pop(); // cr

        Ok(cookie)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or unsuppored cookie message",
        ))
    }
}

fn parse_negotiation_request(
    mut stream: impl io::Read,
) -> io::Result<(String, NegotiationRequestFlags, SecurityProtocol)> {
    let mut buffer = Vec::with_capacity(512);
    read_tpkt_pdu(&mut buffer, &mut stream)?;
    let mut slice = buffer.as_slice();
    let (_length, code) = parse_tdpu_header(&mut slice)?;

    if code != X224TPDUType::ConnectionRequest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid connection request code",
        ));
    }

    let cookie = parse_request_cookie(&mut slice)?;

    if slice.len() >= 8 {
        let neg_req = NegotiationMessage::from_u8(slice.read_u8()?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid negotiation request code"))?;
        if neg_req != NegotiationMessage::NegotiationRequest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid negotiation request code",
            ));
        }

        let flags = NegotiationRequestFlags::from_bits(slice.read_u8()?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid negotiation request flags"))?;
        let _length = slice.read_u16::<LittleEndian>()?;
        let protocol = SecurityProtocol::from_bits(slice.read_u32::<LittleEndian>()?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid security protocol code"))?;

        Ok((cookie, flags, protocol))
    } else {
        Ok((cookie, NegotiationRequestFlags::default(), SecurityProtocol::RDP))
    }
}

fn write_negotiation_response(
    transport: impl io::Write,
    flags: NegotiationResponseFlags,
    protocol: SecurityProtocol,
    src_ref: u16,
) -> io::Result<u64> {
    let length = write_tpkt_tpdu_message(transport, X224TPDUType::ConnectionConfirm, src_ref, |buffer| {
        write_negotiation_data(
            buffer,
            NegotiationMessage::NegotiationResponse,
            flags.bits(),
            protocol.bits(),
        )
    })?;

    Ok(length)
}

fn write_negotiation_response_error(
    transport: impl io::Write,
    flags: NegotiationResponseFlags,
    protocol: SecurityProtocol,
    src_ref: u16,
) -> io::Result<u64> {
    let length = write_tpkt_tpdu_message(transport, X224TPDUType::ConnectionConfirm, src_ref, |buffer| {
        write_negotiation_data(
            buffer,
            NegotiationMessage::NegotiationFailure,
            flags.bits(),
            protocol.bits() & !0x80000000,
        )
    })?;

    Ok(length)
}

fn write_negotiation_data(
    cursor: &mut io::Cursor<Vec<u8>>,
    message: NegotiationMessage,
    flags: u8,
    data: u32,
) -> io::Result<()> {
    cursor.write_u8(message.to_u8().unwrap())?;
    cursor.write_u8(flags)?;
    cursor.write_u16::<LittleEndian>(RDP_NEG_DATA_LENGTH)?;
    cursor.write_u32::<LittleEndian>(data)?;

    Ok(())
}

fn write_tpkt_tpdu_message(
    mut transport: impl io::Write,
    code: X224TPDUType,
    src_ref: u16,
    callback: impl Fn(&mut io::Cursor<Vec<u8>>) -> io::Result<()>,
) -> io::Result<u64> {
    let mut buffer = io::Cursor::new(Vec::with_capacity(512));

    buffer.seek(io::SeekFrom::Start(TPDU_CONNECTION_REQUEST_LENGTH as u64))?;
    callback(&mut buffer)?;
    let length = buffer.position();
    buffer.seek(io::SeekFrom::Start(0))?;

    write_tpkt_header(&mut buffer, length as u16)?;
    write_tpdu_header(&mut buffer, (length - TPKT_HEADER_LENGTH as u64) as u8, code, src_ref)?;

    transport.write_all(buffer.into_inner().as_slice())?;
    transport.flush()?;

    Ok(length)
}

fn write_tpkt_header(mut stream: impl io::Write, length: u16) -> io::Result<()> {
    let version = 3;

    stream.write_u8(version)?;
    stream.write_u8(0)?; // reserved
    stream.write_u16::<BigEndian>(length)?;

    Ok(())
}

fn read_tpkt_pdu(buffer: &mut Vec<u8>, mut stream: impl io::Read) -> io::Result<u64> {
    let version = stream.read_u8()?;
    if version != 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a tpkt header"));
    }

    let _reserved = stream.read_u8()?;
    let data_len = u64::from(stream.read_u16::<BigEndian>()? - TPKT_HEADER_LENGTH as u16);

    let bytes_read = stream.take(data_len).read_to_end(buffer)?;
    if bytes_read == data_len as usize {
        Ok(data_len)
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
    }
}

fn write_tpdu_header(mut stream: impl io::Write, length: u8, code: X224TPDUType, src_ref: u16) -> io::Result<()> {
    // tpdu header length field doesn't include the length of the length field
    stream.write_u8(length - 1)?;
    stream.write_u8(code.to_u8().unwrap())?;

    if code == X224TPDUType::Data {
        let eot = 0x80;
        stream.write_u8(eot)?;
    } else {
        let dst_ref = 0;
        stream.write_u16::<LittleEndian>(dst_ref)?;
        stream.write_u16::<LittleEndian>(src_ref)?;
        let class = 0;
        stream.write_u8(class)?;
    }

    Ok(())
}

fn parse_tdpu_header(mut stream: impl io::Read) -> io::Result<(u8, X224TPDUType)> {
    let length = stream.read_u8()?;
    let code = X224TPDUType::from_u8(stream.read_u8()?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid X224 TPDU type"))?;

    if code == X224TPDUType::Data {
        let _eof = stream.read_u8()?;
    } else {
        let _dst_ref = stream.read_u16::<LittleEndian>()?;
        let _src_ref = stream.read_u16::<LittleEndian>()?;
        let _class = stream.read_u8()?;
    }

    Ok((length, code))
}

#[derive(Debug)]
enum NegotiationError {
    IOError(io::Error),
    NegotiationFailure(u32),
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NegotiationError::IOError(e) => e.fmt(f),
            NegotiationError::NegotiationFailure(code) => {
                write!(f, "Received negotiation error from server, code={}", code)
            }
        }
    }
}

impl From<io::Error> for NegotiationError {
    fn from(e: io::Error) -> Self {
        NegotiationError::IOError(e)
    }
}
