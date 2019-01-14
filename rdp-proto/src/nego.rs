// TODO: remove after
#![allow(dead_code)]

#[cfg(test)]
mod tests;

use std::{
    fmt,
    io::{self, prelude::*},
};

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

fn send_negotiation_request(mut transport: impl io::Write, settings: &Settings) -> io::Result<u64> {
    let mut buffer = io::Cursor::new(Vec::with_capacity(512));

    buffer.seek(io::SeekFrom::Start(TPDU_CONNECTION_REQUEST_LENGTH as u64))?;
    write!(buffer, "Cookie: mstshash={}", settings.username)?;
    let cr = 0x0D;
    buffer.write_u8(cr)?;
    let lf = 0x0A;
    buffer.write_u8(lf)?;

    if settings.security_protocol.bits() > SecurityProtocol::RDP.bits() {
        buffer.write_u8(NegotiationMessage::NegotiationRequest.to_u8().unwrap())?;
        let restricted_admin_mode_required = 0;
        buffer.write_u8(restricted_admin_mode_required)?;
        buffer.write_u16::<LittleEndian>(RDP_NEG_DATA_LENGTH)?;
        buffer.write_u32::<LittleEndian>(SecurityProtocol::NLA.bits())?;
    }

    let length = buffer.position();
    buffer.seek(io::SeekFrom::Start(0))?;
    write_tpkt_header(&mut buffer, length as u16)?;
    write_tpdu_header(
        &mut buffer,
        (length - TPKT_HEADER_LENGTH as u64) as u8,
        X224TPDUType::ConnectionRequest,
    )?;

    transport.write_all(buffer.into_inner().as_slice())?;
    transport.flush()?;

    Ok(length)
}

fn receive_nego_response(mut stream: impl io::Read) -> Result<SecurityProtocol, NegotiationError> {
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
    let _flags = slice.read_u8()?;
    let _length = slice.read_u16::<LittleEndian>()?;

    if neg_resp == NegotiationMessage::NegotiationResponse {
        let selected_protocol = SecurityProtocol::from_bits(slice.read_u32::<LittleEndian>()?).ok_or_else(|| {
            NegotiationError::IOError(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid security protocol code",
            ))
        })?;
        Ok(selected_protocol)
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

fn write_tpdu_header(mut stream: impl io::Write, length: u8, code: X224TPDUType) -> io::Result<()> {
    // tpdu header length field doesn't include the length of the length field
    stream.write_u8(length - 1)?;
    stream.write_u8(code.to_u8().unwrap())?;

    if code == X224TPDUType::Data {
        let eot = 0x80;
        stream.write_u8(eot)?;
    } else {
        let dst_ref = 0;
        stream.write_u16::<LittleEndian>(dst_ref)?;
        let src_ref = 0;
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
