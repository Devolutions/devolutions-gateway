#![allow(clippy::unwrap_used)] // FIXME: fix warnings

pub mod accept;
pub mod connect;
pub mod test;

pub use http::StatusCode;

mod utils;

use crate::accept::{JetAcceptReq, JetAcceptRsp};
use crate::connect::{JetConnectReq, JetConnectRsp};
use crate::utils::RequestHelper;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use log::trace;
use std::env;
use std::io::{self, Read};
use std::sync::OnceLock;
use test::{JetTestReq, JetTestRsp};
use uuid::Uuid;

pub const JET_MSG_SIGNATURE: u32 = 0x0054_454A;
pub const JET_MSG_HEADER_SIZE: u32 = 8;
pub const JET_VERSION_V1: u8 = 1;
pub const JET_VERSION_V2: u8 = 2;

const JET_HEADER_VERSION: &str = "Jet-Version";
const JET_HEADER_METHOD: &str = "Jet-Method";
const JET_HEADER_ASSOCIATION: &str = "Jet-Association";
const JET_HEADER_TIMEOUT: &str = "Jet-Timeout";
const JET_HEADER_INSTANCE: &str = "Jet-Instance";
const JET_HEADER_HOST: &str = "Host";
const JET_HEADER_CONNECTION: &str = "Connection";

const JET_MSG_DEFAULT_MASK: u8 = 0x73;

pub fn get_mask_value() -> u8 {
    static JET_MSG_MASK: OnceLock<u8> = OnceLock::new();

    let value = JET_MSG_MASK.get_or_init(|| {
        if let Some(mask) = env::var("JET_MSG_MASK")
            .ok()
            .and_then(|mask| u8::from_str_radix(mask.trim_start_matches("0x"), 16).ok())
        {
            mask
        } else {
            JET_MSG_DEFAULT_MASK
        }
    });

    *value
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JetMessage {
    JetTestReq(JetTestReq),
    JetTestRsp(JetTestRsp),
    JetAcceptReq(JetAcceptReq),
    JetAcceptRsp(JetAcceptRsp),
    JetConnectReq(JetConnectReq),
    JetConnectRsp(JetConnectRsp),
}

struct JetHeader {
    msg_size: u16,
    mask: u8,
}

impl JetMessage {
    pub fn read_request<R: Read>(stream: &mut R) -> Result<Self, Error> {
        let jet_header = JetMessage::read_header(stream)?;
        let payload = JetMessage::read_payload(stream, &jet_header)?;

        trace!("Message received: {payload}");

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);

        if req.parse(payload.as_bytes()).is_ok()
            && let Some(path) = req.path.map(|path| path.to_lowercase())
        {
            if path.starts_with("/jet/accept") {
                return Ok(JetMessage::JetAcceptReq(JetAcceptReq::from_request(&req)?));
            } else if path.starts_with("/jet/connect") {
                return Ok(JetMessage::JetConnectReq(JetConnectReq::from_request(&req)?));
            } else if path.starts_with("/jet/test") {
                return Ok(JetMessage::JetTestReq(JetTestReq::from_request(&req)?));
            } else if path.eq("/")
                && let Some(jet_method) = req.get_header_value("jet-method")
            {
                if jet_method.to_lowercase().eq("accept") {
                    return Ok(JetMessage::JetAcceptReq(JetAcceptReq::from_request(&req)?));
                } else {
                    return Ok(JetMessage::JetConnectReq(JetConnectReq::from_request(&req)?));
                }
            }
        }

        Err(format!("Invalid message received: Payload={payload}").into())
    }

    pub fn read_accept_response<R: Read>(stream: &mut R) -> Result<Self, Error> {
        let jet_header = JetMessage::read_header(stream)?;
        let payload = JetMessage::read_payload(stream, &jet_header)?;

        trace!("Message received: {payload}");

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut rsp = httparse::Response::new(&mut headers);

        if rsp.parse(payload.as_bytes()).is_ok() {
            return Ok(JetMessage::JetAcceptRsp(JetAcceptRsp::from_response(&rsp)?));
        }

        Err(format!("Invalid message received: Payload={payload}").into())
    }

    pub fn read_connect_response<R: Read>(stream: &mut R) -> Result<Self, Error> {
        let jet_header = JetMessage::read_header(stream)?;
        let payload = JetMessage::read_payload(stream, &jet_header)?;

        trace!("Message received: {payload}");

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut rsp = httparse::Response::new(&mut headers);

        if rsp.parse(payload.as_bytes()).is_ok() {
            return Ok(JetMessage::JetConnectRsp(JetConnectRsp::from_response(&rsp)?));
        }

        Err(format!("Invalid message received: Payload={payload}").into())
    }

    pub fn write_to(&self, mut stream: impl io::Write) -> Result<(), Error> {
        let flags: u8 = 0;
        let mask: u8 = get_mask_value();

        let mut payload: Vec<u8> = Vec::new();
        match self {
            JetMessage::JetTestReq(req) => req.write_payload(&mut payload)?,
            JetMessage::JetTestRsp(rsp) => rsp.write_payload(&mut payload)?,
            JetMessage::JetAcceptReq(req) => req.write_payload(&mut payload)?,
            JetMessage::JetAcceptRsp(rsp) => rsp.write_payload(&mut payload)?,
            JetMessage::JetConnectReq(req) => req.write_payload(&mut payload)?,
            JetMessage::JetConnectRsp(rsp) => rsp.write_payload(&mut payload)?,
        };

        apply_mask(mask, &mut payload);

        let size = u16::try_from(payload.len()).unwrap() + u16::try_from(JET_MSG_HEADER_SIZE).unwrap();
        stream.write_u32::<LittleEndian>(JET_MSG_SIGNATURE)?;
        stream.write_u16::<BigEndian>(size)?;
        stream.write_u8(flags)?;
        stream.write_u8(mask)?;
        stream.write_all(&payload)?;

        Ok(())
    }

    fn read_header<R: Read>(stream: &mut R) -> Result<JetHeader, Error> {
        let signature = stream.read_u32::<LittleEndian>()?;
        if signature != JET_MSG_SIGNATURE {
            return Err(Error::Str(format!("Invalid JetMessage - Signature = {signature}.")));
        }
        let msg_size = stream.read_u16::<BigEndian>()?;
        let _ = stream.read_u8()?;
        let mask = stream.read_u8()?;

        Ok(JetHeader { msg_size, mask })
    }

    fn read_payload<R: Read>(stream: &mut R, header: &JetHeader) -> Result<String, Error> {
        if header.msg_size < 8 {
            return Err(Error::Size);
        }
        let mut payload: Vec<u8> = vec![0; (header.msg_size - 8) as usize];
        stream.read_exact(&mut payload)?;

        apply_mask(header.mask, &mut payload);

        let payload = String::from_utf8(payload).map_err(|e| {
            Error::Str(format!(
                "Invalid JetMessage - Message can't be converted in String: {e}"
            ))
        })?;

        Ok(payload)
    }
}

fn get_uuid_in_path(path: &str, index: usize) -> Option<Uuid> {
    if let Some(raw_uuid) = path.split('/').nth(index + 1) {
        Uuid::parse_str(raw_uuid).ok()
    } else {
        None
    }
}

fn apply_mask(mask: u8, payload: &mut [u8]) {
    for byte in payload {
        *byte ^= mask;
    }
}

#[derive(Debug)]
pub enum Error {
    Internal,
    Version,
    Capabilities,
    Unresolved,
    Unreachable,
    Unavailable,
    Transport,
    Memory,
    State,
    Protocol,
    Header,
    Payload,
    Size,
    Type,
    Value,
    Offset,
    Flags,
    Argument,
    Timeout,
    Cancelled,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    NotImplemented,
    Io(io::Error),
    Str(String),
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::Io(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        io::Error::other(error)
    }
}

impl From<&'static str> for Error {
    fn from(error: &'static str) -> Error {
        Error::Str(error.to_owned())
    }
}

impl From<String> for Error {
    fn from(error: String) -> Error {
        Error::Str(error)
    }
}

impl Error {
    pub fn from_http_status_code(status_code: u16) -> Self {
        match status_code {
            400 => Error::BadRequest,
            401 => Error::Unauthorized,
            403 => Error::Forbidden,
            404 => Error::NotFound,
            _ => Error::BadRequest,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Internal => write!(f, "Internal error"),
            Error::Version => write!(f, "Version error"),
            Error::Capabilities => write!(f, "Capabilities error"),
            Error::Unresolved => write!(f, "Unresolved error"),
            Error::Unreachable => write!(f, "Unreachable error"),
            Error::Unavailable => write!(f, "Unavailable error"),
            Error::Transport => write!(f, "Transport error"),
            Error::Memory => write!(f, "Memory error"),
            Error::State => write!(f, "State error"),
            Error::Protocol => write!(f, "Protocol error"),
            Error::Header => write!(f, "Header error"),
            Error::Payload => write!(f, "Payload error"),
            Error::Size => write!(f, "Size error"),
            Error::Type => write!(f, "Type error"),
            Error::Value => write!(f, "Value error"),
            Error::Offset => write!(f, "Offset error"),
            Error::Flags => write!(f, "Flags error"),
            Error::Argument => write!(f, "Argument error"),
            Error::Timeout => write!(f, "Timeout error"),
            Error::Cancelled => write!(f, "Cancelled error"),
            Error::BadRequest => write!(f, "BadRequest error"),
            Error::Unauthorized => write!(f, "Unauthorized error"),
            Error::Forbidden => write!(f, "Forbidden error"),
            Error::NotFound => write!(f, "NotFound error"),
            Error::NotImplemented => write!(f, "NotImplemented error"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Str(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    //GET /jet/accept/300f1c82-d33b-11e9-bb65-2a2ae2dbcce5/4c8f409a-c1a2-4cae-bda2-84c590fed618 HTTP/1.1
    //Host: jet101.wayk.net
    //Connection: Keep-Alive
    //Jet-Version: 2
    static TEST_JET_ACCEPT_REQ_V2: &[u8] = &hex!(
        "
    4a 45 54 00 00 A8 00 00
    47 45 54 20 2f 6a 65 74 2f 61 63 63 65 70 74 2f
    33 30 30 66 31 63 38 32 2d 64 33 33 62 2d 31 31
    65 39 2d 62 62 36 35 2d 32 61 32 61 65 32 64 62
    63 63 65 35 2f 34 63 38 66 34 30 39 61 2d 63 31
    61 32 2d 34 63 61 65 2d 62 64 61 32 2d 38 34 63
    35 39 30 66 65 64 36 31 38 20 48 54 54 50 2f 31
    2e 31 0a 48 6f 73 74 3a 20 6a 65 74 31 30 31 2e
    77 61 79 6b 2e 6e 65 74 0a 43 6f 6e 6e 65 63 74
    69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 0a
    4a 65 74 2d 56 65 72 73 69 6f 6e 3a 20 32 0a 0a
    "
    );

    #[test]
    fn test_accept_v2() {
        use std::io::Cursor;
        use std::str::FromStr;

        let mut cursor = Cursor::new(TEST_JET_ACCEPT_REQ_V2);
        let jet_message = JetMessage::read_request(&mut cursor).unwrap();
        assert!(
            jet_message
                == JetMessage::JetAcceptReq(JetAcceptReq {
                    association: Uuid::from_str("300f1c82-d33b-11e9-bb65-2a2ae2dbcce5").unwrap(),
                    candidate: Uuid::from_str("4c8f409a-c1a2-4cae-bda2-84c590fed618").unwrap(),
                    version: 2,
                    host: "jet101.wayk.net".to_owned()
                })
        );
    }
}
