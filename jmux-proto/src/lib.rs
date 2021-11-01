//! [Specification document](https://github.com/awakecoding/qmux/blob/protocol-update/SPEC.md)

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use core::fmt;

/// Distant identifier for a channel
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct DistantChannelId(u32);

impl From<u32> for DistantChannelId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<DistantChannelId> for u32 {
    fn from(id: DistantChannelId) -> Self {
        id.0
    }
}

impl fmt::Display for DistantChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "d#{}", self.0)
    }
}

/// Local identifier for a channel
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct LocalChannelId(u32);

impl From<u32> for LocalChannelId {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<LocalChannelId> for u32 {
    fn from(id: LocalChannelId) -> Self {
        id.0
    }
}

impl fmt::Display for LocalChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "l#{}", self.0)
    }
}

#[derive(Debug)]
pub enum Error {
    PacketOversized {
        packet_size: usize,
        max: usize,
    },
    NotEnoughBytes {
        name: &'static str,
        received: usize,
        expected: usize,
    },
    InvalidPacket {
        name: &'static str,
        field: &'static str,
        reason: &'static str,
    },
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PacketOversized { packet_size, max } => {
                write!(f, "Packet oversized: max is {}, got {}", max, packet_size)
            }
            Error::NotEnoughBytes {
                name,
                received,
                expected,
            } => write!(
                f,
                "Not enough bytes provided to decode {}: received {} bytes, expected {} bytes",
                name, received, expected
            ),
            Error::InvalidPacket { name, field, reason } => {
                write!(f, "Invalid `{}` in {}: {}", field, name, reason)
            }
        }
    }
}

macro_rules! ensure_size {
    ($buf:ident [$expected:expr] for $name:expr) => {{
        let received = $buf.len();
        let expected = $expected;
        if !(received >= expected) {
            return Err(Error::NotEnoughBytes {
                name: $name,
                received,
                expected,
            });
        }
    }};
    (plain $packet_struct:ident in $buf:ident) => {{
        ensure_size!($buf[$packet_struct::SIZE] for $packet_struct::NAME)
    }};
    (fixed $packet_struct:ident in $buf:ident) => {{
        ensure_size!($buf[$packet_struct::FIXED_PART_SIZE] for $packet_struct::NAME)
    }};
}

#[derive(Debug, PartialEq)]
pub enum Message {
    Open(ChannelOpen),
    OpenSuccess(ChannelOpenSuccess),
    OpenFailure(ChannelOpenFailure),
    WindowAdjust(ChannelWindowAdjust),
    Data(ChannelData),
    Eof(ChannelEof),
    Close(ChannelClose),
}

impl Message {
    pub fn open(id: LocalChannelId, maximum_packet_size: u16, destination_url: impl Into<String>) -> Self {
        Self::Open(ChannelOpen::new(id, maximum_packet_size, destination_url))
    }

    pub fn open_success(
        distant_id: DistantChannelId,
        local_id: LocalChannelId,
        initial_window_size: u32,
        maximum_packet_size: u16,
    ) -> Self {
        Self::OpenSuccess(ChannelOpenSuccess::new(
            distant_id,
            local_id,
            initial_window_size,
            maximum_packet_size,
        ))
    }

    pub fn open_failure(distant_id: DistantChannelId, reason_code: ReasonCode, description: impl Into<String>) -> Self {
        Self::OpenFailure(ChannelOpenFailure::new(distant_id, reason_code, description))
    }

    pub fn window_adjust(distant_id: DistantChannelId, window_adjustment: u32) -> Self {
        Self::WindowAdjust(ChannelWindowAdjust::new(distant_id, window_adjustment))
    }

    pub fn data(id: DistantChannelId, data: Vec<u8>) -> Self {
        Self::Data(ChannelData::new(id, data))
    }

    pub fn eof(distant_id: DistantChannelId) -> Self {
        Self::Eof(ChannelEof::new(distant_id))
    }

    pub fn close(distant_id: DistantChannelId) -> Self {
        Self::Close(ChannelClose::new(distant_id))
    }

    pub fn size(&self) -> usize {
        match self {
            Message::Open(msg) => Header::SIZE + msg.size(),
            Message::OpenSuccess(_) => Header::SIZE + ChannelOpenSuccess::SIZE,
            Message::OpenFailure(msg) => Header::SIZE + msg.size(),
            Message::WindowAdjust(_) => Header::SIZE + ChannelWindowAdjust::SIZE,
            Message::Data(msg) => Header::SIZE + msg.size(),
            Message::Eof(_) => Header::SIZE + ChannelEof::SIZE,
            Message::Close(_) => Header::SIZE + ChannelClose::SIZE,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), Error> {
        macro_rules! reserve_and_encode_header {
            ($buf:ident, $len:expr, $ty:expr) => {
                let len = $len;
                if $buf.len() < len {
                    $buf.reserve(len - $buf.len());
                }
                let header = Header {
                    ty: $ty,
                    size: u16::try_from(len).map_err(|_| Error::PacketOversized {
                        packet_size: len,
                        max: usize::from(u16::MAX),
                    })?,
                    flags: 0,
                };
                header.encode(buf);
            };
        }

        match self {
            Message::Open(msg) => {
                reserve_and_encode_header!(buf, Header::SIZE + msg.size(), MessageType::Open);
                msg.encode(buf)
            }
            Message::OpenSuccess(msg) => {
                reserve_and_encode_header!(buf, Header::SIZE + ChannelOpenSuccess::SIZE, MessageType::OpenSuccess);
                msg.encode(buf)
            }
            Message::OpenFailure(msg) => {
                reserve_and_encode_header!(buf, Header::SIZE + msg.size(), MessageType::OpenFailure);
                msg.encode(buf)
            }
            Message::WindowAdjust(msg) => {
                reserve_and_encode_header!(buf, Header::SIZE + ChannelWindowAdjust::SIZE, MessageType::WindowAdjust);
                msg.encode(buf)
            }
            Message::Data(msg) => {
                reserve_and_encode_header!(buf, Header::SIZE + msg.size(), MessageType::Data);
                msg.encode(buf)
            }
            Message::Eof(msg) => {
                reserve_and_encode_header!(buf, Header::SIZE + ChannelEof::SIZE, MessageType::Eof);
                msg.encode(buf)
            }
            Message::Close(msg) => {
                reserve_and_encode_header!(buf, Header::SIZE + ChannelClose::SIZE, MessageType::Close);
                msg.encode(buf)
            }
        }

        Ok(())
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(plain Header in buf);

        let header = Header::decode(buf.split_to(Header::SIZE))?;
        let total_size = header.size as usize;

        let body_size = total_size.checked_sub(Header::SIZE).ok_or(Error::InvalidPacket {
            name: Header::NAME,
            field: "msgSize",
            reason: "too small",
        })?;

        ensure_size!(buf[body_size] for "BODY");
        let body_bytes = buf.split_to(body_size);

        let message = match header.ty {
            MessageType::Open => Self::Open(ChannelOpen::decode(body_bytes)?),
            MessageType::Data => Self::Data(ChannelData::decode(body_bytes)?),
            MessageType::OpenSuccess => Self::OpenSuccess(ChannelOpenSuccess::decode(body_bytes)?),
            MessageType::OpenFailure => Self::OpenFailure(ChannelOpenFailure::decode(body_bytes)?),
            MessageType::WindowAdjust => Self::WindowAdjust(ChannelWindowAdjust::decode(body_bytes)?),
            MessageType::Eof => Self::Eof(ChannelEof::decode(body_bytes)?),
            MessageType::Close => Self::Close(ChannelClose::decode(body_bytes)?),
        };

        Ok(message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReasonCode(pub u32);

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self.0 {
            0x01 => "GENERAL_FAILURE",
            0x02 => "CONNECTION_NOT_ALLOWED_BY_RULESET",
            0x03 => "NETWORK_UNREACHABLE",
            0x04 => "HOST_UNREACHABLE",
            0x05 => "CONNECTION_REFUSED",
            0x06 => "TTL_EXPIRED",
            0x08 => "ADDRESS_TYPE_NOT_SUPPORTED",
            0x00 | 0x07 | 0x09.. => "OTHER",
        };
        write!(f, "{} (0x{:08X})", desc, self.0)
    }
}

impl ReasonCode {
    /// General server failure
    pub const GENERAL_FAILURE: Self = ReasonCode(0x01);

    /// Connection not allowed by the rule set
    pub const CONNECTION_NOT_ALLOWED_BY_RULESET: Self = ReasonCode(0x02);

    /// Destination network is unreachable
    pub const NETWORK_UNREACHABLE: Self = ReasonCode(0x03);

    /// Destination host is unreachable
    pub const HOST_UNREACHABLE: Self = ReasonCode(0x04);

    /// Connection refused by the remote host
    pub const CONNECTION_REFUSED: Self = ReasonCode(0x05);

    /// TTL expired (the remote host is too far away)
    pub const TTL_EXPIRED: Self = ReasonCode(0x06);

    /// Address type is not supported
    pub const ADDRESS_TYPE_NOT_SUPPORTED: Self = ReasonCode(0x08);
}

impl From<std::io::ErrorKind> for ReasonCode {
    fn from(kind: std::io::ErrorKind) -> ReasonCode {
        match kind {
            std::io::ErrorKind::ConnectionRefused => ReasonCode::CONNECTION_REFUSED,
            std::io::ErrorKind::TimedOut => ReasonCode::TTL_EXPIRED,
            #[cfg(feature = "nightly")] // https://github.com/rust-lang/rust/issues/86442
            std::io::ErrorKind::HostUnreachable => ReasonCode::HOST_UNREACHABLE,
            #[cfg(feature = "nightly")] // https://github.com/rust-lang/rust/issues/86442
            std::io::ErrorKind::NetworkUnreachable => ReasonCode::NETWORK_UNREACHABLE,
            _ => ReasonCode::GENERAL_FAILURE,
        }
    }
}

impl From<std::io::Error> for ReasonCode {
    fn from(e: std::io::Error) -> ReasonCode {
        ReasonCode::from(e.kind())
    }
}

impl From<&std::io::Error> for ReasonCode {
    fn from(e: &std::io::Error) -> ReasonCode {
        ReasonCode::from(e.kind())
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Open = 100,
    OpenSuccess = 101,
    OpenFailure = 102,
    WindowAdjust = 103,
    Data = 104,
    Eof = 105,
    Close = 106,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(v: u8) -> Result<MessageType, Error> {
        match v {
            100 => Ok(MessageType::Open),
            101 => Ok(MessageType::OpenSuccess),
            102 => Ok(MessageType::OpenFailure),
            103 => Ok(MessageType::WindowAdjust),
            104 => Ok(MessageType::Data),
            105 => Ok(MessageType::Eof),
            106 => Ok(MessageType::Close),
            _ => Err(Error::InvalidPacket {
                name: Header::NAME,
                field: "msgType",
                reason: "unknown value",
            }),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Header {
    pub ty: MessageType,
    pub size: u16,
    pub flags: u8,
}

impl Header {
    pub const NAME: &'static str = "HEADER";
    pub const SIZE: usize = 1 /* msgType */ + 2 /* msgSize */ + 1 /* msgFlags */;

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ty as u8);
        buf.put_u16(self.size);
        buf.put_u8(0);
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(plain Self in buf);
        Ok(Self {
            ty: MessageType::try_from(buf.get_u8())?,
            size: buf.get_u16(),
            flags: buf.get_u8(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct ChannelOpen {
    pub sender_channel_id: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u16,
    pub destination_url: String,
}

impl ChannelOpen {
    pub const NAME: &'static str = "CHANNEL OPEN";
    pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 32_768;
    pub const FIXED_PART_SIZE: usize = 4 /* senderChannelId */ + 4 /* initialWindowSize */ + 2 /* maximumPacketSize */;

    pub fn new(id: LocalChannelId, maximum_packet_size: u16, destination_url: impl Into<String>) -> Self {
        Self {
            sender_channel_id: u32::from(id),
            initial_window_size: Self::DEFAULT_INITIAL_WINDOW_SIZE,
            maximum_packet_size,
            destination_url: destination_url.into(),
        }
    }

    pub fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.destination_url.as_bytes().len()
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.sender_channel_id);
        buf.put_u32(self.initial_window_size);
        buf.put_u16(self.maximum_packet_size);
        buf.put(self.destination_url.as_bytes());
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(fixed Self in buf);

        let sender_channel_id = buf.get_u32();
        let initial_window_size = buf.get_u32();
        let maximum_packet_size = buf.get_u16();

        let destination_url = std::str::from_utf8(&buf)
            .map_err(|_| Error::InvalidPacket {
                name: Self::NAME,
                field: "destinationUrl",
                reason: "not valid UTF-8",
            })?
            .to_owned();

        Ok(Self {
            sender_channel_id,
            initial_window_size,
            maximum_packet_size,
            destination_url,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct ChannelOpenSuccess {
    pub recipient_channel_id: u32,
    pub sender_channel_id: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u16,
}

impl ChannelOpenSuccess {
    pub const NAME: &'static str = "CHANNEL OPEN SUCCESS";
    pub const SIZE: usize = 4 /*recipientChannelId*/ + 4 /*senderChannelId*/ + 4 /*initialWindowSize*/ + 2 /*maximumPacketSize*/;

    pub fn new(
        distant_id: DistantChannelId,
        local_id: LocalChannelId,
        initial_window_size: u32,
        maximum_packet_size: u16,
    ) -> Self {
        Self {
            recipient_channel_id: u32::from(distant_id),
            sender_channel_id: u32::from(local_id),
            initial_window_size,
            maximum_packet_size,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.recipient_channel_id);
        buf.put_u32(self.sender_channel_id);
        buf.put_u32(self.initial_window_size);
        buf.put_u16(self.maximum_packet_size);
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(plain Self in buf);

        Ok(Self {
            recipient_channel_id: buf.get_u32(),
            sender_channel_id: buf.get_u32(),
            initial_window_size: buf.get_u32(),
            maximum_packet_size: buf.get_u16(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct ChannelOpenFailure {
    pub recipient_channel_id: u32,
    pub reason_code: ReasonCode,
    pub description: String,
}

impl ChannelOpenFailure {
    pub const NAME: &'static str = "CHANNEL OPEN FAILURE";
    pub const FIXED_PART_SIZE: usize = 4 /*recipientChannelId*/ + 4 /*reasonCode*/;

    pub fn new(distant_id: DistantChannelId, reason_code: ReasonCode, description: impl Into<String>) -> Self {
        Self {
            recipient_channel_id: u32::from(distant_id),
            reason_code,
            description: description.into(),
        }
    }

    pub fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.description.as_bytes().len()
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.recipient_channel_id);
        buf.put_u32(self.reason_code.0);
        buf.put(self.description.as_bytes());
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(fixed Self in buf);

        let recipient_channel_id = buf.get_u32();
        let reason_code = ReasonCode(buf.get_u32());
        let description = std::str::from_utf8(&buf)
            .map_err(|_| Error::InvalidPacket {
                name: Self::NAME,
                field: "description",
                reason: "not valid UTF-8",
            })?
            .to_owned();

        Ok(Self {
            recipient_channel_id,
            reason_code,
            description,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct ChannelWindowAdjust {
    pub recipient_channel_id: u32,
    pub window_adjustment: u32,
}

impl ChannelWindowAdjust {
    pub const NAME: &'static str = "CHANNEL WINDOW ADJUST";
    pub const SIZE: usize = 4 /*recipientChannelId*/ + 4 /*windowAdjustement*/;

    pub fn new(distant_id: DistantChannelId, window_adjustment: u32) -> Self {
        ChannelWindowAdjust {
            recipient_channel_id: u32::from(distant_id),
            window_adjustment,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.recipient_channel_id);
        buf.put_u32(self.window_adjustment);
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(plain Self in buf);
        Ok(Self {
            recipient_channel_id: buf.get_u32(),
            window_adjustment: buf.get_u32(),
        })
    }
}

#[derive(PartialEq)]
pub struct ChannelData {
    pub recipient_channel_id: u32,
    pub transfer_data: Vec<u8>,
}

// We don't want to print `transfer_data` content (usually too big)
impl fmt::Debug for ChannelData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelData")
            .field("recipient_channel_id", &self.recipient_channel_id)
            .field("transfer_data.len()", &self.transfer_data.len())
            .finish_non_exhaustive()
    }
}

impl ChannelData {
    pub const NAME: &'static str = "CHANNEL DATA";
    pub const FIXED_PART_SIZE: usize = 4 /*recipientChannelId*/;

    pub fn new(id: DistantChannelId, data: Vec<u8>) -> Self {
        ChannelData {
            recipient_channel_id: u32::from(id),
            transfer_data: data,
        }
    }

    pub fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.transfer_data.len()
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.recipient_channel_id);
        buf.put(self.transfer_data.as_slice());
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(fixed Self in buf);
        Ok(Self {
            recipient_channel_id: buf.get_u32(),
            transfer_data: buf.to_vec(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct ChannelEof {
    pub recipient_channel_id: u32,
}

impl ChannelEof {
    pub const NAME: &'static str = "CHANNEL EOF";
    pub const SIZE: usize = 4 /*recipientChannelId*/;

    pub fn new(distant_id: DistantChannelId) -> Self {
        Self {
            recipient_channel_id: u32::from(distant_id),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.recipient_channel_id);
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(plain Self in buf);
        Ok(Self {
            recipient_channel_id: buf.get_u32(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct ChannelClose {
    pub recipient_channel_id: u32,
}

impl ChannelClose {
    pub const NAME: &'static str = "CHANNEL CLOSE";
    pub const SIZE: usize = 4 /*recipientChannelId*/;

    pub fn new(distant_id: DistantChannelId) -> Self {
        Self {
            recipient_channel_id: u32::from(distant_id),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.recipient_channel_id);
    }

    pub fn decode(mut buf: Bytes) -> Result<Self, Error> {
        ensure_size!(plain Self in buf);
        Ok(Self {
            recipient_channel_id: buf.get_u32(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_try_from() {
        let msg_type = MessageType::try_from(100).unwrap();
        assert_eq!(MessageType::Open, msg_type);

        let msg_type = MessageType::try_from(103).unwrap();
        assert_eq!(MessageType::WindowAdjust, msg_type);

        let msg_type = MessageType::try_from(106).unwrap();
        assert_eq!(MessageType::Close, msg_type);
    }

    #[test]
    fn message_type_try_err_on_invalid_bytes() {
        let msg_type_res = MessageType::try_from(99);
        assert!(msg_type_res.is_err());

        let msg_type_res = MessageType::try_from(107);
        assert!(msg_type_res.is_err());
    }

    #[test]
    fn header_decode_buffer_too_short_err() {
        let err = Header::decode(Bytes::from_static(&[])).err().unwrap();
        assert_eq!("Not enough bytes provided to decode HEADER", err.to_string());
    }

    #[test]
    fn header_decode() {
        let msg = Header::decode(Bytes::from_static(&[102, 7, 16, 0])).unwrap();
        assert_eq!(
            Header {
                ty: MessageType::OpenFailure,
                size: 1808,
                flags: 0,
            },
            msg
        );
    }

    #[test]
    fn header_encode() {
        let header = Header {
            ty: MessageType::OpenSuccess,
            size: 512,
            flags: 0,
        };
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        assert_eq!(vec![101, 2, 0, 0], buf);
    }

    fn check_encode_decode(sample_msg: Message, raw_msg: &[u8]) {
        let mut encoded = BytesMut::new();
        sample_msg.encode(&mut encoded).unwrap();
        assert_eq!(raw_msg.to_vec(), encoded.to_vec());

        let decoded = Message::decode(Bytes::copy_from_slice(raw_msg)).unwrap();
        assert_eq!(sample_msg, decoded);
    }

    #[test]
    fn channel_open() {
        let raw_msg = &[
            100, // msg type
            0, 34, // msg size
            0,  // msg flags
            0, 0, 0, 1, // sender channel id
            0, 0, 4, 0, // initial window size
            4, 0, // maximum packet size
            116, 99, 112, 58, 47, 47, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 58, 52, 52,
            51, // destination url: tcp://google.com:443
        ];

        let mut msg_sample = ChannelOpen::new(LocalChannelId::from(1), 4096, "tcp://google.com:443");
        msg_sample.initial_window_size = 1024;
        msg_sample.maximum_packet_size = 1024;

        check_encode_decode(Message::Open(msg_sample), raw_msg);
    }

    #[test]
    pub fn channel_open_success() {
        let raw_msg = &[
            101, // msg type
            0, 18, // msg size
            0,  // msg flags
            0, 0, 0, 1, // recipient channel id
            0, 0, 0, 2, // sender channel id
            0, 0, 4, 0, // initial window size
            127, 255, // maximum packet size
        ];

        let msg = ChannelOpenSuccess {
            initial_window_size: 1024,
            sender_channel_id: 2,
            maximum_packet_size: 32767,
            recipient_channel_id: 1,
        };

        check_encode_decode(Message::OpenSuccess(msg), raw_msg);
    }

    #[test]
    pub fn channel_open_failure() {
        let raw_msg = &[
            102, // msg type
            0, 17, // msg size
            0,  // msg flags
            0, 0, 0, 1, // recipient channel id
            0, 0, 0, 2, // reason code
            101, 114, 114, 111, 114, // failure description
        ];

        let msg_example = ChannelOpenFailure {
            recipient_channel_id: 1,
            reason_code: ReasonCode(2),
            description: "error".to_owned(),
        };

        check_encode_decode(Message::OpenFailure(msg_example), raw_msg);
    }

    #[test]
    pub fn channel_window_adjust() {
        let raw_msg = &[
            103, // msg type
            0, 12, // msg size
            0,  // msg flags
            0, 0, 0, 1, // recipient channel id
            0, 0, 2, 0, // window adjustment
        ];

        let msg_example = ChannelWindowAdjust {
            recipient_channel_id: 1,
            window_adjustment: 512,
        };

        check_encode_decode(Message::WindowAdjust(msg_example), raw_msg);
    }

    #[test]
    pub fn error_on_oversized_packet() {
        let mut buf = BytesMut::new();
        let err = Message::data(DistantChannelId::from(1), vec![0; u16::MAX as usize])
            .encode(&mut buf)
            .err()
            .unwrap();
        assert_eq!("Packet oversized: max is 65535, got 65543", err.to_string());
    }

    #[test]
    pub fn channel_data() {
        let raw_msg = &[
            104, // msg type
            0, 12, // msg size
            0,  // msg flags
            0, 0, 0, 1, // recipient channel id
            11, 12, 13, 14, // transfer data
        ];

        let msg_example = ChannelData {
            recipient_channel_id: 1,
            transfer_data: vec![11, 12, 13, 14],
        };

        check_encode_decode(Message::Data(msg_example), raw_msg);
    }

    #[test]
    pub fn channel_eof() {
        let raw_msg = &[
            105, // msg type
            0, 8, // msg size
            0, // msg flags
            0, 0, 0, 1, // recipient channel id
        ];

        let msg_example = ChannelEof {
            recipient_channel_id: 1,
        };

        check_encode_decode(Message::Eof(msg_example), raw_msg);
    }

    #[test]
    pub fn channel_close() {
        let raw_msg = &[
            106, // msg type
            0, 8, // msg size
            0, // msg flags
            0, 0, 0, 1, // recipient channel id
        ];

        let msg_example = ChannelClose {
            recipient_channel_id: 1,
        };

        check_encode_decode(Message::Close(msg_example), raw_msg);
    }
}
