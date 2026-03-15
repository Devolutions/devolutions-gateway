use bytes::{Buf, BufMut, Bytes, BytesMut};
use ipnetwork::Ipv4Network;

use crate::error::{Error, Result};

/// Relay message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayMsgType {
    /// Request to connect to a target (payload: target address string)
    Connect = 0x01,
    /// Connection established successfully (no payload)
    Connected = 0x02,
    /// Data transfer (payload: actual data bytes)
    Data = 0x03,
    /// Close the stream (no payload)
    Close = 0x04,
    /// Error occurred (payload: error message string)
    Error = 0x05,
    /// Full route advertisement for a peer (payload: encoded route set)
    RouteAdvertise = 0x06,
}

impl RelayMsgType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Connected),
            0x03 => Ok(Self::Data),
            0x04 => Ok(Self::Close),
            0x05 => Ok(Self::Error),
            0x06 => Ok(Self::RouteAdvertise),
            _ => Err(Error::InvalidMessageType(v)),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdvertisement {
    pub epoch: u64,
    pub subnets: Vec<Ipv4Network>,
}

impl RouteAdvertisement {
    const HEADER_SIZE: usize = 10; // 8 (epoch) + 2 (subnet_count)
    const SUBNET_SIZE: usize = 5; // 4 (network) + 1 (prefix)

    pub fn new(epoch: u64, mut subnets: Vec<Ipv4Network>) -> Self {
        subnets.sort_unstable();
        subnets.dedup();

        Self { epoch, subnets }
    }

    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let payload_size = Self::HEADER_SIZE + (self.subnets.len() * Self::SUBNET_SIZE);
        if payload_size > RelayMessage::MAX_PAYLOAD_SIZE {
            return Err(Error::PayloadTooLarge {
                size: payload_size,
                max: RelayMessage::MAX_PAYLOAD_SIZE,
            });
        }

        buf.reserve(payload_size);
        buf.put_u64(self.epoch);
        buf.put_u16(self.subnets.len().try_into().map_err(|_| Error::PayloadTooLarge {
            size: payload_size,
            max: RelayMessage::MAX_PAYLOAD_SIZE,
        })?);

        for subnet in &self.subnets {
            buf.put_u32(u32::from(subnet.network()));
            buf.put_u8(subnet.prefix());
        }

        Ok(())
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self> {
        if buf.remaining() < Self::HEADER_SIZE {
            return Err(Error::NotEnoughBytes {
                received: buf.remaining(),
                expected: Self::HEADER_SIZE,
            });
        }

        let epoch = buf.get_u64();
        let subnet_count = buf.get_u16() as usize;
        let expected_remaining = subnet_count * Self::SUBNET_SIZE;

        if buf.remaining() < expected_remaining {
            return Err(Error::NotEnoughBytes {
                received: buf.remaining(),
                expected: expected_remaining,
            });
        }

        let mut subnets = Vec::with_capacity(subnet_count);
        for _ in 0..subnet_count {
            let network = std::net::Ipv4Addr::from(buf.get_u32());
            let prefix = buf.get_u8();
            let subnet = Ipv4Network::new(network, prefix)
                .map_err(|error| Error::InvalidPayload(format!("invalid subnet {network}/{prefix}: {error}")))?;
            subnets.push(subnet);
        }

        Ok(Self::new(epoch, subnets))
    }
}

/// Relay protocol message
///
/// Wire format (7-byte header + variable payload):
/// ```text
/// ┌──────────────┬──────────────┬──────────────┬──────────────────┐
/// │  stream_id   │   msg_type   │    length    │     payload      │
/// │   (4 bytes)  │   (1 byte)   │  (2 bytes)   │  (length bytes)  │
/// └──────────────┴──────────────┴──────────────┴──────────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMessage {
    /// Stream identifier (unique per peer connection)
    pub stream_id: u32,
    /// Message type
    pub msg_type: RelayMsgType,
    /// Message payload
    pub payload: Bytes,
}

impl RelayMessage {
    /// Fixed header size in bytes
    pub const HEADER_SIZE: usize = 7; // 4 (stream_id) + 1 (msg_type) + 2 (length)

    /// Maximum payload size (64KB - header)
    pub const MAX_PAYLOAD_SIZE: usize = 65535 - Self::HEADER_SIZE;

    /// Create a new relay message
    pub fn new(stream_id: u32, msg_type: RelayMsgType, payload: Bytes) -> Result<Self> {
        if payload.len() > Self::MAX_PAYLOAD_SIZE {
            return Err(Error::PayloadTooLarge {
                size: payload.len(),
                max: Self::MAX_PAYLOAD_SIZE,
            });
        }

        Ok(Self {
            stream_id,
            msg_type,
            payload,
        })
    }

    /// Create a CONNECT message
    pub fn connect(stream_id: u32, target: &str) -> Result<Self> {
        Self::new(stream_id, RelayMsgType::Connect, Bytes::from(target.to_owned()))
    }

    /// Create a CONNECTED message
    pub fn connected(stream_id: u32) -> Result<Self> {
        Self::new(stream_id, RelayMsgType::Connected, Bytes::new())
    }

    /// Create a DATA message
    pub fn data(stream_id: u32, data: impl Into<Bytes>) -> Result<Self> {
        Self::new(stream_id, RelayMsgType::Data, data.into())
    }

    /// Create a CLOSE message
    pub fn close(stream_id: u32) -> Result<Self> {
        Self::new(stream_id, RelayMsgType::Close, Bytes::new())
    }

    /// Create an ERROR message
    pub fn error(stream_id: u32, error_msg: &str) -> Result<Self> {
        Self::new(stream_id, RelayMsgType::Error, Bytes::from(error_msg.to_owned()))
    }

    /// Create a full route advertisement control message.
    pub fn route_advertise(advertisement: &RouteAdvertisement) -> Result<Self> {
        let mut payload = BytesMut::new();
        advertisement.encode(&mut payload)?;
        Self::new(0, RelayMsgType::RouteAdvertise, payload.freeze())
    }

    /// Calculate total message size (header + payload)
    pub fn size(&self) -> usize {
        Self::HEADER_SIZE + self.payload.len()
    }

    /// Encode the message into a buffer
    ///
    /// # Format
    /// ```text
    /// [stream_id: u32 BE][msg_type: u8][length: u16 BE][payload: bytes]
    /// ```
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let total_size = self.size();

        // Reserve space if needed
        if buf.capacity() < total_size {
            buf.reserve(total_size - buf.len());
        }

        // Encode header
        buf.put_u32(self.stream_id); // Big-endian
        buf.put_u8(self.msg_type.as_u8());
        buf.put_u16(self.payload.len().try_into().map_err(|_| Error::PayloadTooLarge {
            size: self.payload.len(),
            max: Self::MAX_PAYLOAD_SIZE,
        })?); // Big-endian

        // Encode payload
        buf.put_slice(&self.payload);

        Ok(())
    }

    /// Decode a message from a buffer
    ///
    /// Returns the decoded message and the number of bytes consumed.
    pub fn decode(mut buf: impl Buf) -> Result<Self> {
        // Check minimum size
        if buf.remaining() < Self::HEADER_SIZE {
            return Err(Error::NotEnoughBytes {
                received: buf.remaining(),
                expected: Self::HEADER_SIZE,
            });
        }

        // Decode header
        let stream_id = buf.get_u32(); // Big-endian
        let msg_type = RelayMsgType::from_u8(buf.get_u8())?;
        let payload_len = buf.get_u16() as usize; // Big-endian

        // Check if we have enough bytes for payload
        if buf.remaining() < payload_len {
            return Err(Error::NotEnoughBytes {
                received: buf.remaining(),
                expected: payload_len,
            });
        }

        // Decode payload
        let payload = buf.copy_to_bytes(payload_len);

        Ok(Self {
            stream_id,
            msg_type,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_round_trip() {
        let types = [
            RelayMsgType::Connect,
            RelayMsgType::Connected,
            RelayMsgType::Data,
            RelayMsgType::Close,
            RelayMsgType::Error,
            RelayMsgType::RouteAdvertise,
        ];

        for ty in types {
            let byte = ty.as_u8();
            let decoded = RelayMsgType::from_u8(byte).expect("message type should decode");
            assert_eq!(ty, decoded);
        }
    }

    #[test]
    fn test_message_encode_decode_connect() {
        let msg = RelayMessage::connect(123, "tcp://192.168.1.100:3389").expect("connect message should build");

        let mut buf = BytesMut::new();
        msg.encode(&mut buf).expect("connect message should encode");

        let decoded = RelayMessage::decode(&buf[..]).expect("connect message should decode");

        assert_eq!(msg.stream_id, decoded.stream_id);
        assert_eq!(msg.msg_type, decoded.msg_type);
        assert_eq!(msg.payload, decoded.payload);
    }

    #[test]
    fn test_message_encode_decode_data() {
        let data = b"Hello, WireGuard tunnel!";
        let msg = RelayMessage::data(456, Bytes::from_static(data)).expect("data message should build");

        let mut buf = BytesMut::new();
        msg.encode(&mut buf).expect("data message should encode");

        let decoded = RelayMessage::decode(&buf[..]).expect("data message should decode");

        assert_eq!(msg.stream_id, decoded.stream_id);
        assert_eq!(msg.msg_type, decoded.msg_type);
        assert_eq!(msg.payload, decoded.payload);
        assert_eq!(&decoded.payload[..], data);
    }

    #[test]
    fn test_message_connected() {
        let msg = RelayMessage::connected(789).expect("connected message should build");

        let mut buf = BytesMut::new();
        msg.encode(&mut buf).expect("connected message should encode");

        assert_eq!(buf.len(), RelayMessage::HEADER_SIZE); // No payload

        let decoded = RelayMessage::decode(&buf[..]).expect("connected message should decode");

        assert_eq!(msg.stream_id, decoded.stream_id);
        assert_eq!(msg.msg_type, RelayMsgType::Connected);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_message_close() {
        let msg = RelayMessage::close(999).expect("close message should build");

        let mut buf = BytesMut::new();
        msg.encode(&mut buf).expect("close message should encode");

        let decoded = RelayMessage::decode(&buf[..]).expect("close message should decode");

        assert_eq!(msg.stream_id, decoded.stream_id);
        assert_eq!(msg.msg_type, RelayMsgType::Close);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_message_error() {
        let msg = RelayMessage::error(111, "Connection refused").expect("error message should build");

        let mut buf = BytesMut::new();
        msg.encode(&mut buf).expect("error message should encode");

        let decoded = RelayMessage::decode(&buf[..]).expect("error message should decode");

        assert_eq!(msg.stream_id, decoded.stream_id);
        assert_eq!(msg.msg_type, RelayMsgType::Error);
        assert_eq!(
            String::from_utf8(decoded.payload.to_vec()).expect("payload should be valid UTF-8"),
            "Connection refused"
        );
    }

    #[test]
    fn test_payload_too_large() {
        let large_payload = vec![0u8; RelayMessage::MAX_PAYLOAD_SIZE + 1];
        let result = RelayMessage::data(1, Bytes::from(large_payload));

        assert!(matches!(result, Err(Error::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_decode_not_enough_bytes() {
        let buf = [0u8; 5]; // Less than HEADER_SIZE (7)
        let result = RelayMessage::decode(&buf[..]);

        assert!(matches!(result, Err(Error::NotEnoughBytes { .. })));
    }

    #[test]
    fn test_invalid_message_type() {
        let result = RelayMsgType::from_u8(0xFF);
        assert!(matches!(result, Err(Error::InvalidMessageType(0xFF))));
    }

    #[test]
    fn test_route_advertise_round_trip() {
        let advertisement = RouteAdvertisement::new(
            42,
            vec![
                "10.20.0.0/16".parse().expect("valid CIDR"),
                "192.168.100.0/24".parse().expect("valid CIDR"),
                "10.20.0.0/16".parse().expect("valid CIDR"),
            ],
        );

        let msg = RelayMessage::route_advertise(&advertisement).expect("route advertisement should build");

        assert_eq!(msg.stream_id, 0);
        assert_eq!(msg.msg_type, RelayMsgType::RouteAdvertise);

        let decoded_advertisement =
            RouteAdvertisement::decode(&msg.payload[..]).expect("route advertisement should decode");
        assert_eq!(decoded_advertisement.epoch, 42);
        assert_eq!(
            decoded_advertisement.subnets,
            vec![
                "10.20.0.0/16".parse::<Ipv4Network>().expect("valid CIDR"),
                "192.168.100.0/24".parse::<Ipv4Network>().expect("valid CIDR"),
            ]
        );
    }

    #[test]
    fn test_route_advertise_invalid_subnet_payload() {
        let mut payload = BytesMut::new();
        payload.put_u64(7);
        payload.put_u16(1);
        payload.put_u32(u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0)));
        payload.put_u8(33);

        let error = RouteAdvertisement::decode(&payload[..]).expect_err("invalid subnet payload should fail");
        assert!(matches!(error, Error::InvalidPayload(_)));
    }
}
