use byteorder::{BigEndian, ByteOrder};

pub const ICMPV4_MTU: usize = 1500; // practically, this is the MTU for most networks

#[repr(u8)]
pub enum Icmpv4MessageType {
    EchoReply = 0,
    Unreachable = 3,
    Quench = 4,
    Redirect = 5,
    Echo = 8,
    TimeExceeded = 11,
    ParameterProblem = 12,
    Timestamp = 13,
    TimestampReply = 14,
    Information = 15,
    InformationReply = 16,
}

#[derive(Debug)]
pub enum Icmpv4Message {
    EchoReply {
        //  type 0
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    Unreachable {
        // type 3
        padding: u32,
        header: Vec<u8>,
    },
    Quench {
        // type 4
        padding: u32,
        header: Vec<u8>,
    },
    Redirect {
        // type 5
        gateway: u32,
        header: Vec<u8>,
    },
    Echo {
        // type 8
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    TimeExceeded {
        // type 11
        padding: u32,
        header: Vec<u8>,
    },
    ParameterProblem {
        // type 12
        pointer: u8,
        padding: (u8, u16),
        header: Vec<u8>,
    },

    Timestamp {
        // type 13
        identifier: u16,
        sequence: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },
    TimestampReply {
        // type 14
        identifier: u16,
        sequence: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },
    Information {
        // type 15
        identifier: u16,
        sequence: u16,
    },
    InformationReply {
        // type 16
        identifier: u16,
        sequence: u16,
    },
}

impl Icmpv4Message {
    pub fn get_type(&self) -> Icmpv4MessageType {
        match self {
            Self::EchoReply { .. } => Icmpv4MessageType::EchoReply,
            Self::Unreachable { .. } => Icmpv4MessageType::Unreachable,
            Self::Quench { .. } => Icmpv4MessageType::Quench,
            Self::Redirect { .. } => Icmpv4MessageType::Redirect,
            Self::Echo { .. } => Icmpv4MessageType::Echo,
            Self::TimeExceeded { .. } => Icmpv4MessageType::TimeExceeded,
            Self::ParameterProblem { .. } => Icmpv4MessageType::ParameterProblem,
            Self::Timestamp { .. } => Icmpv4MessageType::Timestamp,
            Self::TimestampReply { .. } => Icmpv4MessageType::TimestampReply,
            Self::Information { .. } => Icmpv4MessageType::Information,
            Self::InformationReply { .. } => Icmpv4MessageType::InformationReply,
        }
    }
}
impl Icmpv4Message {
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        match self {
            Self::Unreachable {
                // type 3
                padding,
                header,
            }
            | Self::TimeExceeded {
                // type 11
                padding,
                header,
            }
            | Self::Quench {
                // type 4
                padding,
                header,
            }
            | Self::Redirect {
                // type 5
                gateway: padding,
                header,
            } => {
                let mut buf = vec![0; 4];
                BigEndian::write_u32(&mut buf, *padding);
                bytes.append(&mut buf);
                bytes.extend_from_slice(header);
            }
            Self::Echo {
                // type 8
                identifier,
                sequence,
                payload,
            }
            | Self::EchoReply {
                //  type 0
                identifier,
                sequence,
                payload,
            } => {
                let mut buf = vec![0; 2];
                BigEndian::write_u16(&mut buf, *identifier);
                bytes.append(&mut buf);
                buf.resize(2, 0);
                BigEndian::write_u16(&mut buf, *sequence);
                bytes.append(&mut buf);
                bytes.extend_from_slice(payload);
            }
            Self::ParameterProblem {
                // type 12
                pointer,
                padding,
                header,
            } => {
                bytes.push(*pointer);
                bytes.push(padding.0);
                let mut buf = vec![0, 2];
                BigEndian::write_u16(&mut buf, padding.1);
                bytes.append(&mut buf);
                bytes.extend_from_slice(header);
            }
            Self::Timestamp {
                // type 13
                identifier,
                sequence,
                originate,
                receive,
                transmit,
            }
            | Self::TimestampReply {
                // type 14
                identifier,
                sequence,
                originate,
                receive,
                transmit,
            } => {
                let mut buf = vec![0, 2];
                BigEndian::write_u16(&mut buf, *identifier);
                bytes.append(&mut buf);
                BigEndian::write_u16(&mut buf, *sequence);
                bytes.append(&mut buf);
                buf = vec![0, 4];
                BigEndian::write_u32(&mut buf, *originate);
                bytes.append(&mut buf);
                BigEndian::write_u32(&mut buf, *receive);
                bytes.append(&mut buf);
                BigEndian::write_u32(&mut buf, *transmit);
                bytes.append(&mut buf);
            }
            Self::Information {
                // type 15
                identifier,
                sequence,
            }
            | Self::InformationReply {
                // type 16
                identifier,
                sequence,
            } => {
                let mut buf = vec![0, 2];
                BigEndian::write_u16(&mut buf, *identifier);
                bytes.append(&mut buf);
                BigEndian::write_u16(&mut buf, *sequence);
                bytes.append(&mut buf);
            }
        }
        bytes
    }
}

#[derive(Debug)]
pub struct Icmpv4Packet {
    pub code: u8,
    pub checksum: u16,
    pub message: Icmpv4Message,
}

impl TryFrom<&[u8]> for Icmpv4Packet {
    type Error = PacketParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<Icmpv4Packet> for Vec<u8> {
    fn from(val: Icmpv4Packet) -> Self {
        val.to_bytes(true)
    }
}

impl Icmpv4Packet {
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, PacketParseError> {
        let mut bytes = bytes.as_ref();
        let mut packet_len = bytes.len();
        if bytes.len() < 28 {
            return Err(PacketParseError::PacketTooSmall(packet_len));
        }
        // NOTE(jwall) Because we use raw sockets the first 20 bytes are the IPv4 header.
        bytes = &bytes[20..];
        // NOTE(jwall): All ICMP packets are at least 8 bytes long.
        packet_len = bytes.len();
        let (typ, code, checksum) = (bytes[0], bytes[1], BigEndian::read_u16(&bytes[2..4]));
        let message = match typ {
            3 => Icmpv4Message::Unreachable {
                padding: BigEndian::read_u32(&bytes[4..8]),
                header: bytes[8..].to_owned(),
            },
            11 => Icmpv4Message::TimeExceeded {
                padding: BigEndian::read_u32(&bytes[4..8]),
                header: bytes[8..].to_owned(),
            },
            4 => Icmpv4Message::Quench {
                padding: BigEndian::read_u32(&bytes[4..8]),
                header: bytes[8..].to_owned(),
            },
            5 => Icmpv4Message::Redirect {
                gateway: BigEndian::read_u32(&bytes[4..8]),
                header: bytes[8..].to_owned(),
            },
            8 => Icmpv4Message::Echo {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: bytes[8..].to_owned(),
            },
            0 => Icmpv4Message::EchoReply {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: bytes[8..].to_owned(),
            },
            15 => Icmpv4Message::Information {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
            },
            16 => Icmpv4Message::InformationReply {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
            },
            13 => {
                if packet_len < 20 {
                    return Err(PacketParseError::PacketTooSmall(bytes.len()));
                }
                Icmpv4Message::Timestamp {
                    identifier: BigEndian::read_u16(&bytes[4..6]),
                    sequence: BigEndian::read_u16(&bytes[6..8]),
                    originate: BigEndian::read_u32(&bytes[8..12]),
                    receive: BigEndian::read_u32(&bytes[12..16]),
                    transmit: BigEndian::read_u32(&bytes[16..20]),
                }
            }
            14 => {
                if packet_len < 20 {
                    return Err(PacketParseError::PacketTooSmall(bytes.len()));
                }
                Icmpv4Message::TimestampReply {
                    identifier: BigEndian::read_u16(&bytes[4..6]),
                    sequence: BigEndian::read_u16(&bytes[6..8]),
                    originate: BigEndian::read_u32(&bytes[8..12]),
                    receive: BigEndian::read_u32(&bytes[12..16]),
                    transmit: BigEndian::read_u32(&bytes[16..20]),
                }
            }
            t => {
                return Err(PacketParseError::UnrecognizedICMPType(t));
            }
        };
        Ok(Icmpv4Packet {
            code,
            checksum,
            message,
        })
    }

    /// Get this packet serialized to bytes suitable for sending on the wire.
    pub fn to_bytes(&self, with_checksum: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.message.get_type() as u8);
        bytes.push(self.code);
        let mut buf = vec![0; 2];
        BigEndian::write_u16(&mut buf, if with_checksum { self.checksum } else { 0 });
        bytes.append(&mut buf);
        bytes.append(&mut self.message.get_bytes());
        bytes
    }

    pub fn calculate_checksum(&self) -> u16 {
        let mut sum = 0u32;
        let bytes = self.to_bytes(false);
        sum += sum_big_endian_words(&bytes);

        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        #[allow(clippy::cast_possible_truncation)] // Truncation is intended.
        {
            !sum as u16
        }
    }

    /// Populate the checksum field of this Packet.
    #[must_use]
    pub fn with_checksum(mut self) -> Self {
        self.checksum = self.calculate_checksum();
        self
    }

    #[must_use]
    pub fn from_message(message: Icmpv4Message) -> Self {
        Self {
            code: 0,
            checksum: 0,
            message,
        }
        .with_checksum()
    }
}

#[derive(Debug)]
pub enum PacketParseError {
    PacketTooSmall(usize),
    UnrecognizedICMPType(u8),
}

impl std::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketParseError::PacketTooSmall(size) => {
                write!(f, "packet too small to parse: {size}")
            }
            PacketParseError::UnrecognizedICMPType(t) => {
                write!(f, "unrecognized ICMP type: {t}")
            }
        }
    }
}

impl std::error::Error for PacketParseError {}

fn sum_big_endian_words(bs: &[u8]) -> u32 {
    if bs.is_empty() {
        return 0;
    }

    let len = bs.len();
    let mut data = bs;
    let mut sum = 0u32;
    // Iterate by word which is two bytes.
    while data.len() >= 2 {
        sum += u32::from(BigEndian::read_u16(&data[0..2]));
        // remove the first two bytes now that we've already summed them
        data = &data[2..];
    }

    if !len.is_multiple_of(2) {
        // If odd then checksum the last byte
        sum += u32::from(data[0]) << 8;
    }
    sum
}
