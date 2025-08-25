#[repr(u8)]
pub enum Icmpv6MessageType {
    Unreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    EchoRequest = 128,
    EchoReply = 129,
}

#[repr(u8)]
pub enum Icmpv6UnreacheableCode {
    NoRoute = 0,
    AdmProhibited = 1,
    NotNeighbour = 2,
    AddrUnreach = 3,
    PortUnreach = 4,
    PolicyFail = 5,
    RejectRoute = 6,
}

#[repr(u8)]
pub enum Icmpv6TimeExceededCode {
    HopLimitExceeded = 0,
    FragmentReassemblyTimeout = 1,
}

#[repr(u8)]
pub enum Icmpv6ParameterProblemCode {
    ErroneousHeaderField = 0,
    UnrecognizedNextHeaderType = 1,
    UnrecognizedIpv6HeaderOption = 2,
}

pub enum Icmpv6Message {
    Unreachable {
        code: Icmpv6UnreacheableCode,
        original_packet: Vec<u8>,
    },
    PacketTooBig {
        mtu: u32,
        original_packet: Vec<u8>,
    },
    TimeExceeded {
        code: Icmpv6TimeExceededCode,
        original_packet: Vec<u8>,
    },
    ParameterProblem {
        code: Icmpv6ParameterProblemCode,
        pointer: u32,
        original_packet: Vec<u8>,
    },
    EchoRequest {
        identifier: u16,
        sequence_number: u16,
        payload: Vec<u8>,
    },
    EchoReply {
        identifier: u16,
        sequence_number: u16,
        payload: Vec<u8>,
    },
}

impl Icmpv6Message {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(self.get_type() as u8);

        match self {
            Icmpv6Message::Unreachable { code, original_packet } => {
                bytes.push(code as u8);
                bytes.extend(vec![0; 2]); // checksum placeholder
                bytes.extend(vec![0; 4]); // unused
                bytes.extend(original_packet);
            }
            Icmpv6Message::PacketTooBig { mtu, original_packet } => {
                bytes.push(0); // code
                bytes.extend(vec![0; 2]); // checksum placeholder
                bytes.extend(mtu.to_be_bytes());
                bytes.extend(original_packet);
            }
            Icmpv6Message::TimeExceeded { code, original_packet } => {
                bytes.push(code as u8);
                bytes.extend(vec![0; 2]); // checksum placeholder
                bytes.extend(vec![0; 4]); // unused
                bytes.extend(original_packet);
            }
            Icmpv6Message::ParameterProblem {
                code,
                pointer,
                original_packet,
            } => {
                bytes.push(code as u8);
                bytes.extend(vec![0; 2]); // checksum placeholder
                bytes.extend(pointer.to_be_bytes());
                bytes.extend(original_packet);
            }
            Icmpv6Message::EchoRequest {
                identifier,
                sequence_number,
                payload,
            } => {
                bytes.push(0); // code
                bytes.extend(vec![0; 2]); // checksum placeholder
                bytes.extend(identifier.to_be_bytes());
                bytes.extend(sequence_number.to_be_bytes());
                bytes.extend(payload);
            }
            Icmpv6Message::EchoReply {
                identifier,
                sequence_number,
                payload,
            } => {
                bytes.push(0); // code
                bytes.extend(vec![0; 2]); // checksum placeholder
                bytes.extend(identifier.to_be_bytes());
                bytes.extend(sequence_number.to_be_bytes());
                bytes.extend(payload);
            }
        };

        return bytes;
    }
}

impl Icmpv6Message {
    fn get_type(&self) -> Icmpv6MessageType {
        match self {
            Self::Unreachable { .. } => Icmpv6MessageType::Unreachable,
            Self::PacketTooBig { .. } => Icmpv6MessageType::PacketTooBig,
            Self::TimeExceeded { .. } => Icmpv6MessageType::TimeExceeded,
            Self::ParameterProblem { .. } => Icmpv6MessageType::ParameterProblem,
            Self::EchoRequest { .. } => Icmpv6MessageType::EchoRequest,
            Self::EchoReply { .. } => Icmpv6MessageType::EchoReply,
        }
    }
}
