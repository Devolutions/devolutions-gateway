use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid IP packet: {0}")]
    InvalidIpPacket(String),

    #[error("IP packet too small: got {size} bytes, expected at least {min}")]
    PacketTooSmall { size: usize, min: usize },

    #[error("protocol mismatch: expected {expected}, got {actual}")]
    ProtocolMismatch { expected: u8, actual: u8 },

    #[error("tunnel protocol error: {0}")]
    TunnelProto(#[from] tunnel_proto::Error),

    #[error("boringtun error: {0}")]
    Boringtun(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
