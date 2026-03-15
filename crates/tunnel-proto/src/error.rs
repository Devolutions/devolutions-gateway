use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("not enough bytes to decode message: received {received}, expected at least {expected}")]
    NotEnoughBytes { received: usize, expected: usize },

    #[error("message payload too large: {size} bytes (max: {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("invalid payload encoding: {0}")]
    InvalidPayload(String),

    #[error("stream ID pool exhausted (all {0} IDs in use)")]
    StreamIdPoolExhausted(usize),
}

pub type Result<T> = std::result::Result<T, Error>;
