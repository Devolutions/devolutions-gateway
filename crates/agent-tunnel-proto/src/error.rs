/// Protocol-level errors for the agent tunnel.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("unsupported protocol version {received} (supported: {min}..={max})")]
    UnsupportedVersion { received: u16, min: u16, max: u16 },

    #[error("message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: u32, max: u32 },

    #[error("bincode encode/decode error: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
