pub mod ping;

#[derive(Debug)]
pub enum NetworkScanError {
    IoError(std::io::Error),
    Other(String),
    ProtocolError(String),
}

impl From<std::io::Error> for NetworkScanError {
    fn from(e: std::io::Error) -> Self {
        NetworkScanError::IoError(e)
    }
}