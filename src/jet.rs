use std::convert::TryFrom;
use jet_proto::Error;

pub mod association;
pub mod candidate;

#[derive(Serialize, Deserialize, Debug,Clone,PartialEq)]
pub enum TransportType {
    Tcp,
    Tls,
    Ws,
    Wss,
}

impl TryFrom<&str> for TransportType {
    type Error = Error;
    fn try_from(val: &str) -> Result<Self, Error> {
        let ival = val.to_lowercase();
        match ival.as_str() {
            "tcp" => Ok(TransportType::Tcp),
            "tls" => Ok(TransportType::Tls),
            "ws" => Ok(TransportType::Ws),
            "wss" => Ok(TransportType::Wss),
            _ => Err(Error::Value),
        }
    }
}

impl From<TransportType> for &str {
    fn from(val: TransportType) -> Self {
        match val {
            TransportType::Tcp => "tcp",
            TransportType::Tls => "tls",
            TransportType::Ws => "ws",
            TransportType::Wss => "wss",
        }
    }
}

impl TransportType {
    pub fn default_port(&self) -> Option<u16> {
        match self {
            TransportType::Ws => Some(80),
            TransportType::Wss => Some(443),
            _ => None,
        }
    }
}
