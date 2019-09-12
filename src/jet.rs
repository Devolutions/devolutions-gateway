use std::convert::TryFrom;
use jet_proto::Error;

pub mod association;
pub mod candidate;


#[derive(Debug,Clone,PartialEq)]
pub enum Role {
    Client,
    Server,
    Relay,
}

impl TryFrom<u32> for Role {
    type Error = Error;
    fn try_from(val: u32) -> Result<Self, Error> {
        match val {
            0 => Ok(Role::Client),
            1 => Ok(Role::Server),
            2 => Ok(Role::Relay),
            _ => Err(Error::Value),
        }
    }
}

impl TryFrom<&str> for Role {
    type Error = Error;
    fn try_from(val: &str) -> Result<Self, Error> {
        let ival = val.to_lowercase();
        match ival.as_str() {
            "client" => Ok(Role::Client),
            "server" => Ok(Role::Server),
            "relay" => Ok(Role::Relay),
            _ => Err(Error::Value),
        }
    }
}

impl From<Role> for &str {
    fn from(val: Role) -> Self {
        match val {
            Role::Client => "Client",
            Role::Server => "Server",
            Role::Relay => "Relay",
        }
    }
}

#[derive(Debug,Clone,PartialEq)]
pub enum TransportPolicy {
    All,
    Relay,
}

impl TryFrom<&str> for TransportPolicy {
    type Error = Error;
    fn try_from(val: &str) -> Result<Self, Error> {
        let ival = val.to_lowercase();
        match ival.as_str() {
            "all" => Ok(TransportPolicy::All),
            "relay" => Ok(TransportPolicy::Relay),
            _ => Err(Error::Value),
        }
    }
}

impl From<TransportPolicy> for &str {
    fn from(val: TransportPolicy) -> Self {
        match val {
            TransportPolicy::All => "All",
            TransportPolicy::Relay => "Relay",
        }
    }
}

#[derive(Debug,Clone,PartialEq)]
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
