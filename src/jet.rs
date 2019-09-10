use std::io;
use std::convert::TryFrom;

pub mod association;
pub mod candidate;

#[derive(Debug)]
pub enum Error {
    Internal,
    Version,
    Capabilities,
    Unresolved,
    Unreachable,
    Unavailable,
    Transport,
    Memory,
    State,
    Protocol,
    Header,
    Payload,
    Size,
    Type,
    Value,
    Offset,
    Flags,
    Argument,
    Timeout,
    Cancelled,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    NotImplemented,
    Io(io::Error),
    Str(&'static str),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::Io(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        let error_string = error.to_string();
        io::Error::new(io::ErrorKind::Other, error_string.as_str())
    }
}

impl From<&'static str> for Error {
    fn from(error: &'static str) -> Error {
        Error::Str(error)
    }
}

impl Error {
    pub fn from_http_status_code(status_code: u16) -> Self {
        return match status_code {
            400 => Error::BadRequest,
            401 => Error::Unauthorized,
            403 => Error::Forbidden,
            404 => Error::NotFound,
            _ => Error::BadRequest,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Internal => write!(f, "Internal error"),
            Error::Version => write!(f, "Version error"),
            Error::Capabilities => write!(f, "Capabilities error"),
            Error::Unresolved => write!(f, "Unresolved error"),
            Error::Unreachable => write!(f, "Unreachable error"),
            Error::Unavailable => write!(f, "Unavailable error"),
            Error::Transport => write!(f, "Transport error"),
            Error::Memory => write!(f, "Memory error"),
            Error::State => write!(f, "State error"),
            Error::Protocol => write!(f, "Protocol error"),
            Error::Header => write!(f, "Header error"),
            Error::Payload => write!(f, "Payload error"),
            Error::Size => write!(f, "Size error"),
            Error::Type => write!(f, "Type error"),
            Error::Value => write!(f, "Value error"),
            Error::Offset => write!(f, "Offset error"),
            Error::Flags => write!(f, "Flags error"),
            Error::Argument => write!(f, "Argument error"),
            Error::Timeout => write!(f, "Timeout error"),
            Error::Cancelled => write!(f, "Cancelled error"),
            Error::BadRequest => write!(f, "BadRequest error"),
            Error::Unauthorized => write!(f, "Unauthorized error"),
            Error::Forbidden => write!(f, "Forbidden error"),
            Error::NotFound => write!(f, "NotFound error"),
            Error::NotImplemented => write!(f, "NotImplemented error"),
            Error::Io(e) => write!(f, "{}", e),
            Error::Str(e) => write!(f, "{}", e),
        }
    }
}

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
