use std::{error::Error, fmt, io, str};

use serde_derive::{Deserialize, Serialize};

use crate::ntlm::{Ntlm, NTLM_VERSION_SIZE};

pub type SspiResult = std::result::Result<SspiOk, SspiError>;
pub type Result<T> = std::result::Result<T, SspiError>;

pub trait Sspi {
    fn package_type(&self) -> PackageType;
    fn identity(&self) -> &AuthIdentity;
    fn initialize_security_context(&mut self, input: impl io::Read, output: impl io::Write) -> self::SspiResult;
    fn accept_security_context(&mut self, input: impl io::Read, output: impl io::Write) -> self::SspiResult;
    fn complete_auth_token(&mut self) -> self::Result<()>;
    fn encrypt_message(&mut self, input: &[u8], message_seq_number: u32) -> self::Result<Vec<u8>>;
    fn decrypt_message(&mut self, input: &[u8], message_seq_number: u32) -> self::Result<Vec<u8>>;
}

pub enum PackageType {
    Ntlm,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    password: String,
    domain: Option<String>,
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct AuthIdentity {
    pub user: Vec<u8>,
    pub domain: Vec<u8>,
    pub password: Vec<u8>,
}

impl Credentials {
    pub fn new(username: String, password: String, domain: Option<String>) -> Self {
        Self {
            username,
            password,
            domain,
        }
    }
}

impl AuthIdentity {
    pub fn new(user: Vec<u8>, domain: Vec<u8>, password: Vec<u8>) -> Self {
        Self { user, domain, password }
    }

    pub fn is_empty(&self) -> bool {
        self.user.is_empty() || self.password.is_empty()
    }
    pub fn is_eq(&self, other: &AuthIdentity) -> bool {
        self.user == other.user && self.domain == other.domain && self.password == other.password
    }
}

impl From<Credentials> for AuthIdentity {
    fn from(credentials: Credentials) -> AuthIdentity {
        AuthIdentity {
            user: string_to_utf16(credentials.username),
            domain: credentials.domain.map(string_to_utf16).unwrap_or_default(),
            password: string_to_utf16(credentials.password),
        }
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SspiErrorType {
    InternalError = 0x8009_0304,
    InvalidToken = 0x8009_0308,
    OutOfSequence = 0x8009_0310,
    MessageAltered = 0x8009_030F,
    TargetUnknown = 0x8009_0303,
}

#[derive(Debug, PartialEq)]
pub struct SspiError {
    pub error_type: SspiErrorType,
    pub description: String,
}

#[derive(Debug, PartialEq)]
pub enum SspiOk {
    ContinueNeeded = 0x0009_0312,
    CompleteNeeded = 0x0009_0313,
}

impl SspiError {
    pub fn new(error_type: SspiErrorType, error: String) -> Self {
        Self {
            error_type,
            description: error,
        }
    }
}

impl Error for SspiError {}

impl fmt::Display for SspiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<io::Error> for SspiError {
    fn from(err: io::Error) -> Self {
        Self::new(SspiErrorType::InternalError, format!("IO error: {}", err.to_string()))
    }
}

impl From<rand::Error> for SspiError {
    fn from(err: rand::Error) -> Self {
        Self::new(SspiErrorType::InternalError, format!("Rand error: {}", err.to_string()))
    }
}

impl From<std::string::FromUtf16Error> for SspiError {
    fn from(err: std::string::FromUtf16Error) -> Self {
        Self::new(
            SspiErrorType::InternalError,
            format!("UTF-16 error: {}", err.to_string()),
        )
    }
}

impl From<SspiError> for io::Error {
    fn from(err: SspiError) -> io::Error {
        io::Error::new(
            io::ErrorKind::Other,
            format!("{:?}: {}", err.error_type, err.description),
        )
    }
}

impl fmt::Display for SspiOk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn string_to_utf16(value: String) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|i| i.to_le_bytes().to_vec())
        .collect::<Vec<u8>>()
}
