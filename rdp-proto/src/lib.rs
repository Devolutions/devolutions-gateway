//! The Rust implementation of the Remote Desktop Protocol.

// FromPrimitive and ToPrimitive causes clippy error, so we disable it until
// https://github.com/rust-num/num-derive/issues/20 is fixed
#![cfg_attr(feature = "cargo-clippy", allow(clippy::useless_attribute))]

#[macro_use]
mod utils;

pub mod ber;
pub mod gcc;

mod credssp;
mod encryption;
mod nego;
mod ntlm;
mod per;
mod rdp;
mod sspi;
mod tpdu;

pub use crate::{
    credssp::{ts_request::TsRequest, CredSsp, CredSspClient, CredSspResult, CredSspServer, CredentialsProxy},
    nego::*,
    ntlm::NTLM_VERSION_SIZE,
    rdp::*,
    sspi::{Credentials, SspiError, SspiErrorType},
    tpdu::*,
};

pub trait PduParsing {
    type Error;

    fn from_buffer(stream: impl std::io::Read) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized;
    fn to_buffer(&self, stream: impl std::io::Write) -> Result<(), Self::Error>;
    fn buffer_length(&self) -> usize;
}
